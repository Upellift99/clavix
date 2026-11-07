#!/usr/bin/env python3
"""List every npm tarball in pnpm-lock.yaml as a Flatpak source.

flatpak-builder builds without network access. The manifest therefore
downloads each tarball ahead of time into a directory laid out like the npm
registry (`<name>/-/<basename>-<version>.tgz`), and the build serves that
directory on loopback (packaging/flatpak/npm-registry.py) so that
`pnpm install --frozen-lockfile` can fetch from it.

pnpm still asks for the metadata of some packages, so each name also gets a
minimal packument that lists only the locked versions. Their publish times
are a fixed old date: pnpm only reads them for its minimumReleaseAge check,
which the lockfile already passed when it was committed.

Tarballs restricted to another OS or CPU are skipped: pnpm would never
download them on Linux, and esbuild alone ships two dozen of them.

Usage: flatpak-node-sources.py pnpm-lock.yaml > node-sources.json
"""

import base64
import json
import sys

import yaml

REGISTRY = "https://registry.npmjs.org"
# Must match the port in packaging/flatpak/org.clavix.Clavix.yml.
LOCAL_REGISTRY = "http://127.0.0.1:4873"
LOCKED_TIME = "2000-01-01T00:00:00.000Z"
# Flatpak architectures we build for, in npm's `cpu` vocabulary.
CPUS = {"x64", "arm64"}


def split_key(key: str) -> tuple[str, str]:
    """`@scope/name@1.2.3` -> (`@scope/name`, `1.2.3`)."""
    at = key.rindex("@")
    return key[:at], key[at + 1 :]


def wanted(meta: dict) -> bool:
    os_list = meta.get("os")
    if os_list and not any(o == "linux" or (o.startswith("!") and o != "!linux") for o in os_list):
        return False
    cpu_list = meta.get("cpu")
    if cpu_list and not CPUS.intersection(cpu_list):
        return False
    return True


def main(lockfile: str) -> None:
    with open(lockfile, encoding="utf-8") as f:
        docs = list(yaml.safe_load_all(f))
    # pnpm 11 may prepend a document describing the package manager.
    lock = docs[-1]

    sources = []
    packuments: dict[str, dict] = {}
    for key, meta in sorted(lock.get("packages", {}).items()):
        resolution = meta.get("resolution", {})
        integrity = resolution.get("integrity", "")
        if not integrity.startswith("sha512-") or "tarball" in resolution:
            sys.exit(f"error: {key}: only registry tarballs with a sha512 integrity are supported")
        name, version = split_key(key)
        basename = name.rsplit("/", 1)[-1]
        filename = f"{basename}-{version}.tgz"
        if wanted(meta):
            sources.append(
                {
                    "type": "file",
                    "url": f"{REGISTRY}/{name}/-/{filename}",
                    "sha512": base64.b64decode(integrity[len("sha512-") :]).hex(),
                    "dest": f"npm-registry/{name}/-",
                    "dest-filename": filename,
                }
            )
        # Metadata for every entry, skipped platforms included: pnpm checks
        # the whole lockfile against its policies before it installs.
        doc = packuments.setdefault(name, {"name": name, "versions": {}, "time": {}})
        doc["versions"][version] = {
            "name": name,
            "version": version,
            "dist": {"tarball": f"{LOCAL_REGISTRY}/{name}/-/{filename}", "integrity": integrity},
        }
        doc["time"][version] = LOCKED_TIME

    for name, doc in sorted(packuments.items()):
        # Any locked version will do: a frozen install never reads dist-tags.
        doc["dist-tags"] = {"latest": next(iter(doc["versions"]))}
        sources.append(
            {
                "type": "inline",
                "contents": json.dumps(doc, sort_keys=True),
                "dest": f"npm-registry/{name}",
                "dest-filename": "packument.json",
            }
        )

    json.dump(sources, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
