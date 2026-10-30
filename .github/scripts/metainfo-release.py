#!/usr/bin/env python3
"""Give the AppStream metainfo a <release> entry for the version being released.

Run by release-please.yml on the release branch, after release-please has
bumped package.json and written the CHANGELOG section. The entry gets the
version from package.json and the date of that CHANGELOG section, so the two
agree. An existing entry for the version has its date refreshed: release-please
rewrites the section's date when it updates the PR on a later day.

Usage: metainfo-release.py <repo root>
"""

import json
import re
import sys
from pathlib import Path

METAINFO = Path("packaging/linux/org.clavix.Clavix.metainfo.xml")


def main(root: Path) -> int:
    version = json.loads((root / "package.json").read_text())["version"]

    changelog = (root / "CHANGELOG.md").read_text()
    heading = re.search(
        rf"^## \[{re.escape(version)}\].*\((\d{{4}}-\d{{2}}-\d{{2}})\)\s*$",
        changelog,
        re.MULTILINE,
    )
    if not heading:
        print(f"error: no dated CHANGELOG section for {version}", file=sys.stderr)
        return 1
    date = heading.group(1)

    path = root / METAINFO
    xml = path.read_text()
    entry = f'<release version="{version}" date="{date}"/>'
    existing = re.compile(rf'<release version="{re.escape(version)}" date="[^"]*"\s*/>')

    if existing.search(xml):
        updated = existing.sub(entry, xml, count=1)
    else:
        opening = re.search(r"^(\s*)<releases>\n", xml, re.MULTILINE)
        if not opening:
            print(f"error: no <releases> element in {METAINFO}", file=sys.stderr)
            return 1
        indent = opening.group(1) + "  "
        updated = xml[: opening.end()] + f"{indent}{entry}\n" + xml[opening.end() :]

    if updated == xml:
        print(f"{METAINFO} already lists {version} ({date})")
    else:
        path.write_text(updated)
        print(f"{METAINFO}: {version} ({date})")
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")))
