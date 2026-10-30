// Vite plugin: writes THIRD_PARTY_LICENSES.txt next to index.html in the
// client build, with the license text of every npm package whose code or
// assets end up in it. build/ ships as is in the release frontend tarball and
// is embedded in the binary, so the notices travel with both. The SIL OFL in
// particular asks for its text to accompany the fonts.
//
// Packages are found from the client bundle itself, not from package.json:
// JS through the module graph, fonts through the original paths of the
// emitted assets (they come in via CSS @import, outside the module graph).
// The output is sorted and carries no timestamp, so the build stays
// reproducible. A bundled package without a license file fails the build
// rather than shipping without its notice.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";

const OUTPUT = "THIRD_PARTY_LICENSES.txt";
const LICENSE_FILE = /^(licen[cs]e|copying|notice)/i;
const RULE = "-".repeat(79);

/**
 * The package directory a bundled file comes from, or null for our own code.
 * @param {string} root
 * @param {string} file
 * @returns {string | null}
 */
function packageDir(root, file) {
  const abs = path.resolve(root, file.replace(/^\0/, "").split("?")[0]);
  const marker = `${path.sep}node_modules${path.sep}`;
  const at = abs.lastIndexOf(marker);
  if (at === -1) return null;
  const rest = abs.slice(at + marker.length).split(path.sep);
  const name = rest[0].startsWith("@") ? rest.slice(0, 2) : rest.slice(0, 1);
  return path.join(abs.slice(0, at + marker.length), ...name);
}

/**
 * @param {{ repository?: string | { url?: string }, homepage?: string }} pkg
 * @returns {string}
 */
function repositoryUrl(pkg) {
  const repo = typeof pkg.repository === "string" ? pkg.repository : pkg.repository?.url;
  return (repo ?? pkg.homepage ?? "")
    .replace(/^git\+/, "")
    .replace(/^git:\/\//, "https://")
    .replace(/\.git$/, "")
    .replace(/^(?:github:)?([\w.-]+\/[\w.-]+)$/, "https://github.com/$1");
}

/**
 * @param {string} dir
 * @returns {{ key: string, text: string }}
 */
function entry(dir) {
  const pkg = JSON.parse(readFileSync(path.join(dir, "package.json"), "utf8"));
  const files = readdirSync(dir)
    .filter((f) => LICENSE_FILE.test(f))
    .sort();
  if (files.length === 0) {
    throw new Error(`${pkg.name}@${pkg.version} is bundled but ships no license file`);
  }
  const texts = files.map((f) => readFileSync(path.join(dir, f), "utf8").trim());
  const source = repositoryUrl(pkg);
  return {
    key: `${pkg.name}@${pkg.version}`,
    text: [
      RULE,
      `${pkg.name} ${pkg.version}`,
      `License: ${pkg.license ?? "see below"}`,
      ...(source ? [`Source: ${source}`] : []),
      "",
      texts.join(`\n\n`),
      "",
    ].join("\n"),
  };
}

/** @returns {import("vite").Plugin} */
export function thirdPartyLicenses() {
  let root = process.cwd();
  return {
    name: "clavix-third-party-licenses",
    apply: "build",
    configResolved(config) {
      root = config.root;
    },
    generateBundle(_options, bundle) {
      // SvelteKit also runs a server build for prerendering; only the
      // client build reaches build/.
      if (this.environment?.name !== "client") return;

      const dirs = new Set();
      /** @param {string} file */
      const add = (file) => {
        const dir = packageDir(root, file);
        if (dir && existsSync(path.join(dir, "package.json"))) dirs.add(dir);
      };
      for (const id of this.getModuleIds()) add(id);
      for (const file of Object.values(bundle)) {
        if (file.type === "asset") (file.originalFileNames ?? []).forEach(add);
      }

      const entries = [...dirs].map(entry).sort((a, b) => a.key.localeCompare(b.key));
      const source = [
        "Third-party software in the Clavix web UI",
        "",
        "This build of the Clavix web UI contains code and fonts from the",
        "packages below. Each is listed with its license text. Clavix itself is",
        "licensed under the GPL-3.0-or-later; see https://github.com/Upellift99/clavix.",
        "",
        ...entries.map((e) => e.text),
      ].join("\n");
      this.emitFile({ type: "asset", fileName: OUTPUT, source });
    },
  };
}
