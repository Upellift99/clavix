"""A read-only npm registry on loopback, for the offline Flatpak build.

Serves the directory flatpak-builder filled from node-sources.json:

  <name>/-/<basename>-<version>.tgz   the tarballs
  <name>/packument.json               minimal metadata for <name>

pnpm asks for `/<name>` (scoped names arrive as `@scope%2Fname`), which is a
directory here, so a directory request answers with its packument.json.

Usage: python3 npm-registry.py <port> <directory>
"""

import http.server
import os
import sys
import urllib.parse


class Handler(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        local = super().translate_path(urllib.parse.unquote(path))
        if os.path.isdir(local):
            return os.path.join(local, "packument.json")
        return local

    def guess_type(self, path):
        if path.endswith(".json"):
            return "application/json"
        return "application/octet-stream"

    def log_message(self, *args):
        pass


def main() -> None:
    port, directory = int(sys.argv[1]), sys.argv[2]
    os.chdir(directory)
    http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
