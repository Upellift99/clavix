import { paraglideVitePlugin } from "@inlang/paraglide-js";
import adapter from "@sveltejs/adapter-static";
import { sveltekit } from "@sveltejs/kit/vite";
import { vitePreprocess } from "@sveltejs/vite-plugin-svelte";
import { svelteTesting } from "@testing-library/svelte/vite";
import { defineConfig } from "vite";

const host = process.env.TAURI_DEV_HOST;

export default defineConfig(async () => ({
  plugins: [
    // SvelteKit 3 reads its options from the plugin; `svelte.config.js` is
    // no longer supported. Unknown keys are forwarded to vite-plugin-svelte,
    // so kit options (adapter, csp) must sit at this top level, not under `kit`.
    //
    // Tauri doesn't have a Node.js server to do proper SSR
    // so we use adapter-static with a fallback to index.html to put the site in SPA mode
    // See: https://svelte.dev/docs/kit/single-page-apps
    // See: https://v2.tauri.app/start/frontend/sveltekit/ for more info
    sveltekit({
      preprocess: vitePreprocess(),
      adapter: adapter({
        fallback: "index.html",
      }),
      // Hash-mode CSP: SvelteKit emits one inline <script> in
      // index.html (the bootstrap that imports the entry chunks and
      // calls kit.start). Its content changes on every build because
      // chunk filenames are hashed. SvelteKit computes the SHA-256 of
      // that inline script at build time and lists it in a
      // <meta http-equiv="Content-Security-Policy"> tag, so the CSP
      // permits exactly that one script — no `'unsafe-inline'` needed.
      //
      // Tauri's own CSP must NOT also restrict script-src: combined
      // CSPs are intersected per directive, and Tauri can't know the
      // hash at config time. Tauri CSP is therefore set to null in
      // tauri.conf.json so the SvelteKit meta is the sole authority
      // for inline-script execution. Other protections (img-src,
      // connect-src, frame-ancestors) live in this same `directives`
      // block to keep the policy in one place.
      csp: {
        mode: "hash",
        directives: {
          "default-src": ["self", "ipc:", "http://ipc.localhost"],
          "script-src": ["self"],
          "style-src": ["self", "unsafe-inline"],
          // The WebView never issues an outbound fetch/WebSocket: every
          // Vaultwarden request is proxied by the Rust `reqwest` client over
          // IPC. Dropping `https:`/`http:` from connect-src closes the trivial
          // exfiltration channel a compromised WebView (XSS or a bad npm dep)
          // would otherwise use to POST the decrypted vault, tokens and SSH
          // private keys to any host. This is the highest-leverage containment
          // fix from the security review (M1).
          "connect-src": ["self", "ipc:", "http://ipc.localhost"],
          // `https:` stays here on purpose: favicons load as <img> from the
          // user's own Vaultwarden server (`${serverUrl}/icons/<domain>/icon.png`,
          // an arbitrary user-configured HTTPS host we can't hardcode). `http:`
          // is dropped — favicons are https-only. An <img> beacon is a much
          // weaker, GET-only, no-response-read channel than connect-src.
          "img-src": ["self", "data:", "blob:", "https:"],
          "font-src": ["self", "data:"],
          "object-src": ["none"],
          "frame-ancestors": ["none"],
          "base-uri": ["self"],
          "form-action": ["none"],
        },
      },
    }),
    paraglideVitePlugin({
      project: "./project.inlang",
      outdir: "./src/lib/paraglide",
    }),
    // Enables client-mode Svelte compilation for *.svelte.test.ts files that
    // opt into the jsdom environment; node-env tests are unaffected.
    svelteTesting(),
  ],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
  test: {
    include: ["src/**/*.test.ts"],
    environment: "node",
  },
}));
