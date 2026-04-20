import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";
import { existsSync, mkdirSync, rmSync } from "node:fs";

const here = fileURLToPath(new URL(".", import.meta.url));
const projectRoot = resolve(here, "../..");
const app = resolve(projectRoot, "src-tauri/target/debug/clavix");
const tauriDriverBin = resolve(homedir(), ".cargo/bin/tauri-driver");

// Sandbox the app's data directory so tests cannot touch the real
// ~/.local/share/clavix/ of whoever runs them. store.rs / cache.rs go
// through dirs::data_local_dir(), which honours XDG_DATA_HOME on Linux.
const sandboxDataHome = resolve(here, "sandbox");

if (!existsSync(app)) {
  throw new Error(
    `Built Clavix binary not found at ${app}. Run \`pnpm tauri build --debug\` first.`,
  );
}
if (!existsSync(tauriDriverBin)) {
  throw new Error(
    `tauri-driver not found at ${tauriDriverBin}. Run \`cargo install tauri-driver --locked\`.`,
  );
}

let tauriDriverProcess;

export const config = {
  runner: "local",
  specs: [resolve(here, "specs/**/*.spec.mjs")],
  maxInstances: 1,
  capabilities: [
    {
      maxInstances: 1,
      "tauri:options": {
        application: app,
      },
    },
  ],
  logLevel: "warn",
  bail: 0,
  baseUrl: "http://localhost",
  waitforTimeout: 10_000,
  connectionRetryTimeout: 60_000,
  connectionRetryCount: 3,
  reporters: ["spec"],
  framework: "mocha",
  mochaOpts: { ui: "bdd", timeout: 60_000 },
  port: 4444,

  // Spin up tauri-driver per session; it in turn spawns WebKitWebDriver on
  // 127.0.0.1:4445. Forcing the host to 127.0.0.1 sidesteps the IPv6 bind
  // issue reported in tauri-apps/tauri#3815.
  beforeSession() {
    rmSync(sandboxDataHome, { recursive: true, force: true });
    mkdirSync(sandboxDataHome, { recursive: true });

    tauriDriverProcess = spawn(
      tauriDriverBin,
      ["--native-host", "127.0.0.1"],
      {
        stdio: [null, process.stdout, process.stderr],
        env: {
          ...process.env,
          // WebKitGTK GPU compositing is flaky under WebDriver on Linux —
          // the CPU fallback gives more reproducible runs at no visible
          // cost for our UI.
          WEBKIT_DISABLE_COMPOSITING_MODE: "1",
          XDG_DATA_HOME: sandboxDataHome,
        },
      },
    );
  },

  afterSession() {
    tauriDriverProcess?.kill();
  },
};
