import { spawn, spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";
import { existsSync, mkdirSync, rmSync } from "node:fs";

const here = fileURLToPath(new URL(".", import.meta.url));
const projectRoot = resolve(here, "../..");
const app = resolve(projectRoot, "src-tauri/target/debug/clavix");
const tauriDriverBin = resolve(homedir(), ".cargo/bin/tauri-driver");
const composeFile = resolve(here, "docker-compose.yml");

// Credentials for the seeded Vaultwarden account, shared with the Rust
// seed helper and the WebdriverIO specs.
export const e2eServer = "http://127.0.0.1:8000";
export const e2eEmail = "e2e@clavix.test";
export const e2ePassword = "correct-horse-battery-staple";

// Sandbox the app's data directory so tests cannot touch the real
// ~/.local/share/clavix/ of whoever runs them. store.rs / cache.rs go
// through dirs::data_local_dir(), which honours XDG_DATA_HOME on Linux.
const sandboxDataHome = resolve(here, "sandbox");

function run(cmd, args, opts = {}) {
  const result = spawnSync(cmd, args, { stdio: "inherit", ...opts });
  if (result.status !== 0) {
    throw new Error(
      `${cmd} ${args.join(" ")} exited with status ${result.status}`,
    );
  }
}

async function waitForVaultwarden(timeoutMs = 30_000) {
  const started = Date.now();
  // eslint-disable-next-line no-constant-condition
  while (true) {
    try {
      const r = await fetch(`${e2eServer}/alive`);
      if (r.ok) return;
    } catch {
      /* retry */
    }
    if (Date.now() - started > timeoutMs) {
      throw new Error(
        `Vaultwarden did not respond on ${e2eServer}/alive within ${timeoutMs} ms`,
      );
    }
    await new Promise((r) => setTimeout(r, 300));
  }
}

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

  // Boots Vaultwarden and seeds it before any spec runs. Set
  // E2E_SKIP_DOCKER=1 to reuse an externally-managed container (useful
  // when iterating on specs locally — saves ~3 s per run).
  //
  // We don't pass `--wait` to `docker compose up` because Vaultwarden's
  // first boot sometimes blows through the healthcheck's 60 s window
  // and `docker compose up` then exits with a non-zero status even
  // though the container is actually coming up fine — and that non-zero
  // aborts the whole orchestrator. Our own `waitForVaultwarden()` polls
  // `/alive` with a friendlier timeout.
  async onPrepare() {
    if (process.env.E2E_SKIP_DOCKER !== "1") {
      run("docker", ["compose", "-f", composeFile, "up", "-d"]);
    }
    await waitForVaultwarden();
    run(
      "cargo",
      ["run", "--quiet", "--example", "e2e_seed"],
      {
        cwd: resolve(projectRoot, "src-tauri"),
        env: {
          ...process.env,
          E2E_SERVER_URL: e2eServer,
          E2E_EMAIL: e2eEmail,
          E2E_PASSWORD: e2ePassword,
        },
      },
    );
  },

  onComplete() {
    if (
      process.env.E2E_SKIP_DOCKER !== "1" &&
      process.env.E2E_KEEP_CONTAINER !== "1"
    ) {
      // `down` instead of `stop` so the tmpfs volume is dropped and the
      // next run registers against a blank Vaultwarden.
      run("docker", ["compose", "-f", composeFile, "down", "--volumes"]);
    }
  },

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
