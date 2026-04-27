import { api } from "./api";
import { formatError } from "./format";
import type { Phase, StoredAccount } from "./types";

export type AuthEvent = "loggedIn";
export type AuthListener = (event: AuthEvent) => void | Promise<void>;

export class AuthController {
  serverUrl = $state("https://vault.example.com");
  email = $state("");
  password = $state("");
  totpCode = $state("");
  yubikeyOtp = $state("");
  selectedProvider = $state(0);
  pendingProviders = $state<number[]>([]);
  webauthnChallenge = $state<string | null>(null);
  webauthnBusy = $state(false);

  phase = $state<Phase>("init");
  storedAccount = $state<StoredAccount | null>(null);
  error = $state<string | null>(null);

  /** True when the persisted session has a Yubikey wrap on disk;
   * drives the "Toucher la Yubikey" button on the unlock view. */
  yubikeyAvailable = $state(false);
  /** True while a CTAP call is in flight (key-tap window).
   * Lets the UI disable the button to prevent re-tap loops. */
  yubikeyBusy = $state(false);
  /** PIN bound to the unlock view's optional input. Cleared after
   * each unlock attempt (success or failure). */
  yubikeyPin = $state("");

  private listeners = new Set<AuthListener>();

  on(listener: AuthListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private async emit(event: AuthEvent) {
    for (const l of this.listeners) {
      try {
        await l(event);
      } catch (e) {
        console.warn("[clavix] auth listener failed:", e);
      }
    }
  }

  /** Resolves the initial phase from the persisted session. */
  async bootstrap(opts: { onboarded: boolean }) {
    try {
      const account = await api.storedAccount();
      if (account) {
        this.storedAccount = account;
        this.serverUrl = account.serverUrl;
        this.email = account.email;
        this.phase = "unlock";
        // Best-effort: tell the unlock view whether to render the
        // Yubikey button. A failure here just hides it — the master
        // password path always works.
        try {
          this.yubikeyAvailable = await api.yubikeyUnlockState();
        } catch (e) {
          console.warn("[clavix] yubikey_unlock_state failed:", e);
          this.yubikeyAvailable = false;
        }
      } else {
        this.phase = opts.onboarded ? "idle" : "onboarding";
      }
    } catch (e) {
      this.error = formatError(e);
      this.phase = "idle";
    }
  }

  async submitLogin(event: Event) {
    event.preventDefault();
    this.phase = "authenticating";
    this.error = null;
    try {
      const result = await api.login(this.serverUrl, this.email, this.password);
      if (result.type === "success") {
        this.storedAccount = { serverUrl: this.serverUrl, email: this.email };
        this.password = "";
        this.phase = "loggedIn";
        await this.emit("loggedIn");
      } else {
        this.pendingProviders = result.data.providers;
        const supported = this.pendingProviders.find(
          (p) => p === 0 || p === 3 || p === 7,
        );
        this.selectedProvider = supported ?? this.pendingProviders[0] ?? 0;
        this.totpCode = "";
        this.yubikeyOtp = "";
        this.webauthnChallenge = result.data.webauthnChallenge ?? null;
        this.phase = "twoFactor";
      }
    } catch (e) {
      this.error = formatError(e);
      this.phase = "error";
    }
  }

  async submitWebauthn() {
    if (!this.webauthnChallenge) return;
    this.webauthnBusy = true;
    this.error = null;
    try {
      const token = await api.webauthnSignChallenge(this.webauthnChallenge);
      await this.finishTwoFactor(token, 7);
    } catch (e) {
      this.error = formatError(e);
    } finally {
      this.webauthnBusy = false;
    }
  }

  private async finishTwoFactor(code: string, provider: number) {
    this.phase = "authenticating";
    try {
      await api.loginWithTwoFactor(code, provider);
      this.storedAccount = { serverUrl: this.serverUrl, email: this.email };
      this.password = "";
      this.totpCode = "";
      this.yubikeyOtp = "";
      this.webauthnChallenge = null;
      this.phase = "loggedIn";
      await this.emit("loggedIn");
    } catch (e) {
      this.error = formatError(e);
      this.phase = "twoFactor";
    }
  }

  async submitTwoFactor(event: Event) {
    event.preventDefault();
    const codeSnapshot =
      this.selectedProvider === 3 ? this.yubikeyOtp.trim() : this.totpCode.trim();
    if (!codeSnapshot) return;
    this.phase = "authenticating";
    this.error = null;
    try {
      await api.loginWithTwoFactor(codeSnapshot, this.selectedProvider);
      this.storedAccount = { serverUrl: this.serverUrl, email: this.email };
      this.password = "";
      this.totpCode = "";
      this.yubikeyOtp = "";
      this.phase = "loggedIn";
      await this.emit("loggedIn");
    } catch (e) {
      this.error = formatError(e);
      this.phase = "twoFactor";
    }
  }

  async submitUnlock(event: Event) {
    event.preventDefault();
    this.phase = "authenticating";
    this.error = null;
    try {
      await api.unlock(this.password);
      this.password = "";
      this.phase = "loggedIn";
      await this.emit("loggedIn");
    } catch (e) {
      this.error = formatError(e);
      this.phase = "unlock";
    }
  }

  /** Try to release the cached user key by touching the registered
   * FIDO2 token. Falls back to leaving the master-password field
   * functional on any error — no silent fallback, the user has to
   * explicitly retry or use the password.
   *
   * On `yubikey_stale_wrap` the backend has already dropped the
   * on-disk wrap; we mirror that here by hiding the button until the
   * user signs in with the master password and re-enrols. */
  async submitYubikey() {
    if (!this.yubikeyAvailable || this.yubikeyBusy) return;
    this.yubikeyBusy = true;
    this.error = null;
    try {
      const pin = this.yubikeyPin.trim();
      await api.unlockWithYubikey(pin.length > 0 ? pin : null);
      this.password = "";
      this.yubikeyPin = "";
      this.phase = "loggedIn";
      await this.emit("loggedIn");
    } catch (e) {
      const tauriErr = e as { code?: string };
      if (tauriErr?.code === "yubikey_stale_wrap") {
        this.yubikeyAvailable = false;
      }
      this.error = formatError(e);
      this.yubikeyPin = "";
    } finally {
      this.yubikeyBusy = false;
    }
  }

  async lock() {
    try {
      await api.lock();
    } catch {
      // best-effort
    }
    this.password = "";
    this.totpCode = "";
    this.pendingProviders = [];
    this.error = null;
    this.phase = this.storedAccount ? "unlock" : "idle";
  }

  async switchAccount() {
    try {
      await api.logout();
    } catch {
      // best-effort
    }
    this.storedAccount = null;
    this.password = "";
    this.totpCode = "";
    this.pendingProviders = [];
    this.error = null;
    this.phase = "idle";
  }

  async cancelTwoFactor() {
    // Tell Rust to drop the parked PendingTwoFactor slot so the
    // master key + password hash get zeroized immediately rather
    // than waiting for the 5-minute TTL. Best-effort: swallowing the
    // error here is fine since the slot will expire on its own.
    try {
      await api.cancelTwoFactor();
    } catch {
      // best-effort
    }
    this.phase = this.storedAccount ? "unlock" : "idle";
    this.error = null;
    this.totpCode = "";
    this.pendingProviders = [];
    this.password = "";
  }
}
