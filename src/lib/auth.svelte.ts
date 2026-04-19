import { api } from "./api";
import { formatError } from "./format";
import type { Phase, StoredAccount, TokenSet } from "./types";

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

  phase = $state<Phase>("init");
  tokens = $state<TokenSet | null>(null);
  storedAccount = $state<StoredAccount | null>(null);
  error = $state<string | null>(null);

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
        this.tokens = result.data;
        this.storedAccount = { serverUrl: this.serverUrl, email: this.email };
        this.password = "";
        this.phase = "loggedIn";
        await this.emit("loggedIn");
      } else {
        this.pendingProviders = result.data.providers;
        const supported = this.pendingProviders.find((p) => p === 0 || p === 3);
        this.selectedProvider = supported ?? this.pendingProviders[0] ?? 0;
        this.totpCode = "";
        this.yubikeyOtp = "";
        this.phase = "twoFactor";
      }
    } catch (e) {
      this.error = formatError(e);
      this.phase = "error";
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
      this.tokens = await api.loginWithTwoFactor(
        this.serverUrl,
        this.email,
        this.password,
        codeSnapshot,
        this.selectedProvider,
      );
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
      this.tokens = await api.unlock(this.password);
      this.password = "";
      this.phase = "loggedIn";
      await this.emit("loggedIn");
    } catch (e) {
      this.error = formatError(e);
      this.phase = "unlock";
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
    this.tokens = null;
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
    this.tokens = null;
    this.pendingProviders = [];
    this.error = null;
    this.phase = "idle";
  }

  cancelTwoFactor() {
    this.phase = this.storedAccount ? "unlock" : "idle";
    this.error = null;
    this.totpCode = "";
    this.tokens = null;
    this.pendingProviders = [];
    this.password = "";
  }
}
