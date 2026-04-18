<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";

  type TokenSet = {
    access_token: string;
    refresh_token: string;
    expires_in: number;
    token_type: string;
    key: string | null;
    privateKey: string | null;
    kdf: 0 | 1 | null;
    kdfIterations: number | null;
  };

  type LoginResult =
    | { type: "success"; data: TokenSet }
    | { type: "twoFactorRequired"; data: { providers: number[] } };

  type Phase = "idle" | "authenticating" | "twoFactor" | "loggedIn" | "error";

  const TOTP_PATTERN = "[0-9]{6}";

  let serverUrl = $state("https://vault.example.com");
  let email = $state("");
  let password = $state("");
  let totpCode = $state("");
  let phase = $state<Phase>("idle");
  let errorMsg = $state<string | null>(null);
  let tokens = $state<TokenSet | null>(null);
  let pendingProviders = $state<number[]>([]);

  async function onLoginSubmit(event: Event) {
    event.preventDefault();
    phase = "authenticating";
    errorMsg = null;
    try {
      const result = await invoke<LoginResult>("login", { serverUrl, email, password });
      if (result.type === "success") {
        tokens = result.data;
        phase = "loggedIn";
      } else {
        pendingProviders = result.data.providers;
        phase = "twoFactor";
      }
    } catch (e) {
      errorMsg = String(e);
      phase = "error";
    }
  }

  async function onTwoFactorSubmit(event: Event) {
    event.preventDefault();
    const codeSnapshot = totpCode;
    phase = "authenticating";
    errorMsg = null;
    try {
      const result = await invoke<TokenSet>("login_with_two_factor", {
        serverUrl,
        email,
        password,
        code: codeSnapshot,
        provider: 0,
      });
      tokens = result;
      totpCode = "";
      phase = "loggedIn";
    } catch (e) {
      errorMsg = String(e);
      phase = "twoFactor";
    }
  }

  function reset() {
    phase = "idle";
    errorMsg = null;
    totpCode = "";
    tokens = null;
    pendingProviders = [];
    password = "";
  }

  function truncate(s: string, n: number = 24): string {
    return s.length > n ? `${s.slice(0, n)}…` : s;
  }

  function formatExpiry(seconds: number): string {
    const minutes = Math.round(seconds / 60);
    if (minutes >= 60) return `${(minutes / 60).toFixed(1)} h`;
    return `${minutes} min`;
  }

  const providerLabel = (p: number): string => {
    switch (p) {
      case 0: return "TOTP (Authenticator)";
      case 1: return "Email";
      case 2: return "Duo";
      case 3: return "YubiKey OTP";
      case 7: return "WebAuthn / FIDO2";
      default: return `Provider #${p}`;
    }
  };
</script>

<main class="container">
  <h1>Clavix</h1>
  <p class="subtitle">Étape 2b : login Vaultwarden + 2FA TOTP</p>

  {#if phase === "idle" || phase === "authenticating" || phase === "error"}
    <form onsubmit={onLoginSubmit}>
      <label>
        Serveur Vaultwarden
        <input type="url" bind:value={serverUrl} required disabled={phase === "authenticating"} />
      </label>
      <label>
        Email
        <input type="email" bind:value={email} placeholder="toi@exemple.fr" required disabled={phase === "authenticating"} />
      </label>
      <label>
        Mot de passe maître
        <input type="password" bind:value={password} required disabled={phase === "authenticating"} />
      </label>
      <button type="submit" disabled={phase === "authenticating"}>
        {phase === "authenticating" ? "Connexion…" : "Connexion"}
      </button>
    </form>
  {/if}

  {#if phase === "twoFactor"}
    <section class="box">
      <h2>Double authentification</h2>
      <p class="hint">
        Providers annoncés par le serveur : {pendingProviders.map(providerLabel).join(", ")}
      </p>
      <form onsubmit={onTwoFactorSubmit}>
        <label>
          Code TOTP (6 chiffres)
          <input
            type="text"
            bind:value={totpCode}
            inputmode="numeric"
            pattern={TOTP_PATTERN}
            maxlength="6"
            autocomplete="one-time-code"
            required
          />
        </label>
        <div class="row">
          <button type="button" class="secondary" onclick={reset}>Annuler</button>
          <button type="submit">Valider</button>
        </div>
      </form>
    </section>
  {/if}

  {#if phase === "loggedIn" && tokens}
    <section class="box result">
      <h2>Connecté</h2>
      <dl>
        <dt>access_token</dt>
        <dd><code>{truncate(tokens.access_token)}</code></dd>
        <dt>refresh_token</dt>
        <dd><code>{truncate(tokens.refresh_token)}</code></dd>
        <dt>token_type</dt>
        <dd>{tokens.token_type}</dd>
        <dt>expires_in</dt>
        <dd>{formatExpiry(tokens.expires_in)}</dd>
        {#if tokens.kdf !== null && tokens.kdfIterations !== null}
          <dt>KDF du compte</dt>
          <dd>{tokens.kdf === 0 ? "PBKDF2" : "Argon2id"} / {tokens.kdfIterations.toLocaleString("fr-FR")} itérations</dd>
        {/if}
        {#if tokens.key}
          <dt>Key (chiffrée)</dt>
          <dd><code>{truncate(tokens.key, 32)}</code></dd>
        {/if}
      </dl>
      <button type="button" class="secondary" onclick={reset}>Se déconnecter</button>
    </section>
  {/if}

  {#if errorMsg}
    <section class="box error">
      <h2>Erreur</h2>
      <pre>{errorMsg}</pre>
    </section>
  {/if}
</main>

<style>
  :root {
    font-family: Inter, Avenir, Helvetica, Arial, sans-serif;
    font-size: 15px;
    line-height: 1.5;
    color: #0f0f0f;
    background-color: #f6f6f6;
  }

  .container {
    max-width: 540px;
    margin: 0 auto;
    padding: 3rem 1.5rem;
  }

  h1 {
    margin: 0 0 0.25rem;
  }

  .subtitle {
    margin: 0 0 2rem;
    color: #555;
  }

  form {
    display: flex;
    flex-direction: column;
    gap: 0.9rem;
    background: #fff;
    padding: 1.25rem;
    border-radius: 10px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
  }

  label {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    font-size: 0.9rem;
    color: #333;
  }

  input,
  button {
    font: inherit;
    padding: 0.55rem 0.8rem;
    border-radius: 6px;
    border: 1px solid #d0d0d0;
    background: #fff;
  }

  input:focus {
    outline: none;
    border-color: #396cd8;
    box-shadow: 0 0 0 2px rgba(57, 108, 216, 0.15);
  }

  button {
    cursor: pointer;
    background: #396cd8;
    color: #fff;
    border-color: #396cd8;
    font-weight: 500;
  }

  button.secondary {
    background: #fff;
    color: #333;
    border-color: #d0d0d0;
  }

  button:hover:not(:disabled) {
    filter: brightness(0.95);
  }

  button:disabled {
    opacity: 0.6;
    cursor: progress;
  }

  .row {
    display: flex;
    gap: 0.5rem;
    justify-content: flex-end;
  }

  .box {
    margin-top: 1.5rem;
    padding: 1rem 1.25rem;
    border-radius: 10px;
    background: #fff;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
  }

  .box h2 {
    margin: 0 0 0.75rem;
    font-size: 1rem;
  }

  .box.error {
    border-left: 4px solid #d63a3a;
  }

  .box.error pre {
    color: #7a1d1d;
    white-space: pre-wrap;
    margin: 0;
  }

  .hint {
    margin: 0 0 1rem;
    font-size: 0.85rem;
    color: #555;
  }

  dl {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 0.4rem 1rem;
    margin: 0 0 1rem;
  }

  dt {
    font-weight: 600;
    color: #444;
  }

  dd {
    margin: 0;
    overflow-wrap: anywhere;
  }

  pre {
    font-size: 0.8rem;
    background: #f1f1f1;
    padding: 0.5rem;
    border-radius: 6px;
    overflow-x: auto;
  }

  code {
    background: #eee;
    padding: 0.1rem 0.35rem;
    border-radius: 4px;
    font-size: 0.85em;
  }

  @media (prefers-color-scheme: dark) {
    :root {
      color: #f6f6f6;
      background-color: #1e1e1e;
    }
    .subtitle { color: #aaa; }
    form, .box { background: #2b2b2b; box-shadow: none; }
    label { color: #ccc; }
    input, button { background: #1e1e1e; color: #f6f6f6; border-color: #3a3a3a; }
    button { background: #396cd8; border-color: #396cd8; }
    button.secondary { background: #2b2b2b; color: #ddd; border-color: #3a3a3a; }
    dt { color: #ccc; }
    .box.error pre { color: #ff8a8a; }
    .hint { color: #aaa; }
    pre { background: #181818; }
    code { background: #333; }
  }
</style>
