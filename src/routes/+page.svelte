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

  type TypeCounts = {
    login: number;
    secureNote: number;
    card: number;
    identity: number;
    sshKey: number;
  };

  type FolderSummary = { id: string; encryptedName: string };

  type CipherSummary = {
    id: string;
    kind: number;
    encryptedName: string;
    folderId: string | null;
    organizationId: string | null;
    favorite: boolean;
  };

  type SyncSummary = {
    email: string;
    name: string | null;
    itemCount: number;
    folderCount: number;
    collectionCount: number;
    organizationCount: number;
    typeCounts: TypeCounts;
    folders: FolderSummary[];
    cipherPreview: CipherSummary[];
  };

  type Phase = "idle" | "authenticating" | "twoFactor" | "loggedIn" | "error";

  type TauriError = { code: string; message: string; data?: Record<string, unknown> };

  function formatError(e: unknown): string {
    if (e && typeof e === "object" && "message" in e) {
      const m = (e as { message?: unknown }).message;
      if (typeof m === "string") return m;
    }
    return String(e);
  }

  const TOTP_PATTERN = "[0-9]{6}";

  let serverUrl = $state("https://vault.example.com");
  let email = $state("");
  let password = $state("");
  let totpCode = $state("");
  let phase = $state<Phase>("idle");
  let errorMsg = $state<string | null>(null);
  let tokens = $state<TokenSet | null>(null);
  let pendingProviders = $state<number[]>([]);
  let syncSummary = $state<SyncSummary | null>(null);
  let syncing = $state(false);

  async function onLoginSubmit(event: Event) {
    event.preventDefault();
    phase = "authenticating";
    errorMsg = null;
    try {
      const result = await invoke<LoginResult>("login", { serverUrl, email, password });
      if (result.type === "success") {
        tokens = result.data;
        password = "";
        phase = "loggedIn";
      } else {
        pendingProviders = result.data.providers;
        phase = "twoFactor";
      }
    } catch (e) {
      errorMsg = formatError(e);
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
      password = "";
      totpCode = "";
      phase = "loggedIn";
    } catch (e) {
      errorMsg = formatError(e);
      phase = "twoFactor";
    }
  }

  async function onSync() {
    syncing = true;
    errorMsg = null;
    try {
      syncSummary = await invoke<SyncSummary>("sync");
    } catch (e) {
      errorMsg = formatError(e);
    } finally {
      syncing = false;
    }
  }

  async function onLogout() {
    try {
      await invoke("logout");
    } catch {
      // best-effort, on reset de toute façon
    }
    reset();
  }

  function reset() {
    phase = "idle";
    errorMsg = null;
    totpCode = "";
    tokens = null;
    pendingProviders = [];
    password = "";
    syncSummary = null;
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

  const cipherTypeLabel = (k: number): string => {
    switch (k) {
      case 1: return "Login";
      case 2: return "Note";
      case 3: return "Carte";
      case 4: return "Identité";
      case 5: return "Clé SSH";
      default: return `Type ${k}`;
    }
  };
</script>

<main class="container">
  <h1>Clavix</h1>
  <p class="subtitle">Étape 2c : sync du coffre</p>

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
        Providers annoncés : {pendingProviders.map(providerLabel).join(", ")}
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
    <section class="box">
      <h2>Session active</h2>
      <dl>
        <dt>access_token</dt>
        <dd><code>{truncate(tokens.access_token)}</code></dd>
        <dt>expires_in</dt>
        <dd>{formatExpiry(tokens.expires_in)}</dd>
      </dl>
      <div class="row">
        <button type="button" class="secondary" onclick={onLogout}>Se déconnecter</button>
        <button type="button" onclick={onSync} disabled={syncing}>
          {syncing ? "Synchronisation…" : (syncSummary ? "Resynchroniser" : "Synchroniser")}
        </button>
      </div>
    </section>

    {#if syncSummary}
      <section class="box">
        <h2>Coffre synchronisé</h2>

        <dl>
          <dt>Compte</dt>
          <dd>{syncSummary.name ?? syncSummary.email}</dd>
          <dt>Items</dt>
          <dd>{syncSummary.itemCount}</dd>
          <dt>Folders</dt>
          <dd>{syncSummary.folderCount}</dd>
          <dt>Collections</dt>
          <dd>{syncSummary.collectionCount}</dd>
          <dt>Organisations</dt>
          <dd>{syncSummary.organizationCount}</dd>
        </dl>

        <h3>Répartition par type</h3>
        <dl>
          <dt>Logins</dt>
          <dd>{syncSummary.typeCounts.login}</dd>
          <dt>Notes</dt>
          <dd>{syncSummary.typeCounts.secureNote}</dd>
          <dt>Cartes</dt>
          <dd>{syncSummary.typeCounts.card}</dd>
          <dt>Identités</dt>
          <dd>{syncSummary.typeCounts.identity}</dd>
          {#if syncSummary.typeCounts.sshKey > 0}
            <dt>Clés SSH</dt>
            <dd>{syncSummary.typeCounts.sshKey}</dd>
          {/if}
        </dl>

        {#if syncSummary.folders.length > 0}
          <h3>Folders <small>(noms chiffrés bruts)</small></h3>
          <ul class="enc-list">
            {#each syncSummary.folders as f (f.id)}
              <li>
                <span class="idish">{f.id.slice(0, 8)}</span>
                <code>{truncate(f.encryptedName, 56)}</code>
              </li>
            {/each}
          </ul>
        {/if}

        {#if syncSummary.cipherPreview.length > 0}
          <h3>Aperçu items <small>(10 premiers, chiffrés)</small></h3>
          <ul class="enc-list">
            {#each syncSummary.cipherPreview as c (c.id)}
              <li>
                <span class="badge">{cipherTypeLabel(c.kind)}</span>
                <code>{truncate(c.encryptedName, 40)}</code>
                {#if c.favorite}<span class="star" title="Favori">★</span>{/if}
              </li>
            {/each}
          </ul>
          {#if syncSummary.itemCount > syncSummary.cipherPreview.length}
            <p class="hint">
              … et {syncSummary.itemCount - syncSummary.cipherPreview.length} autres.
            </p>
          {/if}
        {/if}
      </section>
    {/if}
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
    max-width: 620px;
    margin: 0 auto;
    padding: 3rem 1.5rem;
  }

  h1 {
    margin: 0 0 0.25rem;
  }

  h2 {
    margin: 0 0 0.75rem;
    font-size: 1rem;
  }

  h3 {
    margin: 1rem 0 0.5rem;
    font-size: 0.9rem;
    color: #444;
  }

  h3 small {
    color: #888;
    font-weight: 400;
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

  .box.error {
    border-left: 4px solid #d63a3a;
  }

  .box.error pre {
    color: #7a1d1d;
    white-space: pre-wrap;
    margin: 0;
  }

  .hint {
    margin: 0.5rem 0 0;
    font-size: 0.85rem;
    color: #555;
  }

  dl {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 0.35rem 1rem;
    margin: 0 0 0.5rem;
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
    word-break: break-all;
  }

  .enc-list {
    list-style: none;
    padding: 0;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
  }

  .enc-list li {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.85rem;
  }

  .idish {
    font-family: ui-monospace, monospace;
    font-size: 0.75rem;
    color: #888;
    min-width: 4.5rem;
  }

  .badge {
    display: inline-block;
    padding: 0.05rem 0.4rem;
    background: #eef2ff;
    color: #3751c4;
    border-radius: 4px;
    font-size: 0.72rem;
    font-weight: 500;
    min-width: 3.5rem;
    text-align: center;
  }

  .star {
    color: #f0a500;
  }

  @media (prefers-color-scheme: dark) {
    :root {
      color: #f6f6f6;
      background-color: #1e1e1e;
    }
    .subtitle, h3 small, .hint { color: #aaa; }
    h3 { color: #ccc; }
    form, .box { background: #2b2b2b; box-shadow: none; }
    label { color: #ccc; }
    input, button { background: #1e1e1e; color: #f6f6f6; border-color: #3a3a3a; }
    button { background: #396cd8; border-color: #396cd8; }
    button.secondary { background: #2b2b2b; color: #ddd; border-color: #3a3a3a; }
    dt { color: #ccc; }
    .box.error pre { color: #ff8a8a; }
    pre { background: #181818; }
    code { background: #333; }
    .idish { color: #999; }
    .badge { background: #1f2a54; color: #aabaff; }
  }
</style>
