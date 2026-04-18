<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";

  type Prelogin = {
    kdf: 0 | 1;
    kdfIterations: number;
    kdfMemory: number | null;
    kdfParallelism: number | null;
  };

  let serverUrl = $state("https://vault.example.com");
  let email = $state("");
  let result = $state<Prelogin | null>(null);
  let error = $state<string | null>(null);
  let loading = $state(false);

  async function runPrelogin(event: Event) {
    event.preventDefault();
    loading = true;
    error = null;
    result = null;
    try {
      result = await invoke<Prelogin>("prelogin", { serverUrl, email });
    } catch (e) {
      error = String(e);
    } finally {
      loading = false;
    }
  }

  const kdfLabel = (k: 0 | 1) => (k === 0 ? "PBKDF2" : "Argon2id");
</script>

<main class="container">
  <h1>Clavix</h1>
  <p class="subtitle">Étape 2a : test du endpoint <code>prelogin</code></p>

  <form onsubmit={runPrelogin}>
    <label>
      Serveur Vaultwarden
      <input type="url" bind:value={serverUrl} required />
    </label>
    <label>
      Email
      <input type="email" bind:value={email} placeholder="toi@exemple.fr" required />
    </label>
    <button type="submit" disabled={loading}>
      {loading ? "Requête en cours…" : "Prelogin"}
    </button>
  </form>

  {#if error}
    <section class="box error">
      <h2>Erreur</h2>
      <pre>{error}</pre>
    </section>
  {/if}

  {#if result}
    <section class="box result">
      <h2>Résultat</h2>
      <dl>
        <dt>KDF</dt>
        <dd>{kdfLabel(result.kdf)} <small>(kdf = {result.kdf})</small></dd>
        <dt>Itérations</dt>
        <dd>{result.kdfIterations.toLocaleString("fr-FR")}</dd>
        {#if result.kdfMemory !== null}
          <dt>Mémoire (KiB)</dt>
          <dd>{result.kdfMemory}</dd>
        {/if}
        {#if result.kdfParallelism !== null}
          <dt>Parallélisme</dt>
          <dd>{result.kdfParallelism}</dd>
        {/if}
      </dl>
      <details>
        <summary>JSON brut</summary>
        <pre>{JSON.stringify(result, null, 2)}</pre>
      </details>
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

  button:hover:not(:disabled) {
    background: #2f5bc7;
  }

  button:disabled {
    opacity: 0.6;
    cursor: progress;
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

  dl {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 0.4rem 1rem;
    margin: 0;
  }

  dt {
    font-weight: 600;
    color: #444;
  }

  dd {
    margin: 0;
  }

  details {
    margin-top: 0.75rem;
  }

  summary {
    cursor: pointer;
    color: #555;
    font-size: 0.85rem;
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
    dt { color: #ccc; }
    .box.error pre { color: #ff8a8a; }
    pre { background: #181818; }
    code { background: #333; }
    summary { color: #aaa; }
  }
</style>
