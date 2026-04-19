<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { onMount } from "svelte";

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

  type FolderSummary = { id: string; name: string };
  type OrganizationSummary = { id: string; name: string };
  type CollectionSummary = { id: string; organizationId: string; name: string };

  type CipherSummary = {
    id: string;
    kind: number;
    name: string;
    folderId: string | null;
    organizationId: string | null;
    collectionIds: string[];
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
    organizations: OrganizationSummary[];
    collections: CollectionSummary[];
    ciphers: CipherSummary[];
  };

  type Phase =
    | "init"
    | "idle"
    | "authenticating"
    | "twoFactor"
    | "unlock"
    | "loggedIn"
    | "error";

  type StoredAccount = { serverUrl: string; email: string };

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
  let phase = $state<Phase>("init");
  let errorMsg = $state<string | null>(null);
  let tokens = $state<TokenSet | null>(null);
  let pendingProviders = $state<number[]>([]);
  let syncSummary = $state<SyncSummary | null>(null);
  let syncing = $state(false);
  let storedAccount = $state<StoredAccount | null>(null);
  let search = $state("");
  let selectedKey = $state<string | null>(null);
  let expanded = $state<Set<string>>(new Set());

  type TreeNode = {
    key: string;
    label: string;
    kind: "folder" | "organization" | "collection";
    folderId: string | null;
    organizationId: string | null;
    collectionId: string | null;
    children: TreeNode[];
    itemCount: number;
  };

  const folderTree = $derived.by<TreeNode | null>(() => {
    if (!syncSummary) return null;
    const root: TreeNode = {
      key: "folders",
      label: "Folders",
      kind: "folder",
      folderId: null,
      organizationId: null,
      collectionId: null,
      children: [],
      itemCount: 0,
    };
    for (const f of syncSummary.folders) {
      const segments = splitPath(f.name);
      if (segments.length === 0) continue;
      insertIntoTree(root, segments, { folderId: f.id, kind: "folder" });
    }
    computeFolderCounts(root, syncSummary.ciphers);
    sortTree(root);
    return root;
  });

  const orgTrees = $derived.by<TreeNode[]>(() => {
    if (!syncSummary) return [];
    return syncSummary.organizations.map((org) => {
      const root: TreeNode = {
        key: `org/${org.id}`,
        label: org.name,
        kind: "organization",
        folderId: null,
        organizationId: org.id,
        collectionId: null,
        children: [],
        itemCount: syncSummary!.ciphers.filter((c) => c.organizationId === org.id).length,
      };
      for (const c of syncSummary!.collections) {
        if (c.organizationId !== org.id) continue;
        const segments = splitPath(c.name);
        if (segments.length === 0) continue;
        insertIntoTree(root, segments, {
          collectionId: c.id,
          organizationId: org.id,
          kind: "collection",
        });
      }
      computeCollectionCounts(root, syncSummary!.ciphers);
      sortTree(root);
      return root;
    });
  });

  function splitPath(name: string): string[] {
    return name.split("/").map((s) => s.trim()).filter((s) => s.length > 0);
  }

  function insertIntoTree(
    root: TreeNode,
    segments: string[],
    leaf: { folderId?: string; collectionId?: string; organizationId?: string; kind: "folder" | "collection" },
  ) {
    let current = root;
    let acc = root.key;
    for (let i = 0; i < segments.length; i++) {
      const seg = segments[i];
      acc = `${acc}/${seg}`;
      let child = current.children.find((c) => c.label === seg);
      if (!child) {
        child = {
          key: acc,
          label: seg,
          kind: leaf.kind,
          folderId: null,
          organizationId: leaf.organizationId ?? null,
          collectionId: null,
          children: [],
          itemCount: 0,
        };
        current.children.push(child);
      }
      if (i === segments.length - 1) {
        if (leaf.folderId) child.folderId = leaf.folderId;
        if (leaf.collectionId) child.collectionId = leaf.collectionId;
      }
      current = child;
    }
  }

  function computeFolderCounts(node: TreeNode, ciphers: CipherSummary[]): number {
    const direct = node.folderId
      ? ciphers.filter((c) => c.folderId === node.folderId).length
      : 0;
    let total = direct;
    for (const child of node.children) {
      total += computeFolderCounts(child, ciphers);
    }
    node.itemCount = total;
    return total;
  }

  function computeCollectionCounts(node: TreeNode, ciphers: CipherSummary[]): number {
    const direct = node.collectionId
      ? ciphers.filter((c) => c.collectionIds.includes(node.collectionId!)).length
      : 0;
    let total = direct;
    for (const child of node.children) {
      total += computeCollectionCounts(child, ciphers);
    }
    // For organization root, keep the pre-computed total (all items of the org)
    if (node.kind !== "organization") {
      node.itemCount = total;
    }
    return total;
  }

  function sortTree(node: TreeNode) {
    node.children.sort((a, b) => a.label.localeCompare(b.label, "fr"));
    for (const child of node.children) sortTree(child);
  }

  function findNodeInTrees(key: string): TreeNode | null {
    const search = (node: TreeNode): TreeNode | null => {
      if (node.key === key) return node;
      for (const c of node.children) {
        const found = search(c);
        if (found) return found;
      }
      return null;
    };
    if (folderTree) {
      const hit = search(folderTree);
      if (hit) return hit;
    }
    for (const t of orgTrees) {
      const hit = search(t);
      if (hit) return hit;
    }
    return null;
  }

  function collectFolderIds(node: TreeNode, ids: Set<string>) {
    if (node.folderId) ids.add(node.folderId);
    for (const c of node.children) collectFolderIds(c, ids);
  }

  function collectCollectionIds(node: TreeNode, ids: Set<string>) {
    if (node.collectionId) ids.add(node.collectionId);
    for (const c of node.children) collectCollectionIds(c, ids);
  }

  const filteredCiphers = $derived.by(() => {
    if (!syncSummary) return [];
    const q = search.trim().toLowerCase();
    let items = syncSummary.ciphers;

    if (selectedKey) {
      const node = findNodeInTrees(selectedKey);
      if (node) {
        if (node.kind === "folder") {
          const ids = new Set<string>();
          collectFolderIds(node, ids);
          items = items.filter((c) => c.folderId !== null && ids.has(c.folderId));
        } else if (node.kind === "organization") {
          items = items.filter((c) => c.organizationId === node.organizationId);
        } else {
          const ids = new Set<string>();
          collectCollectionIds(node, ids);
          items = items.filter((c) => c.collectionIds.some((cid) => ids.has(cid)));
        }
      }
    }

    if (q) {
      items = items.filter((c) => c.name.toLowerCase().includes(q));
    }
    return items;
  });

  function toggleExpanded(key: string) {
    const next = new Set(expanded);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    expanded = next;
  }

  function selectNode(key: string) {
    selectedKey = selectedKey === key ? null : key;
  }

  onMount(async () => {
    try {
      const account = await invoke<StoredAccount | null>("stored_account");
      if (account) {
        storedAccount = account;
        serverUrl = account.serverUrl;
        email = account.email;
        phase = "unlock";
      } else {
        phase = "idle";
      }
    } catch (e) {
      errorMsg = formatError(e);
      phase = "idle";
    }
  });

  async function onLoginSubmit(event: Event) {
    event.preventDefault();
    phase = "authenticating";
    errorMsg = null;
    try {
      const result = await invoke<LoginResult>("login", { serverUrl, email, password });
      if (result.type === "success") {
        tokens = result.data;
        storedAccount = { serverUrl, email };
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
      storedAccount = { serverUrl, email };
      password = "";
      totpCode = "";
      phase = "loggedIn";
    } catch (e) {
      errorMsg = formatError(e);
      phase = "twoFactor";
    }
  }

  async function onUnlockSubmit(event: Event) {
    event.preventDefault();
    phase = "authenticating";
    errorMsg = null;
    try {
      tokens = await invoke<TokenSet>("unlock", { password });
      password = "";
      phase = "loggedIn";
    } catch (e) {
      errorMsg = formatError(e);
      phase = "unlock";
    }
  }

  async function onLock() {
    try {
      await invoke("lock");
    } catch {
      // best-effort
    }
    password = "";
    totpCode = "";
    tokens = null;
    syncSummary = null;
    pendingProviders = [];
    errorMsg = null;
    phase = storedAccount ? "unlock" : "idle";
  }

  async function switchAccount() {
    try {
      await invoke("logout");
    } catch {
      // best-effort
    }
    storedAccount = null;
    password = "";
    totpCode = "";
    tokens = null;
    syncSummary = null;
    pendingProviders = [];
    errorMsg = null;
    phase = "idle";
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

  function reset() {
    phase = storedAccount ? "unlock" : "idle";
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

  {#if phase === "init"}
    <p class="subtitle">Chargement…</p>
  {/if}

  {#if phase === "idle" || (phase === "authenticating" && !storedAccount) || phase === "error"}
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

  {#if phase === "unlock" || (phase === "authenticating" && storedAccount)}
    <section class="box">
      <h2>Déverrouiller</h2>
      <p class="hint">
        {storedAccount?.email} sur {storedAccount?.serverUrl}
      </p>
      <form onsubmit={onUnlockSubmit}>
        <label>
          Mot de passe maître
          <input type="password" bind:value={password} required disabled={phase === "authenticating"} />
        </label>
        <div class="row">
          <button type="button" class="secondary" onclick={switchAccount}>Changer de compte</button>
          <button type="submit" disabled={phase === "authenticating"}>
            {phase === "authenticating" ? "Déverrouillage…" : "Déverrouiller"}
          </button>
        </div>
      </form>
    </section>
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
        <button type="button" class="secondary" onclick={switchAccount}>Se déconnecter</button>
        <button type="button" class="secondary" onclick={onLock}>Verrouiller</button>
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
          <h3>Folders</h3>
          <ul class="enc-list">
            {#each syncSummary.folders as f (f.id)}
              <li>
                <span class="idish">{f.id.slice(0, 8)}</span>
                <span class="name">{f.name}</span>
              </li>
            {/each}
          </ul>
        {/if}

        {#if syncSummary.ciphers.length > 0}
          <div class="vault-layout">
            <aside class="tree-pane">
              <button
                type="button"
                class="tree-all"
                class:selected={selectedKey === null}
                onclick={() => (selectedKey = null)}
              >
                <span>Tous les items</span>
                <span class="tree-count">{syncSummary.itemCount.toLocaleString("fr-FR")}</span>
              </button>
              {#if folderTree && folderTree.children.length > 0}
                <h4>Folders</h4>
                <ul class="tree-root">
                  {#each folderTree.children as node (node.key)}
                    {@render treeNode(node)}
                  {/each}
                </ul>
              {/if}
              {#if orgTrees.length > 0}
                <h4>Organisations</h4>
                <ul class="tree-root">
                  {#each orgTrees as orgRoot (orgRoot.key)}
                    {@render orgRootNode(orgRoot)}
                  {/each}
                </ul>
              {/if}
            </aside>

            <section class="list-pane">
              <h3>
                Items
                <small>
                  ({filteredCiphers.length.toLocaleString("fr-FR")}
                  {#if search.trim() || selectedKey}/{syncSummary.ciphers.length.toLocaleString("fr-FR")}{/if})
                </small>
              </h3>
              <div class="search-row">
                <input
                  type="search"
                  bind:value={search}
                  placeholder="Rechercher un item…"
                  class="search"
                />
                {#if search.trim()}
                  <button type="button" class="secondary small" onclick={() => (search = "")}>
                    Effacer
                  </button>
                {/if}
              </div>
              {#if filteredCiphers.length === 0}
                <p class="hint">
                  {#if search.trim()}
                    Aucun item ne correspond à « {search} ».
                  {:else}
                    Aucun item dans ce dossier.
                  {/if}
                </p>
              {:else}
                <ul class="enc-list">
                  {#each filteredCiphers as c (c.id)}
                    <li>
                      <span class="badge">{cipherTypeLabel(c.kind)}</span>
                      <span class="name">{c.name}</span>
                      {#if c.favorite}<span class="star" title="Favori">★</span>{/if}
                    </li>
                  {/each}
                </ul>
              {/if}
            </section>
          </div>
        {/if}

        {#snippet treeNode(node: TreeNode)}
          <li>
            <div class="tree-row" class:selected={selectedKey === node.key}>
              {#if node.children.length > 0}
                <button
                  type="button"
                  class="tree-toggle"
                  onclick={() => toggleExpanded(node.key)}
                  aria-label={expanded.has(node.key) ? "Réduire" : "Déplier"}
                >
                  {expanded.has(node.key) ? "▼" : "▶"}
                </button>
              {:else}
                <span class="tree-spacer"></span>
              {/if}
              <button
                type="button"
                class="tree-label"
                onclick={() => selectNode(node.key)}
              >
                <span class="tree-label-text">{node.label}</span>
                <span class="tree-count">{node.itemCount}</span>
              </button>
            </div>
            {#if expanded.has(node.key) && node.children.length > 0}
              <ul class="tree-children">
                {#each node.children as child (child.key)}
                  {@render treeNode(child)}
                {/each}
              </ul>
            {/if}
          </li>
        {/snippet}

        {#snippet orgRootNode(node: TreeNode)}
          <li>
            <div class="tree-row org-root" class:selected={selectedKey === node.key}>
              {#if node.children.length > 0}
                <button
                  type="button"
                  class="tree-toggle"
                  onclick={() => toggleExpanded(node.key)}
                  aria-label={expanded.has(node.key) ? "Réduire" : "Déplier"}
                >
                  {expanded.has(node.key) ? "▼" : "▶"}
                </button>
              {:else}
                <span class="tree-spacer"></span>
              {/if}
              <button
                type="button"
                class="tree-label"
                onclick={() => selectNode(node.key)}
              >
                <span class="tree-label-text">{node.label}</span>
                <span class="tree-count">{node.itemCount}</span>
              </button>
            </div>
            {#if expanded.has(node.key) && node.children.length > 0}
              <ul class="tree-children">
                {#each node.children as child (child.key)}
                  {@render treeNode(child)}
                {/each}
              </ul>
            {/if}
          </li>
        {/snippet}
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
    max-width: 960px;
    margin: 0 auto;
    padding: 2rem 1.5rem;
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

  .name {
    overflow-wrap: anywhere;
    flex: 1;
  }

  .star {
    color: #f0a500;
  }

  .search-row {
    display: flex;
    gap: 0.5rem;
    margin: 0.5rem 0 0.75rem;
  }

  .search {
    flex: 1;
  }

  button.small {
    padding: 0.4rem 0.75rem;
    font-size: 0.9rem;
  }

  .vault-layout {
    display: grid;
    grid-template-columns: 260px 1fr;
    gap: 1rem;
    align-items: start;
  }

  .tree-pane {
    background: #fff;
    border-radius: 10px;
    padding: 0.75rem;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
    max-height: 70vh;
    overflow-y: auto;
  }

  .tree-pane h4 {
    margin: 0.75rem 0 0.3rem;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    color: #888;
  }

  .tree-root,
  .tree-children {
    list-style: none;
    padding: 0;
    margin: 0;
  }

  .tree-children {
    padding-left: 0.9rem;
    margin-left: 0.5rem;
    border-left: 1px solid #e5e5e5;
  }

  .tree-row {
    display: flex;
    align-items: center;
    gap: 0.15rem;
    min-width: 0;
  }

  .tree-toggle,
  .tree-spacer {
    width: 1.3rem;
    min-width: 1.3rem;
    height: 1.3rem;
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }

  .tree-toggle {
    background: transparent;
    border: none;
    cursor: pointer;
    font-size: 0.6rem;
    color: #777;
    padding: 0;
  }

  .tree-label {
    flex: 1;
    min-width: 0;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.4rem;
    padding: 0.2rem 0.4rem;
    background: transparent;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    color: inherit;
    font: inherit;
    text-align: left;
  }

  .tree-label-text {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .tree-label:hover {
    background: #f0f0f0;
  }

  .tree-row.selected > .tree-label {
    background: #e3ecff;
    color: #1e3a8a;
    font-weight: 500;
  }

  .tree-count {
    font-size: 0.72rem;
    color: #888;
    background: #f1f1f1;
    padding: 0.05rem 0.4rem;
    border-radius: 10px;
    min-width: 1.5rem;
    text-align: center;
  }

  .tree-row.selected > .tree-label .tree-count {
    background: #c5d6ff;
    color: #1e3a8a;
  }

  .tree-all {
    display: flex;
    width: 100%;
    align-items: center;
    justify-content: space-between;
    padding: 0.5rem 0.6rem;
    border: none;
    background: transparent;
    border-radius: 6px;
    cursor: pointer;
    color: inherit;
    font: inherit;
    font-weight: 500;
  }

  .tree-all:hover {
    background: #f0f0f0;
  }

  .tree-all.selected {
    background: #e3ecff;
    color: #1e3a8a;
  }

  .tree-row.org-root > .tree-label {
    font-weight: 500;
  }

  @media (max-width: 760px) {
    .vault-layout {
      grid-template-columns: 1fr;
    }
    .tree-pane {
      max-height: 40vh;
    }
  }

  @media (prefers-color-scheme: dark) {
    .tree-pane {
      background: #2b2b2b;
      box-shadow: none;
    }
    .tree-pane h4 { color: #aaa; }
    .tree-label:hover, .tree-all:hover { background: #333; }
    .tree-row.selected > .tree-label,
    .tree-all.selected {
      background: #1f2a54;
      color: #aabaff;
    }
    .tree-count {
      background: #333;
      color: #aaa;
    }
    .tree-row.selected > .tree-label .tree-count {
      background: #2a3870;
      color: #aabaff;
    }
    .tree-children { border-left-color: #444; }
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
