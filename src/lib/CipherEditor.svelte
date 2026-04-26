<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import QrScanner from "$lib/QrScanner.svelte";
  import { api } from "$lib/api";
  import type { TauriError } from "$lib/types";

  type FolderSummary = { id: string; name: string };
  type OrganizationSummary = { id: string; name: string };
  type CollectionSummary = { id: string; organizationId: string; name: string };

  export type CipherKind = 1 | 2 | 3 | 4 | 5;

  type CardFields = {
    cardholderName: string;
    brand: string;
    number: string;
    expMonth: string;
    expYear: string;
    code: string;
  };

  type IdentityFields = {
    title: string;
    firstName: string;
    middleName: string;
    lastName: string;
    address1: string;
    address2: string;
    address3: string;
    city: string;
    state: string;
    postalCode: string;
    country: string;
    company: string;
    email: string;
    phone: string;
    ssn: string;
    username: string;
    passportNumber: string;
    licenseNumber: string;
  };

  type SshKeyFields = {
    privateKey: string;
    publicKey: string;
    keyFingerprint: string;
  };

  export type Initial = {
    id: string | null;
    cipherType: CipherKind;
    name: string;
    folderId: string | null;
    favorite: boolean;
    notes: string;
    // login
    username: string;
    password: string;
    uris: string[];
    totp: string;
    // card
    card: CardFields;
    // identity
    identity: IdentityFields;
    // ssh
    sshKey: SshKeyFields;
    // org scoping
    organizationId: string | null;
    collectionIds: string[];
  };

  export type SubmitPayload = Omit<Initial, "id">;

  const EMPTY_CARD: CardFields = {
    cardholderName: "",
    brand: "",
    number: "",
    expMonth: "",
    expYear: "",
    code: "",
  };

  const EMPTY_IDENTITY: IdentityFields = {
    title: "",
    firstName: "",
    middleName: "",
    lastName: "",
    address1: "",
    address2: "",
    address3: "",
    city: "",
    state: "",
    postalCode: "",
    country: "",
    company: "",
    email: "",
    phone: "",
    ssn: "",
    username: "",
    passportNumber: "",
    licenseNumber: "",
  };

  const EMPTY_SSH: SshKeyFields = {
    privateKey: "",
    publicKey: "",
    keyFingerprint: "",
  };

  let {
    open,
    mode,
    initial,
    folders,
    organizations,
    collections,
    onCancel,
    onSubmit,
  }: {
    open: boolean;
    mode: "create" | "edit";
    initial: Initial;
    folders: FolderSummary[];
    organizations: OrganizationSummary[];
    collections: CollectionSummary[];
    onCancel: () => void;
    onSubmit: (payload: SubmitPayload) => Promise<void>;
  } = $props();

  let cipherType = $state<CipherKind>(1);
  let name = $state("");
  let folderId = $state<string | null>(null);
  let favorite = $state(false);
  let notes = $state("");
  let username = $state("");
  let password = $state("");
  let urisInput = $state("");
  let totp = $state("");
  let card = $state<CardFields>({ ...EMPTY_CARD });
  let identity = $state<IdentityFields>({ ...EMPTY_IDENTITY });
  let sshKey = $state<SshKeyFields>({ ...EMPTY_SSH });
  let organizationId = $state<string | null>(null);
  let collectionId = $state<string | null>(null);
  let showPassword = $state(false);
  let submitting = $state(false);
  let error = $state<string | null>(null);
  let qrOpen = $state(false);

  // SSH passphrase prompt state — populated when the user pastes an
  // encrypted OpenSSH private key. The passphrase is consumed once
  // (decrypts the PEM, fills publicKey/fingerprint if empty) and never
  // stored anywhere — same model as Bitwarden Desktop's import flow.
  let sshPassphrase = $state("");
  let sshPassphrasePrompt = $state(false);
  let sshPassphraseError = $state<string | null>(null);

  // SSH key generation (create mode only) — calls into the Rust
  // `generate_ssh_key` command which produces a fresh Ed25519 keypair
  // via ssh_key::PrivateKey::random and returns the canonical OpenSSH
  // PEM + ssh-ed25519 line + SHA-256 fingerprint, which we drop straight
  // into the bound state. Mirrors Bitwarden Desktop's "generate" button
  // in the SSH cipher editor.
  let sshGenerating = $state(false);

  const orgCollections = $derived(
    organizationId ? collections.filter((c) => c.organizationId === organizationId) : [],
  );

  $effect(() => {
    if (open) {
      cipherType = initial.cipherType;
      name = initial.name;
      folderId = initial.folderId;
      favorite = initial.favorite;
      notes = initial.notes;
      username = initial.username;
      password = initial.password;
      urisInput = initial.uris.join("\n");
      totp = initial.totp;
      card = { ...initial.card };
      identity = { ...initial.identity };
      sshKey = { ...initial.sshKey };
      organizationId = initial.organizationId;
      collectionId = initial.collectionIds[0] ?? null;
      showPassword = false;
      submitting = false;
      error = null;
      sshPassphrase = "";
      sshPassphrasePrompt = false;
      sshPassphraseError = null;
      sshGenerating = false;
    }
  });

  async function handleGenerateSshKey() {
    if (sshGenerating) return;
    sshGenerating = true;
    error = null;
    try {
      const fresh = await api.generateSshKey();
      sshKey.privateKey = fresh.privateKey;
      sshKey.publicKey = fresh.publicKey;
      sshKey.keyFingerprint = fresh.keyFingerprint;
    } catch (e) {
      error = (e as Error).message ?? String(e);
    } finally {
      sshGenerating = false;
    }
  }

  function tauriCode(e: unknown): string | null {
    if (e && typeof e === "object" && "code" in e) {
      return (e as TauriError).code;
    }
    return null;
  }

  /**
   * Normalize the SSH key fields before submit. Returns true if the editor
   * can proceed with submit; false if we showed a passphrase prompt and need
   * the user to fill it in. Fills `publicKey`/`keyFingerprint` if empty.
   */
  async function prepareSshKey(): Promise<boolean> {
    if (cipherType !== 5) return true;
    const pem = sshKey.privateKey.trim();
    if (pem.length === 0) return true;
    // Skip work when the private key is unchanged from what the cipher
    // already holds — we don't want to re-normalize on every save.
    if (mode === "edit" && pem === initial.sshKey.privateKey.trim()) return true;

    try {
      const decrypted = await api.decryptSshPrivateKey(
        pem,
        sshPassphrase.length > 0 ? sshPassphrase : null,
      );
      sshKey.privateKey = decrypted.privateKey;
      if (sshKey.publicKey.trim().length === 0) sshKey.publicKey = decrypted.publicKey;
      if (sshKey.keyFingerprint.trim().length === 0)
        sshKey.keyFingerprint = decrypted.keyFingerprint;
      sshPassphrase = "";
      sshPassphrasePrompt = false;
      sshPassphraseError = null;
      return true;
    } catch (e) {
      const code = tauriCode(e);
      if (code === "ssh_passphrase_required") {
        sshPassphrasePrompt = true;
        sshPassphraseError = null;
        return false;
      }
      if (code === "ssh_wrong_passphrase") {
        sshPassphrasePrompt = true;
        sshPassphraseError = m.ssh_passphrase_wrong();
        return false;
      }
      // Any other error (parse, unsupported algorithm) — surface it on the
      // main editor error line and let the user fix the input.
      throw e;
    }
  }

  function generatePassword() {
    const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const lower = "abcdefghijklmnopqrstuvwxyz";
    const digits = "0123456789";
    const symbols = "!@#$%^&*()-_=+[]{};:,.<>?/";
    const ambiguous = /[O0Il1|`']/g;
    const charset = (upper + lower + digits + symbols).replace(ambiguous, "");
    const length = 20;
    const chars = Array.from(charset);
    const rng = new Uint32Array(length);
    crypto.getRandomValues(rng);
    const out: string[] = [];
    for (let i = 0; i < length; i++) out.push(chars[rng[i] % chars.length]);
    password = out.join("");
    showPassword = true;
  }

  async function handleSubmit(e: Event) {
    e.preventDefault();
    if (!name.trim()) return;
    submitting = true;
    error = null;
    try {
      const ready = await prepareSshKey();
      if (!ready) {
        submitting = false;
        return;
      }
      const uris = urisInput
        .split(/\r?\n/)
        .map((u) => u.trim())
        .filter((u) => u.length > 0);
      await onSubmit({
        cipherType,
        name: name.trim(),
        folderId: organizationId ? null : folderId || null,
        favorite,
        notes,
        username,
        password,
        uris,
        totp,
        card: { ...card },
        identity: { ...identity },
        sshKey: { ...sshKey },
        organizationId,
        collectionIds: organizationId && collectionId ? [collectionId] : [],
      });
    } catch (e) {
      error = (e as Error).message ?? String(e);
    } finally {
      submitting = false;
    }
  }
</script>

{#if open}
  <div
    class="editor-backdrop"
    onclick={onCancel}
    onkeydown={(e) => e.key === "Escape" && onCancel()}
    role="presentation"
  >
    <div
      class="editor-panel"
      onclick={(e) => e.stopPropagation()}
      onkeydown={(e) => e.stopPropagation()}
      role="dialog"
      aria-modal="true"
      aria-labelledby="editor-title"
      tabindex="-1"
    >
      <header class="editor-header">
        <h2 id="editor-title">
          {mode === "create" ? m.editor_create_title_generic() : m.editor_edit_title()}
        </h2>
        <button type="button" class="secondary small" onclick={onCancel} aria-label={m.action_close()}>
          ✕
        </button>
      </header>

      <form onsubmit={handleSubmit}>
        {#if mode === "create"}
          <label>
            {m.editor_type()}
            <select bind:value={cipherType}>
              <option value={1}>🔐 {m.type_login()}</option>
              <option value={2}>📝 {m.type_note()}</option>
              <option value={3}>💳 {m.type_card()}</option>
              <option value={4}>🪪 {m.type_identity()}</option>
              <option value={5}>🔑 {m.type_ssh_key()}</option>
            </select>
          </label>
        {/if}

        <label>
          {m.editor_name()}
          <input type="text" bind:value={name} required />
        </label>

        {#if organizations.length > 0}
          <label>
            {m.editor_owner()}
            <select
              bind:value={organizationId}
              disabled={mode === "edit"}
              title={mode === "edit" ? m.editor_owner_locked() : undefined}
            >
              <option value={null}>{m.editor_owner_personal()}</option>
              {#each organizations as org (org.id)}
                <option value={org.id}>{org.name}</option>
              {/each}
            </select>
          </label>
        {/if}

        {#if organizationId}
          <label>
            {m.editor_collection()}
            <select bind:value={collectionId}>
              {#if orgCollections.length === 0}
                <option value={null} disabled>{m.editor_no_collection()}</option>
              {:else}
                {#each orgCollections as c (c.id)}
                  <option value={c.id}>{c.name}</option>
                {/each}
              {/if}
            </select>
          </label>
        {:else}
          <label>
            {m.editor_folder()}
            <select bind:value={folderId}>
              <option value={null}>{m.editor_no_folder()}</option>
              {#each folders as f (f.id)}
                <option value={f.id}>{f.name}</option>
              {/each}
            </select>
          </label>
        {/if}

        {#if cipherType === 1}
          <label>
            {m.detail_field_username()}
            <input type="text" bind:value={username} autocomplete="off" />
          </label>
          <label>
            {m.detail_field_password()}
            <div class="password-row">
              <input
                type={showPassword ? "text" : "password"}
                bind:value={password}
                autocomplete="off"
              />
              <button
                type="button"
                class="secondary small"
                onclick={() => (showPassword = !showPassword)}
              >
                {showPassword ? m.action_hide() : m.action_show()}
              </button>
              <button type="button" class="secondary small" onclick={generatePassword}>
                🎲
              </button>
            </div>
          </label>
          <label>
            {m.editor_uris()}
            <textarea bind:value={urisInput} rows="2" placeholder={m.editor_uris_placeholder()}></textarea>
          </label>
          <label>
            {m.detail_field_totp()}
            <div class="totp-row">
              <input type="text" bind:value={totp} autocomplete="off" placeholder="otpauth://…" />
              <button
                type="button"
                class="secondary small"
                onclick={() => (qrOpen = true)}
                title={m.qr_button_title()}
              >
                📷
              </button>
            </div>
          </label>
        {:else if cipherType === 3}
          <label>
            {m.detail_field_cardholder()}
            <input type="text" bind:value={card.cardholderName} autocomplete="off" />
          </label>
          <label>
            {m.detail_field_brand()}
            <input type="text" bind:value={card.brand} autocomplete="off" />
          </label>
          <label>
            {m.detail_field_number()}
            <input type="text" bind:value={card.number} autocomplete="off" />
          </label>
          <div class="two-col">
            <label>
              {m.detail_field_expiry()}
              <div class="expiry-row">
                <input type="text" bind:value={card.expMonth} placeholder="MM" maxlength="2" />
                <span>/</span>
                <input type="text" bind:value={card.expYear} placeholder="YY" maxlength="4" />
              </div>
            </label>
            <label>
              {m.detail_field_cvv()}
              <input type="text" bind:value={card.code} autocomplete="off" maxlength="4" />
            </label>
          </div>
        {:else if cipherType === 4}
          <div class="two-col">
            <label>
              {m.identity_title()}
              <input type="text" bind:value={identity.title} autocomplete="off" />
            </label>
            <label>
              {m.identity_first_name()}
              <input type="text" bind:value={identity.firstName} autocomplete="off" />
            </label>
          </div>
          <div class="two-col">
            <label>
              {m.identity_middle_name()}
              <input type="text" bind:value={identity.middleName} autocomplete="off" />
            </label>
            <label>
              {m.identity_last_name()}
              <input type="text" bind:value={identity.lastName} autocomplete="off" />
            </label>
          </div>
          <label>
            {m.identity_username()}
            <input type="text" bind:value={identity.username} autocomplete="off" />
          </label>
          <label>
            {m.identity_email()}
            <input type="email" bind:value={identity.email} autocomplete="off" />
          </label>
          <label>
            {m.identity_phone()}
            <input type="tel" bind:value={identity.phone} autocomplete="off" />
          </label>
          <label>
            {m.identity_company()}
            <input type="text" bind:value={identity.company} autocomplete="off" />
          </label>
          <label>
            {m.identity_address1()}
            <input type="text" bind:value={identity.address1} autocomplete="off" />
          </label>
          <label>
            {m.identity_address2()}
            <input type="text" bind:value={identity.address2} autocomplete="off" />
          </label>
          <div class="two-col">
            <label>
              {m.identity_city()}
              <input type="text" bind:value={identity.city} autocomplete="off" />
            </label>
            <label>
              {m.identity_postal_code()}
              <input type="text" bind:value={identity.postalCode} autocomplete="off" />
            </label>
          </div>
          <div class="two-col">
            <label>
              {m.identity_state()}
              <input type="text" bind:value={identity.state} autocomplete="off" />
            </label>
            <label>
              {m.identity_country()}
              <input type="text" bind:value={identity.country} autocomplete="off" />
            </label>
          </div>
          <label>
            {m.detail_field_ssn()}
            <input type="text" bind:value={identity.ssn} autocomplete="off" />
          </label>
          <div class="two-col">
            <label>
              {m.identity_passport()}
              <input type="text" bind:value={identity.passportNumber} autocomplete="off" />
            </label>
            <label>
              {m.identity_license()}
              <input type="text" bind:value={identity.licenseNumber} autocomplete="off" />
            </label>
          </div>
        {:else if cipherType === 5}
          {#if mode === "create" && sshKey.privateKey.trim().length === 0}
            <div class="ssh-generate-row">
              <button
                type="button"
                class="ssh-generate-btn"
                onclick={handleGenerateSshKey}
                disabled={sshGenerating}
              >
                {sshGenerating ? m.ssh_generate_running() : m.ssh_generate_action()}
              </button>
              <small class="ssh-generate-hint">{m.ssh_generate_hint()}</small>
            </div>
          {/if}
          <label>
            {m.detail_field_private_key()}
            <textarea
              bind:value={sshKey.privateKey}
              rows="6"
              placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
              class="ssh-private-key"
            ></textarea>
          </label>
          {#if sshPassphrasePrompt}
            <label>
              {m.ssh_passphrase_label()}
              <input
                type="password"
                bind:value={sshPassphrase}
                autocomplete="off"
                placeholder="••••••••"
              />
              <small class="ssh-passphrase-hint">
                {sshPassphraseError ?? m.ssh_passphrase_required()}
              </small>
              <small class="ssh-passphrase-note">{m.ssh_passphrase_hint()}</small>
            </label>
          {/if}
          <label>
            {m.detail_field_public_key()}
            <textarea bind:value={sshKey.publicKey} rows="2" placeholder="ssh-ed25519 AAAA…"></textarea>
          </label>
          <label>
            {m.detail_field_fingerprint()}
            <input type="text" bind:value={sshKey.keyFingerprint} autocomplete="off" placeholder="SHA256:…" />
          </label>
        {/if}

        <label>
          {m.detail_field_notes()}
          <textarea bind:value={notes} rows="3"></textarea>
        </label>

        <label class="checkbox-row">
          <input type="checkbox" bind:checked={favorite} />
          <span>★ {m.items_favorite()}</span>
        </label>

        {#if error}
          <p class="editor-error">{error}</p>
        {/if}

        <div class="row">
          <button type="button" class="secondary" onclick={onCancel} disabled={submitting}>
            {m.action_cancel()}
          </button>
          <button type="submit" disabled={submitting || !name.trim()}>
            {submitting ? m.editor_saving() : m.action_save()}
          </button>
        </div>
      </form>
    </div>
  </div>

  <QrScanner
    open={qrOpen}
    onCancel={() => (qrOpen = false)}
    onDetected={(uri) => {
      totp = uri;
      qrOpen = false;
    }}
  />
{/if}

<style>
  .editor-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.35);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }

  .editor-panel {
    background: #fff;
    border-radius: 10px;
    padding: 1.25rem 1.5rem;
    width: min(560px, 94vw);
    max-height: 90vh;
    overflow-y: auto;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.25);
  }

  .editor-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.75rem;
  }

  .editor-header h2 {
    margin: 0;
    font-size: 1.05rem;
  }

  form {
    display: flex;
    flex-direction: column;
    gap: 0.65rem;
    background: none;
    padding: 0;
    box-shadow: none;
  }

  label {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    font-size: 0.85rem;
    color: #333;
  }

  input[type="text"],
  input[type="email"],
  input[type="tel"],
  input[type="password"],
  select,
  textarea {
    font: inherit;
    padding: 0.45rem 0.65rem;
    border-radius: 6px;
    border: 1px solid #d0d0d0;
    background: #fff;
  }

  textarea {
    resize: vertical;
    font-family: inherit;
  }

  .ssh-private-key {
    font-family: ui-monospace, monospace;
    font-size: 0.82rem;
  }

  .ssh-generate-row {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    margin-bottom: 0.25rem;
  }

  .ssh-generate-btn {
    align-self: flex-start;
  }

  .ssh-generate-hint {
    color: var(--color-muted, #888);
    font-size: 0.78rem;
  }

  .ssh-passphrase-hint {
    display: block;
    margin-top: 0.25rem;
    color: var(--color-warning, #c97a00);
    font-size: 0.78rem;
  }

  .ssh-passphrase-note {
    display: block;
    margin-top: 0.15rem;
    color: var(--color-muted, #888);
    font-size: 0.72rem;
    font-style: italic;
  }

  .password-row,
  .totp-row {
    display: flex;
    gap: 0.35rem;
  }

  .password-row input,
  .totp-row input {
    flex: 1;
  }

  .two-col {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.6rem;
  }

  .expiry-row {
    display: flex;
    align-items: center;
    gap: 0.3rem;
  }

  .expiry-row input {
    width: 4rem;
  }

  .checkbox-row {
    flex-direction: row;
    align-items: center;
    gap: 0.5rem;
  }

  .editor-error {
    color: #7a1d1d;
    background: #fdecec;
    padding: 0.5rem 0.7rem;
    border-radius: 6px;
    margin: 0;
  }

  .row {
    display: flex;
    gap: 0.5rem;
    justify-content: flex-end;
    margin-top: 0.5rem;
  }

  button {
    cursor: pointer;
    background: #396cd8;
    color: #fff;
    border: 1px solid #396cd8;
    border-radius: 6px;
    padding: 0.5rem 0.9rem;
    font: inherit;
    font-weight: 500;
  }

  button.secondary {
    background: #fff;
    color: #333;
    border-color: #d0d0d0;
  }

  button.small {
    padding: 0.3rem 0.6rem;
    font-size: 0.85rem;
  }

  button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  button:hover:not(:disabled) {
    filter: brightness(0.95);
  }
</style>
