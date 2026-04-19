<script lang="ts">
  import * as m from "$lib/paraglide/messages";

  type FolderSummary = { id: string; name: string };

  type Initial = {
    id: string | null;
    name: string;
    folderId: string | null;
    favorite: boolean;
    notes: string;
    username: string;
    password: string;
    uris: string[];
    totp: string;
  };

  let {
    open,
    mode,
    initial,
    folders,
    onCancel,
    onSubmit,
  }: {
    open: boolean;
    mode: "create" | "edit";
    initial: Initial;
    folders: FolderSummary[];
    onCancel: () => void;
    onSubmit: (input: {
      name: string;
      folderId: string | null;
      favorite: boolean;
      notes: string;
      username: string;
      password: string;
      uris: string[];
      totp: string;
    }) => Promise<void>;
  } = $props();

  let name = $state("");
  let folderId = $state<string | null>(null);
  let favorite = $state(false);
  let notes = $state("");
  let username = $state("");
  let password = $state("");
  let urisInput = $state("");
  let totp = $state("");
  let showPassword = $state(false);
  let submitting = $state(false);
  let error = $state<string | null>(null);

  $effect(() => {
    if (open) {
      name = initial.name;
      folderId = initial.folderId;
      favorite = initial.favorite;
      notes = initial.notes;
      username = initial.username;
      password = initial.password;
      urisInput = initial.uris.join("\n");
      totp = initial.totp;
      showPassword = false;
      submitting = false;
      error = null;
    }
  });

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
      const uris = urisInput
        .split(/\r?\n/)
        .map((u) => u.trim())
        .filter((u) => u.length > 0);
      await onSubmit({
        name: name.trim(),
        folderId: folderId || null,
        favorite,
        notes,
        username,
        password,
        uris,
        totp,
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
          {mode === "create" ? m.editor_create_title() : m.editor_edit_title()}
        </h2>
        <button type="button" class="secondary small" onclick={onCancel} aria-label={m.action_close()}>
          ✕
        </button>
      </header>

      <form onsubmit={handleSubmit}>
        <label>
          {m.editor_name()}
          <input type="text" bind:value={name} required />
        </label>

        <label>
          {m.editor_folder()}
          <select bind:value={folderId}>
            <option value={null}>{m.editor_no_folder()}</option>
            {#each folders as f (f.id)}
              <option value={f.id}>{f.name}</option>
            {/each}
          </select>
        </label>

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
          <input type="text" bind:value={totp} autocomplete="off" placeholder="otpauth://…" />
        </label>

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
    width: min(520px, 94vw);
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
    gap: 0.75rem;
    background: none;
    padding: 0;
    box-shadow: none;
  }

  label {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
    font-size: 0.88rem;
    color: #333;
  }

  input[type="text"],
  input[type="password"],
  select,
  textarea {
    font: inherit;
    padding: 0.5rem 0.7rem;
    border-radius: 6px;
    border: 1px solid #d0d0d0;
    background: #fff;
  }

  textarea {
    resize: vertical;
    font-family: inherit;
  }

  .password-row {
    display: flex;
    gap: 0.35rem;
  }

  .password-row input {
    flex: 1;
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
