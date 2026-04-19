<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import { api } from "./api";
  import { formatError } from "./format";
  import type { AuditResult, Locale } from "./types";

  type Props = {
    currentLocale: Locale;
    onJumpToCipher: (id: string) => void;
  };

  let { currentLocale, onJumpToCipher }: Props = $props();

  let dialog = $state<HTMLDialogElement | null>(null);
  let loading = $state(false);
  let result = $state<AuditResult | null>(null);
  let error = $state<string | null>(null);

  async function run() {
    error = null;
    result = null;
    loading = true;
    try {
      result = await api.auditVaultPasswords();
    } catch (e) {
      error = formatError(e);
    } finally {
      loading = false;
    }
  }

  export async function open() {
    dialog?.showModal();
    await run();
  }

  function close() {
    dialog?.close();
  }

  function jump(id: string) {
    dialog?.close();
    onJumpToCipher(id);
  }

  const numberLocale = $derived(currentLocale === "fr" ? "fr-FR" : "en-US");
</script>

<dialog bind:this={dialog} class="stats-dialog">
  {#key currentLocale}
    <header class="stats-header">
      <h2>🛡 {m.audit_title()}</h2>
      <button type="button" class="secondary small" onclick={close} aria-label={m.action_close()}>
        ✕
      </button>
    </header>
    <p class="hint audit-privacy">{m.audit_privacy_note()}</p>

    {#if loading}
      <p>{m.audit_running()}</p>
    {:else if error}
      <p class="audit-error">{error}</p>
      <div class="row">
        <button type="button" onclick={run}>{m.action_retry()}</button>
      </div>
    {:else if result}
      <p>{m.audit_checked({ count: String(result.checked) })}</p>

      <h3 class="audit-h3">{m.audit_section_pwned()}</h3>
      {#if result.pwned.length === 0}
        <p class="audit-success">✔ {m.audit_no_pwned()}</p>
      {:else}
        <p class="audit-warning">⚠ {m.audit_pwned_count({ count: String(result.pwned.length) })}</p>
        <ul class="audit-list">
          {#each result.pwned as entry (entry.cipherId)}
            <li>
              <button type="button" class="link-button" onclick={() => jump(entry.cipherId)}>
                {entry.name}
              </button>
              <span class="audit-count">
                {m.audit_seen_n_times({ count: entry.count.toLocaleString(numberLocale) })}
              </span>
            </li>
          {/each}
        </ul>
      {/if}

      <h3 class="audit-h3">{m.audit_section_reused()}</h3>
      {#if result.reused.length === 0}
        <p class="audit-success">✔ {m.audit_no_reused()}</p>
      {:else}
        <p class="audit-warning">⚠ {m.audit_reused_count({ count: String(result.reused.length) })}</p>
        <ul class="audit-list">
          {#each result.reused as group, i (i)}
            <li class="audit-group">
              <span class="audit-count">
                {m.audit_reused_shared({ count: String(group.cipherIds.length) })}
              </span>
              <span class="audit-group-items">
                {#each group.cipherIds as cid, j (cid)}
                  <button type="button" class="link-button" onclick={() => jump(cid)}>
                    {group.names[j]}
                  </button>{#if j < group.cipherIds.length - 1}, {/if}
                {/each}
              </span>
            </li>
          {/each}
        </ul>
      {/if}

      <h3 class="audit-h3">{m.audit_section_weak()}</h3>
      {#if result.weak.length === 0}
        <p class="audit-success">✔ {m.audit_no_weak()}</p>
      {:else}
        <p class="audit-warning">⚠ {m.audit_weak_count({ count: String(result.weak.length) })}</p>
        <ul class="audit-list">
          {#each result.weak as entry (entry.cipherId)}
            <li>
              <button type="button" class="link-button" onclick={() => jump(entry.cipherId)}>
                {entry.name}
              </button>
              <span class="audit-count">{m.audit_weak_score({ score: String(entry.score) })}</span>
            </li>
          {/each}
        </ul>
      {/if}
    {/if}
  {/key}
</dialog>
