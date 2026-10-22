<script lang="ts">
  import { openUrl } from "@tauri-apps/plugin-opener";
  import * as m from "#lib/paraglide/messages.js";
  import { api } from "./api";
  import Icon from "./Icon.svelte";
  import type { Locale, UpdateInfo } from "./types";

  type Props = {
    currentLocale: Locale;
  };

  let { currentLocale }: Props = $props();

  let dialog = $state<HTMLDialogElement | null>(null);
  let version = $state("");
  let checking = $state(false);
  // null = not checked yet this session; otherwise the last verdict.
  let result = $state<UpdateInfo | null>(null);
  let failed = $state(false);

  async function check() {
    checking = true;
    failed = false;
    result = null;
    try {
      result = await api.checkForUpdate();
    } catch {
      // Offline / rate-limited / GitHub down — a manual check shouldn't error
      // loudly, just report it couldn't reach the server.
      failed = true;
    } finally {
      checking = false;
    }
  }

  export async function open() {
    checking = false;
    result = null;
    failed = false;
    dialog?.showModal();
    try {
      version = await api.appVersion();
    } catch {
      version = "";
    }
  }

  function close() {
    dialog?.close();
  }

  async function openReleasePage() {
    if (result) await openUrl(result.url);
  }

  async function openWebsite() {
    await openUrl("https://clavix.org");
  }
</script>

<dialog bind:this={dialog} class="stats-dialog about-dialog">
  {#key currentLocale}
    <header class="stats-header">
      <h2>{m.about_title()}</h2>
      <button type="button" class="secondary small" onclick={close} aria-label={m.action_close()}>
        ✕
      </button>
    </header>

    <div class="about-body">
      <p class="about-version">{m.about_version({ version: version || "…" })}</p>

      <p class="about-website-row">
        <button
          type="button"
          class="about-link"
          onclick={openWebsite}
          title={m.about_website()}
          aria-label={m.about_website()}
        >
          clavix.org
        </button>
      </p>

      <div class="about-actions">
        <button type="button" onclick={check} disabled={checking}>
          {checking ? m.about_checking() : m.about_check_updates()}
        </button>
        {#if checking}
          <span class="about-spinner" aria-hidden="true"></span>
        {/if}
      </div>

      {#if failed}
        <p class="about-status about-status--warn">{m.about_check_failed()}</p>
      {:else if result?.updateAvailable}
        <div class="about-status about-status--update">
          <span>{m.update_available_body({ version: result.latest, current: result.current })}</span>
          <button type="button" class="primary small" onclick={openReleasePage}>
            <Icon name="download" size={14} />
            {m.update_action_view()}
          </button>
        </div>
      {:else if result}
        <p class="about-status about-status--ok">✔ {m.about_up_to_date()}</p>
      {/if}
    </div>
  {/key}
</dialog>

<style>
  .about-dialog {
    max-width: 24rem;
  }

  .about-body {
    display: flex;
    flex-direction: column;
    gap: 0.85rem;
    margin-top: 0.4rem;
  }

  .about-version {
    font-size: 0.95rem;
    font-weight: 500;
    margin: 0;
  }

  .about-website-row {
    margin: -0.4rem 0 0;
  }

  .about-link {
    background: none;
    border: none;
    padding: 0;
    font: inherit;
    font-size: 0.85rem;
    color: var(--link);
    text-decoration: underline;
    cursor: pointer;
  }

  .about-link:hover {
    color: var(--link-hover);
  }

  .about-actions {
    display: flex;
    align-items: center;
    gap: 0.55rem;
  }

  .about-spinner {
    width: 1.05rem;
    height: 1.05rem;
    border: 2px solid var(--primary-hover-bg);
    border-top-color: var(--primary);
    border-radius: 50%;
    animation: about-spin 0.7s linear infinite;
    flex: none;
  }

  @keyframes about-spin {
    to {
      transform: rotate(360deg);
    }
  }

  .about-status {
    margin: 0;
    font-size: 0.85rem;
  }

  .about-status--ok {
    color: var(--success-text);
  }

  .about-status--warn {
    color: var(--warning-text);
  }

  .about-status--update {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    gap: 0.5rem;
  }
</style>
