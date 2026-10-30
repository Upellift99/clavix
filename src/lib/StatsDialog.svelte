<script lang="ts">
  import { openUrl } from "@tauri-apps/plugin-opener";
  import * as m from "#lib/paraglide/messages.js";
  import { api } from "./api";
  import Icon from "./Icon.svelte";
  import type { Locale, SyncSummary, UpdateInfo } from "./types";

  // Read-only facts about the vault and the app: account, counts, type
  // breakdown, version and update check. Everything the user can
  // change lives in PreferencesDialog; this one is only for looking.
  type Props = {
    summary: SyncSummary;
    currentLocale: Locale;
  };

  let { summary, currentLocale }: Props = $props();

  let dialog = $state<HTMLDialogElement | null>(null);
  let version = $state("");
  let checking = $state(false);
  // null = not checked yet this session; otherwise the last verdict.
  let result = $state<UpdateInfo | null>(null);
  let failed = $state(false);
  // null until Rust answers; false in builds without the update-check feature.
  let updateCheck = $state<boolean | null>(null);

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
    if (updateCheck === null) {
      try {
        updateCheck = await api.updateCheckEnabled();
      } catch {
        updateCheck = false;
      }
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

<dialog bind:this={dialog} class="stats-dialog infos-dialog">
  {#key currentLocale}
    <header class="stats-header">
      <h2>{m.infos_title()}</h2>
      <button type="button" class="secondary small" onclick={close} aria-label={m.action_close()}>
        <Icon name="x" size={14} />
      </button>
    </header>

    <h3>{m.infos_section_vault()}</h3>
    <dl>
      <dt>{m.stats_account()}</dt>
      <dd>{summary.name ?? summary.email}</dd>
      <dt>{m.stats_items()}</dt>
      <dd>{summary.itemCount}</dd>
      <dt>{m.stats_folders()}</dt>
      <dd>{summary.folderCount}</dd>
      <dt>{m.stats_collections()}</dt>
      <dd>{summary.collectionCount}</dd>
      <dt>{m.stats_organizations()}</dt>
      <dd>{summary.organizationCount}</dd>
    </dl>

    <h3>{m.stats_breakdown()}</h3>
    <dl>
      <dt>{m.stats_logins()}</dt>
      <dd>{summary.typeCounts.login}</dd>
      <dt>{m.stats_notes()}</dt>
      <dd>{summary.typeCounts.secureNote}</dd>
      <dt>{m.stats_cards()}</dt>
      <dd>{summary.typeCounts.card}</dd>
      <dt>{m.stats_identities()}</dt>
      <dd>{summary.typeCounts.identity}</dd>
      {#if summary.typeCounts.sshKey > 0}
        <dt>{m.stats_ssh_keys()}</dt>
        <dd>{summary.typeCounts.sshKey}</dd>
      {/if}
    </dl>

    <h3>{m.about_title()}</h3>
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

      {#if updateCheck === false}
        <p class="about-status">{m.about_distro_updates()}</p>
      {:else if updateCheck}
        <div class="about-actions">
          <button type="button" class="secondary" onclick={check} disabled={checking}>
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
      {/if}
    </div>
  {/key}
</dialog>

<style>
  .infos-dialog {
    width: min(30rem, calc(100vw - 3rem));
  }

  .about-body {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }

  .about-version {
    font-size: 0.95rem;
    font-weight: 500;
    margin: 0;
  }

  .about-website-row {
    margin: -0.3rem 0 0;
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
