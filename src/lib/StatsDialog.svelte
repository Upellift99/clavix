<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import { api } from "./api";
  import { formatError } from "./format";
  import type { Locale, SshAgentStatus, SyncSummary, ThemePref } from "./types";

  type Props = {
    summary: SyncSummary;
    currentLocale: Locale;
    themePref: ThemePref;
    autoLockMinutes: number;
    onApplyLocale: (loc: Locale) => void;
    onApplyTheme: (pref: ThemePref) => void;
    onApplyAutoLock: (minutes: number) => void;
    onCopySocketPath: (socketPath: string) => void;
  };

  let {
    summary,
    currentLocale,
    themePref,
    autoLockMinutes,
    onApplyLocale,
    onApplyTheme,
    onApplyAutoLock,
    onCopySocketPath,
  }: Props = $props();

  let dialog = $state<HTMLDialogElement | null>(null);
  let sshAgent = $state<SshAgentStatus>({
    running: false,
    socketPath: null,
    keys: [],
    skipped: [],
  });
  let sshAgentBusy = $state(false);
  let sshAgentError = $state<string | null>(null);
  let sshAuthSockEnv = $state<string | null>(null);

  async function refreshSshAgent() {
    try {
      sshAgent = await api.sshAgentStatus();
    } catch (e) {
      console.warn("[clavix] ssh_agent_status failed:", e);
    }
    try {
      sshAuthSockEnv = await api.sshAuthSock();
    } catch (e) {
      console.warn("[clavix] ssh_auth_sock failed:", e);
    }
  }

  // Truncate a SHA256:abcdef… fingerprint for compact display while
  // keeping enough characters to spot the right key at a glance.
  // Full fingerprint is still shown via the title attribute on hover.
  function shortFingerprint(fp: string): string {
    if (fp.length <= 24) return fp;
    return fp.slice(0, 17) + "…" + fp.slice(-4);
  }

  async function toggleSshAgent() {
    sshAgentBusy = true;
    sshAgentError = null;
    try {
      if (sshAgent.running) {
        await api.stopSshAgent();
      } else {
        sshAgent = await api.startSshAgent();
        sshAgentBusy = false;
        return;
      }
      await refreshSshAgent();
    } catch (e) {
      sshAgentError = formatError(e);
    } finally {
      sshAgentBusy = false;
    }
  }

  export async function open() {
    dialog?.showModal();
    await refreshSshAgent();
  }

  function close() {
    dialog?.close();
  }
</script>

<dialog bind:this={dialog} class="stats-dialog">
  {#key currentLocale}
    <header class="stats-header">
      <h2>{m.stats_title()}</h2>
      <button type="button" class="secondary small" onclick={close} aria-label={m.action_close()}>
        ✕
      </button>
    </header>
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

    <h3>{m.settings_title()}</h3>
    <dl>
      <dt>{m.settings_language()}</dt>
      <dd>
        <select
          value={currentLocale}
          onchange={(e) => onApplyLocale((e.currentTarget as HTMLSelectElement).value as Locale)}
        >
          <option value="fr">Français</option>
          <option value="en">English</option>
        </select>
      </dd>
      <dt>{m.settings_theme()}</dt>
      <dd>
        <select
          value={themePref}
          onchange={(e) => onApplyTheme((e.currentTarget as HTMLSelectElement).value as ThemePref)}
        >
          <option value="auto">{m.settings_theme_auto()}</option>
          <option value="dark">{m.settings_theme_dark()}</option>
        </select>
      </dd>
      <dt>{m.stats_auto_lock()}</dt>
      <dd>
        <select
          value={autoLockMinutes}
          onchange={(e) =>
            onApplyAutoLock(parseInt((e.currentTarget as HTMLSelectElement).value, 10))}
        >
          <option value={0}>{m.stats_auto_lock_never()}</option>
          <option value={1}>{m.stats_auto_lock_minutes({ count: "1" })}</option>
          <option value={5}>{m.stats_auto_lock_minutes({ count: "5" })}</option>
          <option value={10}>{m.stats_auto_lock_minutes({ count: "10" })}</option>
          <option value={15}>{m.stats_auto_lock_minutes({ count: "15" })}</option>
          <option value={30}>{m.stats_auto_lock_minutes({ count: "30" })}</option>
          <option value={60}>{m.stats_auto_lock_hour()}</option>
        </select>
      </dd>
    </dl>

    <h3>{m.ssh_agent_title()}</h3>
    <p class="hint ssh-agent-hint">{m.ssh_agent_hint()}</p>
    <div class="ssh-agent-row">
      <button type="button" onclick={toggleSshAgent} disabled={sshAgentBusy}>
        {sshAgent.running ? m.ssh_agent_stop() : m.ssh_agent_start()}
      </button>
      <span class="ssh-agent-state" class:on={sshAgent.running}>
        {sshAgent.running
          ? m.ssh_agent_running({ count: String(sshAgent.keys.length) })
          : m.ssh_agent_stopped()}
      </span>
    </div>
    {#if sshAgent.running && sshAgent.socketPath}
      <div class="ssh-agent-sock">
        <code>{sshAgent.socketPath}</code>
        <button
          type="button"
          class="secondary small"
          onclick={() => onCopySocketPath(sshAgent.socketPath!)}
        >
          {m.ssh_agent_copy_export()}
        </button>
      </div>
      {#if sshAuthSockEnv === sshAgent.socketPath}
        <p class="ssh-agent-env-ok">✓ {m.ssh_agent_env_ok()}</p>
      {:else if sshAuthSockEnv}
        <p class="ssh-agent-env-mismatch">
          {m.ssh_agent_env_mismatch({ current: sshAuthSockEnv })}
        </p>
      {:else}
        <p class="ssh-agent-env-unset">{m.ssh_agent_env_unset()}</p>
      {/if}
    {/if}
    {#if sshAgent.running && sshAgent.keys.length > 0}
      <ul class="ssh-agent-keys">
        {#each sshAgent.keys as key (key.fingerprint)}
          <li class="ssh-agent-key">
            <span class="ssh-agent-key-comment">{key.comment || "—"}</span>
            <span class="ssh-agent-key-algo">{key.algorithm}</span>
            <code class="ssh-agent-key-fp" title={key.fingerprint}>
              {shortFingerprint(key.fingerprint)}
            </code>
          </li>
        {/each}
      </ul>
    {/if}
    {#if sshAgent.skipped.length > 0}
      <details class="ssh-agent-skipped-list">
        <summary>
          {m.ssh_agent_skipped({ count: String(sshAgent.skipped.length) })}
        </summary>
        <ul>
          {#each sshAgent.skipped as sk (sk.name + sk.reason)}
            <li>
              <strong>{sk.name}</strong>
              <span class="ssh-agent-skip-reason">{sk.reason}</span>
            </li>
          {/each}
        </ul>
      </details>
    {/if}
    {#if sshAgentError}
      <p class="audit-error">{sshAgentError}</p>
    {/if}

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
  {/key}
</dialog>
