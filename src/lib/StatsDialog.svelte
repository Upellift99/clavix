<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import { api } from "./api";
  import { formatError } from "./format";
  import PasswordInput from "./PasswordInput.svelte";
  import type { SshAgentConfirm } from "./prefs.svelte";
  import type { Locale, SshAgentStatus, SyncSummary, ThemePref } from "./types";

  type Props = {
    summary: SyncSummary;
    currentLocale: Locale;
    themePref: ThemePref;
    autoLockMinutes: number;
    closeToTray: boolean;
    minimizeToTray: boolean;
    hideDockOnTray: boolean;
    requireNarrowing: boolean;
    sshAgentConfirm: SshAgentConfirm;
    onApplyLocale: (loc: Locale) => void;
    onApplyTheme: (pref: ThemePref) => void;
    onApplyAutoLock: (minutes: number) => void;
    onApplyCloseToTray: (value: boolean) => void;
    onApplyMinimizeToTray: (value: boolean) => void;
    onApplyHideDockOnTray: (value: boolean) => void;
    onApplyRequireNarrowing: (value: boolean) => void;
    onApplySshAgentConfirm: (value: SshAgentConfirm) => void;
    onCopySocketPath: (socketPath: string) => void;
  };

  let {
    summary,
    currentLocale,
    themePref,
    autoLockMinutes,
    closeToTray,
    minimizeToTray,
    hideDockOnTray,
    requireNarrowing,
    sshAgentConfirm,
    onApplyLocale,
    onApplyTheme,
    onApplyAutoLock,
    onApplyCloseToTray,
    onApplyMinimizeToTray,
    onApplyHideDockOnTray,
    onApplyRequireNarrowing,
    onApplySshAgentConfirm,
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

  // Yubikey re-unlock enrolment state. The toggle here mutates
  // session.json on disk; the unlock view re-reads it on bootstrap,
  // which is why there's no two-way sync between this dialog and the
  // live `auth` controller. Closing and reopening the app picks up
  // any change made here.
  let yubikeyEnrolled = $state(false);
  let yubikeyEnrollPin = $state("");
  let yubikeyDisenrollPassword = $state("");
  let yubikeyBusy = $state(false);
  let yubikeyError = $state<string | null>(null);
  let yubikeyMessage = $state<string | null>(null);

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

  async function refreshYubikey() {
    try {
      yubikeyEnrolled = (await api.yubikeyUnlockState()).enrolled;
    } catch (e) {
      console.warn("[clavix] yubikey_unlock_state failed:", e);
      yubikeyEnrolled = false;
    }
  }

  async function enrollYubikey() {
    yubikeyBusy = true;
    yubikeyError = null;
    yubikeyMessage = null;
    try {
      const pin = yubikeyEnrollPin.trim();
      await api.enrollYubikeyUnlock(pin.length > 0 ? pin : null);
      yubikeyEnrollPin = "";
      yubikeyMessage = m.yubikey_unlock_enrolled();
      await refreshYubikey();
    } catch (e) {
      yubikeyError = formatError(e);
    } finally {
      yubikeyBusy = false;
    }
  }

  async function disenrollYubikey() {
    if (yubikeyDisenrollPassword.length === 0) return;
    yubikeyBusy = true;
    yubikeyError = null;
    yubikeyMessage = null;
    try {
      await api.disenrollYubikeyUnlock(yubikeyDisenrollPassword);
      yubikeyDisenrollPassword = "";
      await refreshYubikey();
    } catch (e) {
      yubikeyError = formatError(e);
    } finally {
      yubikeyBusy = false;
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
        sshAgent = await api.startSshAgent(sshAgentConfirm);
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

  // Persist the confirmation policy and, if the agent is already running,
  // relaunch it so the change takes effect immediately (the socket path
  // is stable, so SSH_AUTH_SOCK stays valid across the restart).
  async function applyConfirmPolicy(value: SshAgentConfirm) {
    onApplySshAgentConfirm(value);
    if (!sshAgent.running) return;
    sshAgentBusy = true;
    sshAgentError = null;
    try {
      sshAgent = await api.startSshAgent(value);
    } catch (e) {
      sshAgentError = formatError(e);
    } finally {
      sshAgentBusy = false;
    }
  }

  export async function open() {
    dialog?.showModal();
    await refreshSshAgent();
    await refreshYubikey();
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
      <dt>{m.settings_require_narrowing()}</dt>
      <dd>
        <select
          value={requireNarrowing ? "narrow" : "all"}
          onchange={(e) =>
            onApplyRequireNarrowing(
              (e.currentTarget as HTMLSelectElement).value === "narrow",
            )}
        >
          <option value="narrow">{m.settings_require_narrowing_on()}</option>
          <option value="all">{m.settings_require_narrowing_off()}</option>
        </select>
      </dd>
      <dt>{m.settings_close_to_tray()}</dt>
      <dd>
        <select
          value={closeToTray ? "tray" : "quit"}
          onchange={(e) =>
            onApplyCloseToTray(
              (e.currentTarget as HTMLSelectElement).value === "tray",
            )}
        >
          <option value="tray">{m.settings_close_to_tray_tray()}</option>
          <option value="quit">{m.settings_close_to_tray_quit()}</option>
        </select>
      </dd>
      <dt>{m.settings_minimize_to_tray()}</dt>
      <dd>
        <select
          value={minimizeToTray ? "tray" : "taskbar"}
          onchange={(e) =>
            onApplyMinimizeToTray(
              (e.currentTarget as HTMLSelectElement).value === "tray",
            )}
        >
          <option value="tray">{m.settings_minimize_to_tray_tray()}</option>
          <option value="taskbar">{m.settings_minimize_to_tray_taskbar()}</option>
        </select>
      </dd>
      <dt>{m.settings_hide_dock_on_tray()}</dt>
      <dd>
        <select
          value={hideDockOnTray ? "hide" : "keep"}
          onchange={(e) =>
            onApplyHideDockOnTray(
              (e.currentTarget as HTMLSelectElement).value === "hide",
            )}
        >
          <option value="hide">{m.settings_hide_dock_on_tray_on()}</option>
          <option value="keep">{m.settings_hide_dock_on_tray_off()}</option>
        </select>
      </dd>
    </dl>

    <h3>{m.ssh_agent_title()}</h3>
    <p class="hint ssh-agent-hint">{m.ssh_agent_hint()}</p>
    <dl class="ssh-agent-confirm-setting">
      <dt>{m.settings_ssh_confirm()}</dt>
      <dd>
        <select
          value={sshAgentConfirm}
          disabled={sshAgentBusy}
          onchange={(e) =>
            applyConfirmPolicy((e.currentTarget as HTMLSelectElement).value as SshAgentConfirm)}
        >
          <option value="never">{m.settings_ssh_confirm_never()}</option>
          <option value="session">{m.settings_ssh_confirm_session()}</option>
          <option value="always">{m.settings_ssh_confirm_always()}</option>
        </select>
      </dd>
    </dl>
    <div class="ssh-agent-row">
      <button type="button" onclick={toggleSshAgent} disabled={sshAgentBusy}>
        {sshAgent.running ? m.ssh_agent_stop() : m.ssh_agent_start()}
      </button>
      <span class="ssh-agent-state" class:on={sshAgent.running}>
        {sshAgent.running
          ? m.ssh_agent_running({ count: String(sshAgent.keys.length) })
          : m.ssh_agent_stopped()}
      </span>
      {#if sshAgent.running && sshAgent.skipped.length > 0}
        <!-- Say it next to the count itself: the exposed number looking
             short is exactly what sends the user hunting for an answer. -->
        <span class="ssh-agent-skipped-badge">
          {m.ssh_agent_skipped_badge({ count: String(sshAgent.skipped.length) })}
        </span>
      {/if}
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

    <h3>{m.yubikey_unlock_section_title()}</h3>
    <p class="hint">{m.yubikey_unlock_section_hint()}</p>
    <p class="yubikey-warning">{m.yubikey_unlock_warning()}</p>
    {#if yubikeyEnrolled}
      <form
        class="yubikey-disenroll"
        onsubmit={(e) => {
          e.preventDefault();
          disenrollYubikey();
        }}
      >
        <label>
          {m.yubikey_unlock_disenroll_password()}
          <PasswordInput
            bind:value={yubikeyDisenrollPassword}
            autocomplete="off"
            disabled={yubikeyBusy}
            required
          />
          <small class="yubikey-master-note">⚠️ {m.yubikey_unlock_master_not_pin()}</small>
        </label>
        <button
          type="submit"
          class="secondary"
          disabled={yubikeyBusy || yubikeyDisenrollPassword.length === 0}
        >
          {yubikeyBusy ? m.yubikey_unlock_disenrolling() : m.yubikey_unlock_disenroll()}
        </button>
      </form>
    {:else}
      <form
        class="yubikey-enroll"
        onsubmit={(e) => {
          e.preventDefault();
          enrollYubikey();
        }}
      >
        <label>
          {m.yubikey_unlock_pin_label()}
          <PasswordInput
            bind:value={yubikeyEnrollPin}
            autocomplete="off"
            disabled={yubikeyBusy}
            placeholder={m.yubikey_unlock_pin_placeholder()}
          />
        </label>
        <button type="submit" disabled={yubikeyBusy}>
          {yubikeyBusy ? m.yubikey_unlock_enrolling() : m.yubikey_unlock_enroll()}
        </button>
      </form>
    {/if}
    {#if yubikeyMessage}
      <p class="yubikey-message">{yubikeyMessage}</p>
    {/if}
    {#if yubikeyError}
      <p class="audit-error">{yubikeyError}</p>
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
