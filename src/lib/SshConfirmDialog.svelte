<script lang="ts">
  import { onMount } from "svelte";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";
  import * as m from "$lib/paraglide/messages";
  import { api } from "./api";

  // Mirrors the Rust `ConfirmRequest` emitted on "ssh-agent-confirm".
  type ConfirmReq = {
    id: number;
    comment: string;
    algorithm: string;
    fingerprint: string;
    // Advisory identity of the requesting process — see the Rust
    // `CallerInfo` docs on why this must not drive a trust decision.
    callerName: string | null;
    callerPid: number | null;
  };

  // Client-side auto-deny mirrors the backend's 30 s timeout so a prompt
  // nobody answers doesn't linger with buttons that no longer do anything.
  const TIMEOUT_MS = 30_000;

  let dialog = $state<HTMLDialogElement | null>(null);
  let current = $state<ConfirmReq | null>(null);
  // Signatures can arrive in parallel (e.g. `git` opening several
  // connections); queue extras and show them one at a time.
  let queue = $state<ConfirmReq[]>([]);
  let timer: ReturnType<typeof setTimeout> | null = null;

  onMount(() => {
    let unlisten: UnlistenFn | null = null;
    listen<ConfirmReq>("ssh-agent-confirm", (event) => {
      if (current) queue.push(event.payload);
      else show(event.payload);
    }).then((un) => (unlisten = un));
    return () => unlisten?.();
  });

  function show(req: ConfirmReq) {
    current = req;
    dialog?.showModal();
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => respond(false), TIMEOUT_MS);
  }

  async function respond(approved: boolean) {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
    const req = current;
    current = null; // clear first so the `close` handler is a no-op
    dialog?.close();
    if (req) {
      try {
        await api.respondSshAgentConfirm(req.id, approved);
      } catch {
        // best-effort — the backend denies on timeout anyway
      }
    }
    const next = queue.shift();
    if (next) show(next);
  }

  // "git (pid 4321)" / "pid 4321" when the name is unavailable (macOS has
  // no /proc) / null when the peer couldn't be identified at all.
  const callerLabel = $derived.by(() => {
    if (!current) return null;
    const { callerName, callerPid } = current;
    if (callerName && callerPid !== null)
      return m.ssh_confirm_caller_named({ name: callerName, pid: String(callerPid) });
    if (callerPid !== null) return m.ssh_confirm_caller_pid({ pid: String(callerPid) });
    return null;
  });
</script>

<dialog
  bind:this={dialog}
  class="ssh-confirm-dialog"
  onclose={() => {
    // Reached via Esc / backdrop: treat an unanswered close as a denial.
    if (current) respond(false);
  }}
>
  {#if current}
    <h2>{m.ssh_confirm_title()}</h2>
    <p class="ssh-confirm-body">{m.ssh_confirm_body()}</p>
    <dl class="ssh-confirm-key">
      <dt>{m.ssh_confirm_key_label()}</dt>
      <dd>
        {current.comment || "—"}
        <span class="ssh-confirm-algo">{current.algorithm}</span>
      </dd>
      <dt>{m.ssh_confirm_fingerprint()}</dt>
      <!-- Full value: this is the prompt where the fingerprint matters
           most — approving a signature means recognising the key, and a
           truncated fingerprint can't be compared against `ssh-add -l`
           or the one shown by the server. `code` already carries
           `word-break: break-all`, so a narrow window wraps it rather
           than overflowing. -->
      <dd><code title={current.fingerprint}>{current.fingerprint}</code></dd>
      <dt>{m.ssh_confirm_caller_label()}</dt>
      <dd>
        {#if callerLabel}
          {callerLabel}
        {:else}
          <span class="ssh-confirm-caller-unknown">{m.ssh_confirm_caller_unknown()}</span>
        {/if}
      </dd>
    </dl>
    <p class="ssh-confirm-caller-hint">{m.ssh_confirm_caller_hint()}</p>
    <div class="ssh-confirm-actions">
      <button type="button" class="secondary" onclick={() => respond(false)}>
        {m.ssh_confirm_deny()}
      </button>
      <button type="button" onclick={() => respond(true)}>
        {m.ssh_confirm_allow()}
      </button>
    </div>
  {/if}
</dialog>

<style>
  .ssh-confirm-dialog {
    /* 26rem left the fingerprint field about 276px against the ~386px a
       full SHA256 fingerprint needs, which is why it used to be
       truncated. Widened to fit it on one line; the `min` keeps the
       dialog inside a narrow viewport. */
    max-width: min(35rem, calc(100vw - 2rem));
    border: none;
    border-radius: 10px;
    padding: 1.25rem 1.4rem;
  }
  .ssh-confirm-dialog::backdrop {
    background: rgba(0, 0, 0, 0.45);
  }
  .ssh-confirm-dialog h2 {
    margin: 0 0 0.5rem;
    font-size: 1.15rem;
  }
  .ssh-confirm-body {
    margin: 0 0 0.85rem;
    color: #555;
    font-size: 0.9rem;
  }
  .ssh-confirm-key {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 0.25rem 0.75rem;
    margin: 0 0 1rem;
    font-size: 0.9rem;
  }
  .ssh-confirm-key dt {
    color: #777;
  }
  .ssh-confirm-key dd {
    margin: 0;
    word-break: break-all;
  }
  .ssh-confirm-algo {
    color: #777;
    font-size: 0.85em;
  }
  .ssh-confirm-caller-unknown {
    color: #777;
    font-style: italic;
  }
  .ssh-confirm-caller-hint {
    margin: -0.5rem 0 1rem;
    color: #777;
    font-size: 0.8rem;
  }
  .ssh-confirm-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.6rem;
  }

  @media (prefers-color-scheme: dark) {
    .ssh-confirm-body,
    .ssh-confirm-key dt,
    .ssh-confirm-algo,
    .ssh-confirm-caller-unknown,
    .ssh-confirm-caller-hint {
      color: #aaa;
    }
  }
  :global(:root.force-dark) .ssh-confirm-body,
  :global(:root.force-dark) .ssh-confirm-key dt,
  :global(:root.force-dark) .ssh-confirm-algo,
  :global(:root.force-dark) .ssh-confirm-caller-unknown,
  :global(:root.force-dark) .ssh-confirm-caller-hint {
    color: #aaa;
  }
</style>
