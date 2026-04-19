<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import { formatExpiry, truncate } from "./format";
  import type { TokenSet } from "./types";

  type Props = {
    tokens: TokenSet;
    syncing: boolean;
    hasSync: boolean;
    onSync: () => void;
    onLock: () => void;
    onSwitchAccount: () => void;
  };

  let { tokens, syncing, hasSync, onSync, onLock, onSwitchAccount }: Props = $props();
</script>

<section class="box">
  <h2>Session active</h2>
  <dl>
    <dt>access_token</dt>
    <dd><code>{truncate(tokens.access_token)}</code></dd>
    <dt>expires_in</dt>
    <dd>{formatExpiry(tokens.expires_in)}</dd>
  </dl>
  <div class="row">
    <button type="button" class="secondary" onclick={onSwitchAccount}>{m.action_logout()}</button>
    <button type="button" class="secondary" onclick={onLock}>{m.action_lock()}</button>
    <button type="button" onclick={onSync} disabled={syncing}>
      {syncing ? m.action_syncing() : hasSync ? m.action_resync() : m.action_sync()}
    </button>
  </div>
</section>
