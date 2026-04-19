<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import type { StoredAccount } from "./types";

  type Props = {
    account: StoredAccount | null;
    password: string;
    disabled: boolean;
    onSubmit: (event: Event) => void;
    onSwitchAccount: () => void;
  };

  let {
    account,
    password = $bindable(),
    disabled,
    onSubmit,
    onSwitchAccount,
  }: Props = $props();
</script>

<section class="box">
  <h2>{m.unlock_title()}</h2>
  <p class="hint">
    {account?.email} — {account?.serverUrl}
  </p>
  <form onsubmit={onSubmit}>
    <label>
      {m.form_master_password()}
      <input type="password" bind:value={password} required {disabled} />
    </label>
    <div class="row">
      <button type="button" class="secondary" onclick={onSwitchAccount}>{m.action_logout()}</button>
      <button type="submit" {disabled}>
        {disabled ? m.action_unlocking() : m.action_unlock()}
      </button>
    </div>
  </form>
</section>
