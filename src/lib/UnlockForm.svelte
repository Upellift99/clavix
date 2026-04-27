<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import type { StoredAccount } from "./types";

  type Props = {
    account: StoredAccount | null;
    password: string;
    disabled: boolean;
    yubikeyAvailable: boolean;
    yubikeyBusy: boolean;
    yubikeyPin: string;
    onSubmit: (event: Event) => void;
    onYubikey: () => void;
    onSwitchAccount: () => void;
  };

  let {
    account,
    password = $bindable(),
    disabled,
    yubikeyAvailable,
    yubikeyBusy,
    yubikeyPin = $bindable(),
    onSubmit,
    onYubikey,
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

  {#if yubikeyAvailable}
    <div class="yubikey-unlock">
      <p class="hint">{m.yubikey_unlock_or()}</p>
      <label class="yubikey-pin-label">
        {m.yubikey_unlock_pin_label()}
        <input
          type="password"
          bind:value={yubikeyPin}
          autocomplete="off"
          disabled={yubikeyBusy || disabled}
          placeholder={m.yubikey_unlock_pin_placeholder()}
        />
      </label>
      <button
        type="button"
        class="yubikey-unlock-button"
        onclick={onYubikey}
        disabled={yubikeyBusy || disabled}
      >
        {yubikeyBusy ? m.yubikey_unlock_touching() : m.yubikey_unlock_touch()}
      </button>
    </div>
  {/if}
</section>

<style>
  .yubikey-unlock {
    margin-top: 1.25rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border-subtle, rgba(127, 127, 127, 0.25));
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .yubikey-pin-label {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
    font-size: 0.9em;
  }
  .yubikey-unlock-button {
    align-self: flex-end;
  }
</style>
