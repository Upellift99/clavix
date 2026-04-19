<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import { providerLabel } from "./format";

  const TOTP_PATTERN = "[0-9]{6}";
  const YUBIKEY_OTP_LENGTH = 44;

  type Props = {
    providers: number[];
    selectedProvider: number;
    totpCode: string;
    yubikeyOtp: string;
    onSubmit: (event: Event) => void;
    onCancel: () => void;
  };

  let {
    providers,
    selectedProvider = $bindable(),
    totpCode = $bindable(),
    yubikeyOtp = $bindable(),
    onSubmit,
    onCancel,
  }: Props = $props();

  const supportedProviders = $derived(providers.filter((p) => p === 0 || p === 3));

  function onYubikeyInput(event: Event) {
    const input = event.currentTarget as HTMLInputElement;
    const value = input.value.trim().toLowerCase();
    yubikeyOtp = value;
    if (value.length === YUBIKEY_OTP_LENGTH) {
      input.form?.requestSubmit();
    }
  }
</script>

<section class="box">
  <h2>{m.two_factor_title()}</h2>
  <p class="hint">
    {m.two_factor_providers({ providers: providers.map(providerLabel).join(", ") })}
  </p>
  <form onsubmit={onSubmit}>
    {#if supportedProviders.length > 1}
      <label>
        {m.two_factor_method_label()}
        <select bind:value={selectedProvider}>
          {#each supportedProviders as p}
            <option value={p}>{providerLabel(p)}</option>
          {/each}
        </select>
      </label>
    {/if}

    {#if selectedProvider === 0}
      <label>
        {m.two_factor_code_label()}
        <input
          type="text"
          bind:value={totpCode}
          inputmode="numeric"
          pattern={TOTP_PATTERN}
          maxlength="6"
          autocomplete="one-time-code"
          required
        />
      </label>
    {:else if selectedProvider === 3}
      <label>
        {m.two_factor_yubikey_label()}
        <input
          type="text"
          value={yubikeyOtp}
          oninput={onYubikeyInput}
          inputmode="text"
          maxlength={YUBIKEY_OTP_LENGTH}
          autocomplete="off"
          spellcheck="false"
          required
        />
      </label>
      <p class="hint">{m.two_factor_yubikey_help()}</p>
    {:else}
      <p class="hint">
        {m.two_factor_unsupported({ provider: providerLabel(selectedProvider) })}
      </p>
    {/if}

    <div class="row">
      <button type="button" class="secondary" onclick={onCancel}>{m.action_cancel()}</button>
      <button type="submit" disabled={selectedProvider !== 0 && selectedProvider !== 3}>
        {m.action_submit()}
      </button>
    </div>
  </form>
</section>
