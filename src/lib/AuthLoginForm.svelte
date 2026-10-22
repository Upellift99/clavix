<script lang="ts">
  import { onMount } from "svelte";
  import * as m from "#lib/paraglide/messages.js";
  import PasswordInput from "./PasswordInput.svelte";

  type Props = {
    serverUrl: string;
    email: string;
    password: string;
    disabled: boolean;
    onSubmit: (event: Event) => void;
  };

  let {
    serverUrl = $bindable(),
    email = $bindable(),
    password = $bindable(),
    disabled,
    onSubmit,
  }: Props = $props();

  // Bitwarden's hosted regions. The backend maps these hosts to the
  // cloud's split api./identity. endpoints (see `resolve_endpoints`);
  // anything else is treated as a self-hosted single-domain server.
  const BW_US = "https://vault.bitwarden.com";
  const BW_EU = "https://vault.bitwarden.eu";

  type Region = "selfhosted" | "us" | "eu";
  let region = $state<Region>(
    serverUrl === BW_US ? "us" : serverUrl === BW_EU ? "eu" : "selfhosted",
  );
  // Remembers the self-hosted URL while a cloud region is selected, so
  // switching back doesn't wipe what the user typed.
  let savedSelfHosted = $state(
    serverUrl === BW_US || serverUrl === BW_EU ? "" : serverUrl,
  );

  function applyRegion(next: Region) {
    if (region === "selfhosted") savedSelfHosted = serverUrl;
    region = next;
    if (next === "us") serverUrl = BW_US;
    else if (next === "eu") serverUrl = BW_EU;
    else serverUrl = savedSelfHosted;
  }

  // First keystroke goes to the first field still missing: a returning
  // user with server and e-mail remembered lands straight on the password.
  let serverInput = $state<HTMLInputElement | null>(null);
  let emailInput = $state<HTMLInputElement | null>(null);
  let passwordField = $state<{ focus: () => void } | null>(null);
  onMount(() => {
    if (region === "selfhosted" && !serverUrl) serverInput?.focus();
    else if (!email) emailInput?.focus();
    else passwordField?.focus();
  });
</script>

<form onsubmit={onSubmit}>
  <label>
    {m.form_region()}
    <select
      value={region}
      {disabled}
      onchange={(e) => applyRegion((e.currentTarget as HTMLSelectElement).value as Region)}
    >
      <option value="selfhosted">{m.region_selfhosted()}</option>
      <option value="us">{m.region_bitwarden_us()}</option>
      <option value="eu">{m.region_bitwarden_eu()}</option>
    </select>
  </label>
  {#if region === "selfhosted"}
    <label>
      {m.form_server()}
      <input type="url" bind:this={serverInput} bind:value={serverUrl} required {disabled} />
    </label>
  {:else}
    <p class="hint region-note">{m.region_cloud_experimental()}</p>
  {/if}
  <label>
    {m.form_email()}
    <input
      type="email"
      bind:this={emailInput}
      bind:value={email}
      placeholder={m.form_email_placeholder()}
      required
      {disabled}
    />
  </label>
  <label>
    {m.form_master_password()}
    <PasswordInput bind:this={passwordField} bind:value={password} required {disabled} />
  </label>
  <button type="submit" {disabled}>
    {disabled ? m.action_signing_in() : m.action_sign_in()}
  </button>
</form>
