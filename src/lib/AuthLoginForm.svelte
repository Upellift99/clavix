<script lang="ts">
  import * as m from "$lib/paraglide/messages";

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
</script>

<form onsubmit={onSubmit}>
  <label>
    {m.form_server()}
    <input type="url" bind:value={serverUrl} required {disabled} />
  </label>
  <label>
    {m.form_email()}
    <input
      type="email"
      bind:value={email}
      placeholder={m.form_email_placeholder()}
      required
      {disabled}
    />
  </label>
  <label>
    {m.form_master_password()}
    <input type="password" bind:value={password} required {disabled} />
  </label>
  <button type="submit" {disabled}>
    {disabled ? m.action_signing_in() : m.action_sign_in()}
  </button>
</form>
