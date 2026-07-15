<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import Icon from "./Icon.svelte";

  // A password field with a reveal toggle sitting inside its right edge.
  // Typing a master password blind is exactly where a typo costs the most
  // (a failed unlock says nothing about *why*), so every password entry
  // point in the app goes through this rather than a bare <input>.
  let {
    value = $bindable(),
    required = false,
    disabled = false,
    autocomplete = "current-password",
    id = undefined,
  }: {
    value: string;
    required?: boolean;
    disabled?: boolean;
    autocomplete?: AutoFill;
    id?: string;
  } = $props();

  let revealed = $state(false);
</script>

<div class="password-input">
  <input
    {id}
    type={revealed ? "text" : "password"}
    bind:value
    {required}
    {disabled}
    {autocomplete}
  />
  <button
    type="button"
    class="reveal"
    onclick={() => (revealed = !revealed)}
    disabled={disabled}
    title={revealed ? m.action_hide() : m.action_show()}
    aria-label={revealed ? m.action_hide() : m.action_show()}
    aria-pressed={revealed}
    tabindex="-1"
  >
    <Icon name={revealed ? "eye-off" : "eye"} size={16} />
  </button>
</div>

<style>
  .password-input {
    position: relative;
    display: block;
  }

  .password-input input {
    width: 100%;
    /* Room for the button so a long password never slides under it. */
    padding-right: 2.4rem;
  }

  /* Fixed square, vertically centred, sitting comfortably inside the
     field's right edge. The button used to inherit the tall auth-screen
     `button` padding, which stretched its hover box past the input's
     rounded corner — that overhang is the "débordement" reported on the
     unlock screen. Explicit dimensions + padding:0 pin it inside. */
  .reveal {
    position: absolute;
    top: 50%;
    right: 0.5rem;
    transform: translateY(-50%);
    display: flex;
    align-items: center;
    justify-content: center;
    width: 1.6rem;
    height: 1.6rem;
    padding: 0;
    border: none;
    background: none;
    color: #666;
    cursor: pointer;
    border-radius: 4px;
  }

  .reveal:hover:not(:disabled) {
    color: #163b8a;
    background: #eef3ff;
  }

  .reveal:disabled {
    cursor: default;
    opacity: 0.5;
  }
</style>
