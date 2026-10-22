<script lang="ts">
  import * as m from "#lib/paraglide/messages.js";
  import { tick } from "svelte";
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
    autofocus = false,
    id = undefined,
    placeholder = undefined,
    ariaLabel = undefined,
    onEnter = undefined,
  }: {
    value: string;
    required?: boolean;
    disabled?: boolean;
    autocomplete?: AutoFill | "off";
    /** Take focus as soon as the field is mounted. */
    autofocus?: boolean;
    id?: string;
    placeholder?: string;
    ariaLabel?: string;
    /** Called when Enter is pressed in the field. Lets a field that is
     *  not inside a <form> (e.g. the Yubikey PIN) trigger its action on
     *  Enter without giving up the reveal toggle. */
    onEnter?: () => void;
  } = $props();

  let revealed = $state(false);
  let input = $state<HTMLInputElement | null>(null);

  /** Move focus into the field (used after a failed attempt). */
  export function focus() {
    input?.focus();
  }

  $effect(() => {
    if (autofocus) void tick().then(() => input?.focus());
  });
</script>

<div class="password-input">
  <input
    {id}
    bind:this={input}
    type={revealed ? "text" : "password"}
    bind:value
    {required}
    {disabled}
    {autocomplete}
    {placeholder}
    aria-label={ariaLabel}
    onkeydown={(event) => {
      if (event.key === "Enter" && onEnter && !disabled) {
        event.preventDefault();
        onEnter();
      }
    }}
  />
  <button
    type="button"
    class="reveal"
    onclick={() => (revealed = !revealed)}
    disabled={disabled}
    title={revealed ? m.action_hide() : m.action_show()}
    aria-label={revealed ? m.action_hide() : m.action_show()}
    aria-pressed={revealed}
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
    /* border-box is the real fix for the "débordement": there is no global
       box-sizing reset, so a bare input defaults to content-box. With
       content-box, `width: 100%` sizes the *content* to the container and
       `padding-right` is then added on top, pushing the field ~2.4rem past
       its siblings (which the flex column stretches by border box). Pin it
       to border-box so width includes the padding and the field lines up. */
    box-sizing: border-box;
    /* Room for the button so a long password never slides under it. */
    padding-right: 2.4rem;
  }

  /* Fixed square, vertically centred, sitting comfortably inside the
     field's right edge. Explicit dimensions + padding:0 keep the reveal
     button from inheriting the tall auth-screen `button` padding, whose
     hover box would otherwise overhang the input's rounded corner. */
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

  .reveal:hover:not(:disabled),
  .reveal:focus-visible {
    color: #163b8a;
    background: #eef3ff;
  }

  .reveal:focus-visible {
    outline: 2px solid #396cd8;
    outline-offset: 1px;
  }

  .reveal:disabled {
    cursor: default;
    opacity: 0.5;
  }
</style>
