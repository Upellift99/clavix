<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import { generatePassword, buildCharset } from "./generator";
  import type { Locale } from "./types";

  type Props = {
    currentLocale: Locale;
    onCopy: (value: string) => void;
    /** When set, the dialog offers "Use this password" and hands the
        result back — this is how the item editor reaches the same
        options instead of carrying a generator of its own. */
    onUse?: (value: string) => void;
  };

  let { currentLocale, onCopy, onUse }: Props = $props();

  let dialog = $state<HTMLDialogElement | null>(null);
  let length = $state(20);
  let upper = $state(true);
  let lower = $state(true);
  let digits = $state(true);
  let symbols = $state(true);
  let avoidAmbiguous = $state(true);
  let output = $state("");
  let error = $state<string | null>(null);

  function regenerate() {
    const charset = buildCharset({ upper, lower, digits, symbols, avoidAmbiguous });
    if (charset.length === 0) {
      output = "";
      error = m.generator_empty_charset();
      return;
    }
    error = null;
    output = generatePassword({ length, upper, lower, digits, symbols, avoidAmbiguous });
  }

  export function open() {
    // Always a fresh password when opened from the editor: the previous
    // one has, by then, usually been used somewhere.
    if (!output || onUse) regenerate();
    dialog?.showModal();
  }

  function close() {
    dialog?.close();
  }

  // Same character-class colouring as the item detail view (global
  // `.password .ch-*` styles): digits blue, symbols red, letters default,
  // in a monospace face so `1`/`l` and `0`/`O` are distinguishable.
  function charClass(ch: string): string {
    if (/\d/.test(ch)) return "ch-digit";
    if (/[a-zA-Z]/.test(ch)) return "ch-letter";
    return "ch-symbol";
  }
</script>

<dialog bind:this={dialog} class="stats-dialog">
  {#key currentLocale}
    <header class="stats-header">
      <h2>{m.generator_title()}</h2>
      <button type="button" class="secondary small" onclick={close} aria-label={m.action_close()}>
        ✕
      </button>
    </header>

    <div class="generator-output">
      {#if output}
        <code class="password">{#each [...output] as ch, i (i)}<span class={charClass(ch)}>{ch}</span>{/each}</code>
      {:else}
        <code>—</code>
      {/if}
    </div>
    {#if error}
      <p class="hint error-text">{error}</p>
    {/if}

    <label class="generator-slider">
      {m.generator_length({ count: String(length) })}
      <input type="range" min="6" max="64" bind:value={length} oninput={regenerate} />
    </label>

    <label class="generator-check">
      <input type="checkbox" bind:checked={upper} onchange={regenerate} />
      {m.generator_upper()}
    </label>
    <label class="generator-check">
      <input type="checkbox" bind:checked={lower} onchange={regenerate} />
      {m.generator_lower()}
    </label>
    <label class="generator-check">
      <input type="checkbox" bind:checked={digits} onchange={regenerate} />
      {m.generator_numbers()}
    </label>
    <label class="generator-check">
      <input type="checkbox" bind:checked={symbols} onchange={regenerate} />
      {m.generator_symbols()}
    </label>
    <label class="generator-check">
      <input type="checkbox" bind:checked={avoidAmbiguous} onchange={regenerate} />
      {m.generator_avoid_ambiguous()}
    </label>

    <div class="row" style:margin-top="0.75rem">
      <button type="button" class="secondary" onclick={regenerate}>
        {m.generator_regenerate()}
      </button>
      <button
        type="button"
        class={onUse ? "secondary" : undefined}
        onclick={() => output && onCopy(output)}
        disabled={!output}
      >
        {m.action_copy()}
      </button>
      {#if onUse}
        <button
          type="button"
          onclick={() => {
            if (!output) return;
            onUse(output);
            close();
          }}
          disabled={!output}
        >
          {m.generator_use()}
        </button>
      {/if}
    </div>
  {/key}
</dialog>
