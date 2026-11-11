<script lang="ts">
  import { topLayer } from "#lib/top-layer.ts";
  import { matchSuggestions } from "#lib/suggest.ts";

  // A text input with its own suggestion list. It replaces a native
  // <datalist>: WebKitGTK draws that one as an unthemed GTK popup that
  // stretches from the input to the window's right edge and lists every
  // match, covering half the editor. This is the same ARIA combobox
  // pattern, drawn as one of the app's menus (DESIGN.md, Menus and
  // Popovers) and capped to a short list.
  let {
    value = $bindable(""),
    suggestions,
  }: {
    value: string;
    suggestions: string[];
  } = $props();

  const uid = $props.id();
  const listId = `${uid}-suggestions`;

  let inputEl = $state<HTMLInputElement | null>(null);
  let open = $state(false);
  let active = $state(-1);
  let pos = $state({ left: 0, top: 0, width: 0, maxHeight: 0, above: false });

  const matches = $derived(open ? matchSuggestions(suggestions, value) : []);
  const shown = $derived(open && matches.length > 0);

  // Tallest the list gets (about seven rows) before it scrolls.
  const ROOM = 220;
  // One item (0.4rem padding twice + a 0.85rem line) and the list's own
  // padding and border, to know how tall the current matches will be.
  const ROW = 32;
  const CHROME = 10;
  const GAP = 4;

  function place() {
    if (!inputEl) return;
    const r = inputEl.getBoundingClientRect();
    const below = window.innerHeight - r.bottom - GAP - 8;
    const above = r.top - GAP - 8;
    // Flip above only when what is listed does not fit below: a short
    // list stays under the field instead of covering the fields above.
    const needed = Math.min(ROOM, matches.length * ROW + CHROME);
    const flip = below < needed && above > below;
    pos = {
      left: r.left,
      top: flip ? r.top - GAP : r.bottom + GAP,
      width: r.width,
      maxHeight: Math.max(0, Math.min(ROOM, flip ? above : below)),
      above: flip,
    };
  }

  function show() {
    open = true;
    active = -1;
    place();
  }

  function hide() {
    open = false;
    active = -1;
  }

  function pick(s: string) {
    // The bound value is the editor's state, so its dirty tracking sees
    // this like a typed change; no synthetic input event needed.
    value = s;
    hide();
  }

  function onKeydown(e: KeyboardEvent) {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (!shown) {
        show();
        return;
      }
      const n = matches.length;
      active = e.key === "ArrowDown" ? (active + 1) % n : (active - 1 + n) % n;
    } else if (e.key === "Enter" && shown && active >= 0) {
      // Take the highlighted suggestion instead of submitting the form.
      e.preventDefault();
      pick(matches[active]);
    } else if (e.key === "Escape" && shown) {
      // Close the list only; the editor must not read this Escape as
      // "leave the form".
      e.preventDefault();
      e.stopPropagation();
      hide();
    } else if (e.key === "Tab") {
      hide();
    }
  }

  $effect(() => {
    if (!shown) return;
    // The editor scrolls and the window resizes: keep the list glued to
    // the input. Capture catches the form's own scroll container.
    const follow = () => place();
    window.addEventListener("scroll", follow, true);
    window.addEventListener("resize", follow);
    return () => {
      window.removeEventListener("scroll", follow, true);
      window.removeEventListener("resize", follow);
    };
  });

  // A highlighted item scrolled out of view comes back into it.
  $effect(() => {
    if (active < 0) return;
    document.getElementById(`${listId}-${active}`)?.scrollIntoView?.({ block: "nearest" });
  });
</script>

<input
  bind:this={inputEl}
  type="text"
  bind:value
  autocomplete="off"
  role="combobox"
  aria-autocomplete="list"
  aria-expanded={shown}
  aria-controls={shown ? listId : undefined}
  aria-activedescendant={shown && active >= 0 ? `${listId}-${active}` : undefined}
  oninput={() => {
    if (!open) show();
    else {
      active = -1;
      place();
    }
  }}
  onkeydown={onKeydown}
  onblur={hide}
/>

{#if shown}
  <ul
    id={listId}
    class="suggest-list"
    class:above={pos.above}
    role="listbox"
    use:topLayer
    style="left: {pos.left}px; top: {pos.top}px; width: {pos.width}px; max-height: {pos.maxHeight}px;"
  >
    {#each matches as s, i (s)}
      <!-- Pointer only: keyboard selection goes through the input's
           arrow keys (aria-activedescendant), focus never leaves it. -->
      <!-- svelte-ignore a11y_click_events_have_key_events -->
      <li
        id="{listId}-{i}"
        role="option"
        aria-selected={i === active}
        class:active={i === active}
        onmousedown={(e) => e.preventDefault()}
        onclick={() => pick(s)}
      >
        {s}
      </li>
    {/each}
  </ul>
{/if}

<style>
  .suggest-list {
    position: fixed;
    /* Shown as a popover (see lib/top-layer.ts): undo the UA popover
       box so the inline left/top place it under the input. */
    inset: auto;
    margin: 0;
    color: var(--text);
    font-family: var(--font-data);
    z-index: 51;
    box-sizing: border-box;
    list-style: none;
    overflow-y: auto;
    background: var(--surface-raised);
    border: 1px solid var(--border-input);
    border-radius: 6px;
    box-shadow: var(--shadow-menu);
    padding: 0.25rem;
    font-size: 0.85rem;
  }

  .suggest-list.above {
    transform: translateY(-100%);
  }

  li {
    padding: 0.4rem 0.6rem;
    border-radius: 4px;
    cursor: pointer;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  li:hover,
  li.active {
    background: var(--hover-soft);
  }
</style>
