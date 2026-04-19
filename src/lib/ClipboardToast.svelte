<script lang="ts">
  import type { ClipboardController } from "./clipboard.svelte";

  type Props = {
    clipboard: ClipboardController;
  };

  let { clipboard }: Props = $props();
</script>

{#if clipboard.secondsLeft !== null}
  <aside class="clipboard-toast" role="status">
    <span>
      Presse-papier ({clipboard.label}) effacé dans {clipboard.secondsLeft}s
    </span>
    <button type="button" class="secondary small" onclick={() => clipboard.clearNow()}>
      Effacer maintenant
    </button>
  </aside>
{/if}

<style>
  .clipboard-toast {
    position: fixed;
    bottom: 1rem;
    left: 50%;
    transform: translateX(-50%);
    background: #1e3a8a;
    color: #fff;
    padding: 0.6rem 1rem;
    border-radius: 8px;
    display: flex;
    align-items: center;
    gap: 0.75rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
    z-index: 1000;
  }

  .clipboard-toast button.secondary {
    background: #fff;
    color: #1e3a8a;
    border-color: #fff;
    cursor: pointer;
    font: inherit;
    border-radius: 6px;
    padding: 0.4rem 0.75rem;
    font-size: 0.9rem;
  }
</style>
