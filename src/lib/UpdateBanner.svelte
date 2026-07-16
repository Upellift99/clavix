<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import Icon from "./Icon.svelte";
  import type { UpdateInfo } from "./types";

  type Props = {
    info: UpdateInfo;
    onView: () => void;
    onDismiss: () => void;
  };

  let { info, onView, onDismiss }: Props = $props();
</script>

<div class="update-banner" role="status">
  <span class="update-icon"><Icon name="download" size={16} /></span>
  <div class="update-text">
    <strong>{m.update_available_title()}</strong>
    <span>{m.update_available_body({ version: info.latest, current: info.current })}</span>
  </div>
  <div class="update-actions">
    <button type="button" class="primary small" onclick={onView}>
      {m.update_action_view()}
    </button>
    <button
      type="button"
      class="icon-btn"
      title={m.update_action_dismiss()}
      aria-label={m.update_action_dismiss()}
      onclick={onDismiss}
    >
      <Icon name="x" size={16} />
    </button>
  </div>
</div>

<style>
  .update-banner {
    display: flex;
    align-items: center;
    gap: 0.7rem;
    margin-top: 0.75rem;
    padding: 0.55rem 0.85rem;
    border-radius: 8px;
    background: #eff6ff;
    border-left: 3px solid #3b82f6;
    box-shadow: 0 1px 2px rgba(0, 0, 0, 0.06);
  }

  .update-icon {
    display: inline-flex;
    color: #2563eb;
    flex-shrink: 0;
  }

  .update-text {
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
    min-width: 0;
    flex: 1;
  }

  .update-text strong {
    font-size: 0.9rem;
  }

  .update-text span {
    font-size: 0.82rem;
    color: #475569;
  }

  .update-actions {
    display: flex;
    align-items: center;
    gap: 0.35rem;
    flex-shrink: 0;
  }

  @media (prefers-color-scheme: dark) {
    .update-banner {
      background: #1e293b;
      box-shadow: none;
    }
    .update-icon {
      color: #60a5fa;
    }
    .update-text span {
      color: #94a3b8;
    }
  }

  :where(:root.force-dark) .update-banner {
    background: #1e293b;
    box-shadow: none;
  }
  :where(:root.force-dark) .update-icon {
    color: #60a5fa;
  }
  :where(:root.force-dark) .update-text span {
    color: #94a3b8;
  }
</style>
