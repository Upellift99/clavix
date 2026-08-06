<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import type { SessionOrigin } from "./types";

  /**
   * Permanent notice that this vault has no server behind it.
   *
   * A coloured dot in the corner would not carry this: the user needs
   * to know *why* the vault is read-only and what is missing from it,
   * before they try to change something and wonder why nothing saved.
   * So it states the origin, the restriction, and the gaps.
   */
  let { origin }: { origin: SessionOrigin } = $props();

  const title = $derived(
    origin === "exportFile" ? m.standalone_title_file() : m.standalone_title_cache(),
  );
  const detail = $derived(
    origin === "exportFile" ? m.standalone_detail_file() : m.standalone_detail_cache(),
  );
</script>

<div class="standalone-banner" role="status">
  <span class="standalone-icon" aria-hidden="true">⚠</span>
  <div>
    <strong>{title}</strong>
    <p>{detail}</p>
    <p class="standalone-unavailable">{m.standalone_unavailable()}</p>
  </div>
</div>

<style>
  .standalone-banner {
    display: flex;
    gap: 0.6rem;
    align-items: flex-start;
    background: #fef3c7;
    color: #7a3b00;
    border: 1px solid #f0c674;
    border-radius: 6px;
    padding: 0.55rem 0.8rem;
    margin: 0 0 0.6rem;
    font-size: 0.88rem;
  }

  .standalone-icon {
    font-size: 1rem;
    line-height: 1.3;
  }

  .standalone-banner p {
    margin: 0.15rem 0 0;
  }

  .standalone-unavailable {
    opacity: 0.85;
    font-size: 0.83rem;
  }

  /* Both dark blocks are required — the @media one for the system
     preference, the :where(:root.force-dark) one for the in-app theme
     toggle. See the comment at base.css:337-350. */
  @media (prefers-color-scheme: dark) {
    .standalone-banner {
      background: #3a2f14;
      color: #f0d9a8;
      border-color: #6b5520;
    }
  }

  :where(:root.force-dark) .standalone-banner {
    background: #3a2f14;
    color: #f0d9a8;
    border-color: #6b5520;
  }
</style>
