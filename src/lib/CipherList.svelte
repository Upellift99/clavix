<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import { cipherTypeIcon, cipherTypeLabel, faviconUrl } from "./format";
  import type { DragController } from "./drag.svelte";
  import type { CipherSummary, SortKey, StoredAccount } from "./types";

  type Props = {
    items: CipherSummary[];
    totalCount: number;
    hasNarrowing: boolean;
    selectedId: string | null;
    sortKey: SortKey;
    sortAsc: boolean;
    storedAccount: StoredAccount | null;
    drag: DragController;
    onOpenCipher: (id: string) => void;
    onToggleSort: (key: SortKey) => void;
    onSearchInputRef: (el: HTMLInputElement | null) => void;
    search: string;
  };

  let {
    items,
    totalCount,
    hasNarrowing,
    selectedId,
    sortKey,
    sortAsc,
    storedAccount,
    drag,
    onOpenCipher,
    onToggleSort,
    onSearchInputRef,
    search = $bindable(),
  }: Props = $props();

  const ROW_HEIGHT = 36;
  const OVERSCAN = 6;
  let listScrollEl = $state<HTMLElement | null>(null);
  let listScrollTop = $state(0);
  let listViewportHeight = $state(600);
  let searchInputEl = $state<HTMLInputElement | null>(null);

  $effect(() => {
    onSearchInputRef(searchInputEl);
  });

  function onListScroll(event: Event) {
    listScrollTop = (event.currentTarget as HTMLElement).scrollTop;
  }

  $effect(() => {
    if (!listScrollEl) return;
    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        listViewportHeight = entry.contentRect.height;
      }
    });
    observer.observe(listScrollEl);
    listViewportHeight = listScrollEl.clientHeight;
    return () => observer.disconnect();
  });

  // Clamp the scroll position when the visible items shrink (typical
  // case: the user types in the search box, the filter cuts the list
  // from N to a handful). Without this, listScrollTop keeps its old
  // value, virtualWindow.offsetY still translates the rendered slice
  // by hundreds of pixels, and the user sees a tall empty band above
  // the matches. Force both the DOM scrollTop and the local state
  // back into the legal range.
  $effect(() => {
    void items.length;
    if (!listScrollEl) return;
    const maxScroll = Math.max(
      0,
      items.length * ROW_HEIGHT - listViewportHeight,
    );
    if (listScrollTop > maxScroll) {
      listScrollEl.scrollTop = maxScroll;
      listScrollTop = maxScroll;
    }
  });

  const virtualWindow = $derived.by(() => {
    const total = items.length;
    const start = Math.max(0, Math.floor(listScrollTop / ROW_HEIGHT) - OVERSCAN);
    const end = Math.min(
      total,
      Math.ceil((listScrollTop + listViewportHeight) / ROW_HEIGHT) + OVERSCAN,
    );
    return {
      total,
      start,
      end,
      items: items.slice(start, end),
      offsetY: start * ROW_HEIGHT,
      totalHeight: total * ROW_HEIGHT,
    };
  });

  function onCipherDragStart(event: DragEvent, cipherId: string) {
    drag.startCipher(cipherId);
    if (event.dataTransfer) {
      event.dataTransfer.effectAllowed = "move";
      event.dataTransfer.setData("text/plain", cipherId);
    }
  }

  function onCipherDragEnd() {
    drag.resetCipher();
  }
</script>

<section class="list-pane">
  <h3>
    Items
    <small>
      ({items.length.toLocaleString("fr-FR")}
      {#if hasNarrowing}/{totalCount.toLocaleString("fr-FR")}{/if})
    </small>
  </h3>
  <div class="search-row">
    <input
      type="search"
      bind:value={search}
      bind:this={searchInputEl}
      placeholder={m.items_search_placeholder()}
      class="search"
    />
    {#if search.trim()}
      <button type="button" class="secondary small" onclick={() => (search = "")}>
        Effacer
      </button>
    {/if}
  </div>
  {#if items.length === 0}
    <p class="hint">
      {#if search.trim()}
        Aucun item ne correspond à « {search} ».
      {:else}
        Aucun item dans ce dossier.
      {/if}
    </p>
  {:else}
    <div class="cipher-headers cipher-columns" role="row">
      <span></span>
      <button
        type="button"
        class="cipher-header"
        class:active={sortKey === "name"}
        onclick={() => onToggleSort("name")}
      >
        {m.col_name()}
        {#if sortKey === "name"}<span class="sort-arrow">{sortAsc ? "▲" : "▼"}</span>{/if}
      </button>
      <button
        type="button"
        class="cipher-header"
        class:active={sortKey === "username"}
        onclick={() => onToggleSort("username")}
      >
        {m.col_username()}
        {#if sortKey === "username"}<span class="sort-arrow">{sortAsc ? "▲" : "▼"}</span>{/if}
      </button>
      <button
        type="button"
        class="cipher-header"
        class:active={sortKey === "uri"}
        onclick={() => onToggleSort("uri")}
      >
        {m.col_url()}
        {#if sortKey === "uri"}<span class="sort-arrow">{sortAsc ? "▲" : "▼"}</span>{/if}
      </button>
    </div>
    <div class="cipher-scroll" bind:this={listScrollEl} onscroll={onListScroll}>
      <div class="cipher-spacer" style:height="{virtualWindow.totalHeight}px">
        <ul
          class="enc-list cipher-list"
          style:transform="translateY({virtualWindow.offsetY}px)"
        >
          {#each virtualWindow.items as c, i (c.id)}
            {@const fav = faviconUrl(c, storedAccount)}
            <li style:height="{ROW_HEIGHT}px">
              <button
                type="button"
                class="cipher-row cipher-columns"
                class:zebra={(virtualWindow.start + i) % 2 === 1}
                class:selected={selectedId === c.id}
                class:dragging={drag.cipherId === c.id}
                onclick={() => onOpenCipher(c.id)}
                draggable="true"
                ondragstart={(e) => onCipherDragStart(e, c.id)}
                ondragend={onCipherDragEnd}
              >
                <span class="cipher-icon" title={cipherTypeLabel(c.kind)}>
                  {#if fav}
                    <img
                      src={fav}
                      alt=""
                      loading="lazy"
                      onerror={(e) => {
                        const img = e.currentTarget as HTMLImageElement;
                        img.style.display = "none";
                        const fallback = img.nextElementSibling as HTMLElement | null;
                        if (fallback) fallback.style.display = "inline";
                      }}
                    />
                    <span class="emoji-fallback" style:display="none">
                      {cipherTypeIcon(c.kind)}
                    </span>
                  {:else}
                    <span class="emoji-fallback">{cipherTypeIcon(c.kind)}</span>
                  {/if}
                </span>
                <span class="col-name">
                  {c.name}
                  {#if c.favorite}<span class="star" title="Favori">★</span>{/if}
                </span>
                <span class="col-username" title={c.username ?? ""}>
                  {c.username ?? ""}
                </span>
                <span class="col-uri" title={c.primaryUri ?? ""}>
                  {c.primaryUri ?? ""}
                </span>
              </button>
            </li>
          {/each}
        </ul>
      </div>
    </div>
  {/if}
</section>
