<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import Icon from "./Icon.svelte";
  import { cipherTypeIconName, cipherTypeLabel, faviconUrl } from "./format";
  import type { DragController } from "./drag.svelte";
  import type { CipherListColumns } from "./prefs.svelte";
  import type { CipherSummary, SortKey, StoredAccount } from "./types";

  type Props = {
    items: CipherSummary[];
    totalCount: number;
    hasNarrowing: boolean;
    /** Hold the list back until the user searches or picks a folder. */
    gated: boolean;
    onShowAll: () => void;
    selectedId: string | null;
    sortKey: SortKey;
    sortAsc: boolean;
    storedAccount: StoredAccount | null;
    visibleColumns: CipherListColumns;
    drag: DragController;
    onOpenCipher: (id: string) => void;
    onToggleSort: (key: SortKey) => void;
    onToggleColumn: (key: keyof CipherListColumns, value: boolean) => void;
    onSearchInputRef: (el: HTMLInputElement | null) => void;
    search: string;
  };

  let {
    items,
    totalCount,
    hasNarrowing,
    gated,
    onShowAll,
    selectedId,
    sortKey,
    sortAsc,
    storedAccount,
    visibleColumns,
    drag,
    onOpenCipher,
    onToggleSort,
    onToggleColumn,
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
    <!-- Kept on one line: a newline before `)` renders as a stray space,
         which showed up as "(3 319 )" whenever nothing narrowed the list. -->
    <small>({items.length.toLocaleString("fr-FR")}{#if hasNarrowing}/{totalCount.toLocaleString("fr-FR")}{/if})</small>
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
  {#if gated}
    <div class="empty-state" role="status">
      <Icon name="search" size={40} class="empty-icon" />
      <p class="empty-title">{m.items_gated_title()}</p>
      <p class="empty-body">{m.items_gated_body({ count: String(totalCount) })}</p>
      <button type="button" class="secondary small" onclick={onShowAll}>
        {m.items_gated_show_all()}
      </button>
    </div>
  {:else if items.length === 0}
    <div class="empty-state" role="status">
      {#if search.trim()}
        <Icon name="search" size={40} class="empty-icon" />
        <p class="empty-title">Aucun résultat</p>
        <p class="empty-body">
          Aucun item ne correspond à « {search} ».
        </p>
        <button
          type="button"
          class="secondary small"
          onclick={() => (search = "")}
        >
          Effacer la recherche
        </button>
      {:else}
        <Icon name="folder" size={40} class="empty-icon" />
        <p class="empty-title">Ce dossier est vide</p>
        <p class="empty-body">
          Crée un nouvel item ou importe ton coffre KeePassXC depuis la barre d'outils.
        </p>
      {/if}
    </div>
  {:else}
    <div
      class="cipher-headers cipher-columns"
      class:hide-username={!visibleColumns.username}
      class:hide-uri={!visibleColumns.uri}
      role="row"
    >
      <details class="columns-chooser">
        <summary
          class="cipher-icon"
          title={m.columns_chooser_title()}
          aria-label={m.columns_chooser_title()}
        >
          <Icon name="more-horizontal" size={14} />
        </summary>
        <div class="columns-popover" role="menu">
          <div class="columns-popover-title">{m.columns_chooser_title()}</div>
          <label>
            <input
              type="checkbox"
              checked={visibleColumns.username}
              onchange={(e) =>
                onToggleColumn("username", (e.currentTarget as HTMLInputElement).checked)}
            />
            {m.col_username()}
          </label>
          <label>
            <input
              type="checkbox"
              checked={visibleColumns.uri}
              onchange={(e) =>
                onToggleColumn("uri", (e.currentTarget as HTMLInputElement).checked)}
            />
            {m.col_url()}
          </label>
        </div>
      </details>
      <button
        type="button"
        class="cipher-header"
        class:active={sortKey === "name"}
        onclick={() => onToggleSort("name")}
      >
        {m.col_name()}
        {#if sortKey === "name"}<Icon name={sortAsc ? "chevron-up" : "chevron-down"} size={12} class="sort-arrow" />{/if}
      </button>
      {#if visibleColumns.username}
        <button
          type="button"
          class="cipher-header"
          class:active={sortKey === "username"}
          onclick={() => onToggleSort("username")}
        >
          {m.col_username()}
          {#if sortKey === "username"}<Icon name={sortAsc ? "chevron-up" : "chevron-down"} size={12} class="sort-arrow" />{/if}
        </button>
      {/if}
      {#if visibleColumns.uri}
        <button
          type="button"
          class="cipher-header"
          class:active={sortKey === "uri"}
          onclick={() => onToggleSort("uri")}
        >
          {m.col_url()}
          {#if sortKey === "uri"}<Icon name={sortAsc ? "chevron-up" : "chevron-down"} size={12} class="sort-arrow" />{/if}
        </button>
      {/if}
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
                class:hide-username={!visibleColumns.username}
                class:hide-uri={!visibleColumns.uri}
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
                        if (fallback) fallback.style.display = "inline-flex";
                      }}
                    />
                    <span class="icon-fallback" style:display="none">
                      <Icon name={cipherTypeIconName(c.kind)} size={16} />
                    </span>
                  {:else}
                    <span class="icon-fallback">
                      <Icon name={cipherTypeIconName(c.kind)} size={16} />
                    </span>
                  {/if}
                </span>
                <span class="col-name">
                  {c.name}
                  {#if c.favorite}<span class="star" title="Favori"><Icon name="star" size={12} /></span>{/if}
                </span>
                {#if visibleColumns.username}
                  <span class="col-username" title={c.username ?? ""}>
                    {c.username ?? ""}
                  </span>
                {/if}
                {#if visibleColumns.uri}
                  <span class="col-uri" title={c.primaryUri ?? ""}>
                    {c.primaryUri ?? ""}
                  </span>
                {/if}
              </button>
            </li>
          {/each}
        </ul>
      </div>
    </div>
  {/if}
</section>
