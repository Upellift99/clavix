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
    /** Double-click: straight to the edit dialog, desktop-idiom style. */
    onEditCipher: (id: string) => void;
    onRowContextMenu: (event: MouseEvent, cipher: CipherSummary) => void;
    onToggleSort: (key: SortKey) => void;
    onToggleColumn: (key: keyof CipherListColumns, value: boolean) => void;
    onSearchInputRef: (el: HTMLInputElement | null) => void;
    search: string;
    // ---- multi-selection ----
    /** Ids currently ticked. Owned by the page; the list only asks. */
    selectedIds: Set<string>;
    onToggleSelection: (id: string) => void;
    onSetSelection: (ids: string[]) => void;
    onClearSelection: () => void;
    /** Folders offered by the bulk "move to" picker. */
    folders: { id: string; name: string }[];
    /** True when the trash filter is active: bulk delete is permanent
        there, and restore becomes available. */
    trashView: boolean;
    onBulkMove: (folderId: string | null) => void;
    onBulkDelete: () => void;
    onBulkRestore: () => void;
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
    onEditCipher,
    onRowContextMenu,
    onToggleSort,
    onToggleColumn,
    onSearchInputRef,
    search = $bindable(),
    selectedIds,
    onToggleSelection,
    onSetSelection,
    onClearSelection,
    folders,
    trashView,
    onBulkMove,
    onBulkDelete,
    onBulkRestore,
  }: Props = $props();

  // Anchor for Shift-click ranges: the last row clicked without Shift.
  // Kept as an id rather than an index so a re-filter can't silently
  // point it at a different item.
  let anchorId = $state<string | null>(null);

  /**
   * Rows behave like a desktop file list: a plain click opens the item,
   * Ctrl/Cmd-click adds or removes one, Shift-click takes everything
   * between the anchor and here. The selection is deliberately dropped
   * on a plain click — otherwise a stale tick from three filters ago
   * would silently join the next bulk delete.
   */
  function onRowClick(event: MouseEvent, cipher: CipherSummary) {
    if (event.shiftKey && anchorId) {
      event.preventDefault();
      const from = items.findIndex((i) => i.id === anchorId);
      const to = items.findIndex((i) => i.id === cipher.id);
      if (from !== -1 && to !== -1) {
        const [start, end] = from <= to ? [from, to] : [to, from];
        onSetSelection(items.slice(start, end + 1).map((i) => i.id));
      }
      return;
    }
    if (event.ctrlKey || event.metaKey) {
      event.preventDefault();
      anchorId = cipher.id;
      onToggleSelection(cipher.id);
      return;
    }
    anchorId = cipher.id;
    if (selectedIds.size > 0) onClearSelection();
    onOpenCipher(cipher.id);
  }

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
  <!-- Only on screen while something is selected: an always-present bar
       would take a row of vertical space from the list for an action
       nobody has asked for yet. -->
  {#if selectedIds.size > 0}
    <div class="selection-bar" role="toolbar" aria-label={m.items_selected({ count: String(selectedIds.size) })}>
      <span class="selection-count">
        {m.items_selected({ count: String(selectedIds.size) })}
      </span>
      <button type="button" class="secondary small" onclick={() => onSetSelection(items.map((i) => i.id))}>
        {m.items_select_all()}
      </button>
      {#if trashView}
        <button type="button" class="secondary small" onclick={onBulkRestore}>
          {m.bulk_restore()}
        </button>
      {:else}
        <select
          aria-label={m.bulk_move_to_folder()}
          value=""
          onchange={(e) => {
            const value = e.currentTarget.value;
            // Back to the placeholder so the same folder can be picked
            // twice in a row.
            e.currentTarget.value = "";
            if (value !== "") onBulkMove(value === "__none__" ? null : value);
          }}
        >
          <option value="" disabled>{m.bulk_move_to_folder()}</option>
          <option value="__none__">{m.bulk_no_folder()}</option>
          {#each folders as folder (folder.id)}
            <option value={folder.id}>{folder.name}</option>
          {/each}
        </select>
      {/if}
      <button type="button" class="small danger" onclick={onBulkDelete}>
        {m.bulk_delete()}
      </button>
      <button type="button" class="secondary small" onclick={onClearSelection}>
        {m.items_clear_selection()}
      </button>
    </div>
  {/if}
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
                class:ticked={selectedIds.has(c.id)}
                class:dragging={drag.cipherId === c.id}
                class:hide-username={!visibleColumns.username}
                class:hide-uri={!visibleColumns.uri}
                aria-pressed={selectedIds.has(c.id)}
                onclick={(e) => onRowClick(e, c)}
                ondblclick={() => onEditCipher(c.id)}
                oncontextmenu={(e) => onRowContextMenu(e, c)}
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
