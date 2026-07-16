<script lang="ts" module>
  /**
   * Inline SVG icon set, monochrome, stroke-driven, all in a 24×24
   * viewBox with stroke-width 2 — Lucide-style geometry. Inheriting
   * `currentColor` means a button or row's text colour just flows
   * through to the mark; no per-icon palette to maintain.
   *
   * Why not lucide-svelte: every name we use is a tiny path that
   * fits in a few lines, and pulling a transitive package for ~15
   * marks would just add Dependabot churn. Keeping the paths inline
   * also means `pnpm tauri build --no-bundle` doesn't have to thread
   * a JS dependency through tree-shaking for what amounts to text.
   */
  export type IconName =
    | "key" // Login cipher
    | "note" // Secure Note
    | "card" // Card
    | "id-card" // Identity
    | "terminal" // SSH Key
    | "star" // favorite badge
    | "trash" // trash filter / delete forever
    | "refresh" // sync
    | "refresh-spin" // sync in flight
    | "lock" // lock session
    | "log-out" // logout / switch account
    | "plus" // new item
    | "download" // import
    | "upload" // export
    | "dice" // generator
    | "shield" // audit
    | "info" // stats / infos
    | "arrow-up-circle" // about / check for updates
    | "edit" // edit cipher
    | "eye" // reveal field
    | "eye-off" // hide field
    | "copy" // copy to clipboard
    | "search" // search input adornment
    | "folder" // folder node
    | "building" // organisation node
    | "users" // collection node
    | "chevron-right" // tree collapsed
    | "chevron-down" // tree expanded
    | "chevron-up" // sort ascending indicator
    | "more-horizontal" // overflow / column chooser
    | "x"; // close
</script>

<script lang="ts">
  type Props = {
    name: IconName;
    size?: number;
    /** Decorative by default. Set to a label string when the icon
     *  carries meaning that no surrounding text reproduces. */
    label?: string;
    class?: string;
  };

  let { name, size = 16, label, class: className }: Props = $props();
</script>

<svg
  xmlns="http://www.w3.org/2000/svg"
  width={size}
  height={size}
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width="2"
  stroke-linecap="round"
  stroke-linejoin="round"
  class={className}
  aria-hidden={label ? undefined : "true"}
  aria-label={label}
  role={label ? "img" : undefined}
>
  {#if name === "key"}
    <circle cx="7.5" cy="15.5" r="4.5" />
    <line x1="11" y1="12" x2="21" y2="2" />
    <line x1="17" y1="6" x2="20" y2="9" />
    <line x1="14" y1="9" x2="18" y2="13" />
  {:else if name === "note"}
    <path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z" />
    <path d="M14 3v6h6" />
    <line x1="8" y1="13" x2="15" y2="13" />
    <line x1="8" y1="17" x2="15" y2="17" />
  {:else if name === "card"}
    <rect x="2.5" y="5" width="19" height="14" rx="2" />
    <line x1="2.5" y1="10" x2="21.5" y2="10" />
    <line x1="6" y1="15" x2="10" y2="15" />
  {:else if name === "id-card"}
    <rect x="2.5" y="4" width="19" height="16" rx="2" />
    <circle cx="8.5" cy="11" r="2" />
    <line x1="14" y1="9" x2="18" y2="9" />
    <line x1="14" y1="13" x2="18" y2="13" />
    <path d="M5 17c.5-2 2.5-3 3.5-3s3 1 3.5 3" />
  {:else if name === "terminal"}
    <polyline points="4 17 9 12 4 7" />
    <line x1="12" y1="19" x2="20" y2="19" />
  {:else if name === "star"}
    <polygon
      points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26"
    />
  {:else if name === "trash"}
    <polyline points="3 6 5 6 21 6" />
    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6" />
    <path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
    <line x1="10" y1="11" x2="10" y2="17" />
    <line x1="14" y1="11" x2="14" y2="17" />
  {:else if name === "refresh"}
    <polyline points="23 4 23 10 17 10" />
    <polyline points="1 20 1 14 7 14" />
    <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10" />
    <path d="M20.49 15a9 9 0 0 1-14.85 3.36L1 14" />
  {:else if name === "refresh-spin"}
    <polyline points="23 4 23 10 17 10" />
    <polyline points="1 20 1 14 7 14" />
    <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10" />
    <path d="M20.49 15a9 9 0 0 1-14.85 3.36L1 14" />
  {:else if name === "lock"}
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
  {:else if name === "log-out"}
    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
    <polyline points="16 17 21 12 16 7" />
    <line x1="21" y1="12" x2="9" y2="12" />
  {:else if name === "plus"}
    <line x1="12" y1="5" x2="12" y2="19" />
    <line x1="5" y1="12" x2="19" y2="12" />
  {:else if name === "download"}
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
    <polyline points="7 10 12 15 17 10" />
    <line x1="12" y1="15" x2="12" y2="3" />
  {:else if name === "upload"}
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
    <polyline points="17 8 12 3 7 8" />
    <line x1="12" y1="3" x2="12" y2="15" />
  {:else if name === "dice"}
    <rect x="3" y="3" width="18" height="18" rx="2" />
    <circle cx="8" cy="8" r="1.2" fill="currentColor" stroke="none" />
    <circle cx="16" cy="8" r="1.2" fill="currentColor" stroke="none" />
    <circle cx="8" cy="16" r="1.2" fill="currentColor" stroke="none" />
    <circle cx="16" cy="16" r="1.2" fill="currentColor" stroke="none" />
    <circle cx="12" cy="12" r="1.2" fill="currentColor" stroke="none" />
  {:else if name === "shield"}
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    <polyline points="9 12 11 14 15 10" />
  {:else if name === "info"}
    <circle cx="12" cy="12" r="10" />
    <line x1="12" y1="16" x2="12" y2="12" />
    <line x1="12" y1="8" x2="12.01" y2="8" />
  {:else if name === "arrow-up-circle"}
    <circle cx="12" cy="12" r="10" />
    <path d="M8 12l4-4 4 4" />
    <line x1="12" y1="16" x2="12" y2="8" />
  {:else if name === "edit"}
    <path d="M12 20h9" />
    <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4z" />
  {:else if name === "eye"}
    <path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7z" />
    <circle cx="12" cy="12" r="3" />
  {:else if name === "eye-off"}
    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-10-7-10-7a13.16 13.16 0 0 1 4.06-4.94" />
    <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68" />
    <path d="M14.12 14.12a3 3 0 1 1-4.24-4.24" />
    <line x1="1" y1="1" x2="23" y2="23" />
  {:else if name === "copy"}
    <rect x="9" y="9" width="13" height="13" rx="2" />
    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
  {:else if name === "search"}
    <circle cx="11" cy="11" r="7" />
    <line x1="21" y1="21" x2="16.5" y2="16.5" />
  {:else if name === "folder"}
    <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
  {:else if name === "building"}
    <rect x="4" y="2" width="16" height="20" rx="2" />
    <line x1="9" y1="6" x2="15" y2="6" />
    <line x1="9" y1="10" x2="15" y2="10" />
    <line x1="9" y1="14" x2="15" y2="14" />
    <line x1="11" y1="22" x2="11" y2="18" />
    <line x1="13" y1="22" x2="13" y2="18" />
  {:else if name === "users"}
    <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
    <circle cx="9" cy="7" r="4" />
    <path d="M22 21v-2a4 4 0 0 0-3-3.87" />
    <path d="M16 3.13a4 4 0 0 1 0 7.75" />
  {:else if name === "chevron-right"}
    <polyline points="9 6 15 12 9 18" />
  {:else if name === "chevron-down"}
    <polyline points="6 9 12 15 18 9" />
  {:else if name === "chevron-up"}
    <polyline points="18 15 12 9 6 15" />
  {:else if name === "more-horizontal"}
    <circle cx="5" cy="12" r="1.5" fill="currentColor" stroke="none" />
    <circle cx="12" cy="12" r="1.5" fill="currentColor" stroke="none" />
    <circle cx="19" cy="12" r="1.5" fill="currentColor" stroke="none" />
  {:else if name === "x"}
    <line x1="6" y1="6" x2="18" y2="18" />
    <line x1="6" y1="18" x2="18" y2="6" />
  {/if}
</svg>

<style>
  /* Spin marker for the in-flight refresh icon. The component
     toggles between "refresh" (static) and "refresh-spin"
     (animated) so the same geometry can be reused. */
  svg {
    display: inline-block;
    vertical-align: -0.125em;
    flex: 0 0 auto;
  }
  :global(.icon-spin) {
    animation: icon-spin 1s linear infinite;
  }
  @keyframes icon-spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
  }
</style>
