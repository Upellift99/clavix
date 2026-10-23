<script lang="ts">
  // The Clavix mark, "le sceau précis", inline so it follows the theme
  // tokens and needs no asset request. Same geometry as
  // assets/clavix-logo.svg minus the tile: a knurled disc, a hairline
  // ring and the pressed C.
  let { size = 20, label = undefined }: { size?: number; label?: string } = $props();
</script>

<svg
  xmlns="http://www.w3.org/2000/svg"
  viewBox="0 0 512 512"
  width={size}
  height={size}
  class="mark"
  aria-hidden={label ? undefined : "true"}
  aria-label={label}
  role={label ? "img" : undefined}
>
  <circle cx="256" cy="256" r="218" fill="none" stroke="var(--primary)" stroke-width="34" stroke-dasharray="17 11.6" />
  <circle cx="256" cy="256" r="200" fill="var(--primary)" />
  <circle cx="256" cy="256" r="166" fill="none" stroke="var(--primary-hover-border)" stroke-width="8" />
  <path d="M336 182 A110 110 0 1 0 336 330" fill="none" stroke="var(--primary-pressed)" stroke-width="60" transform="translate(7 8)" />
  <path d="M336 182 A110 110 0 1 0 336 330" fill="none" stroke="#ffffff" stroke-width="60" />
</svg>

<style>
  .mark {
    display: inline-block;
    flex: 0 0 auto;
    vertical-align: middle;
  }
</style>
