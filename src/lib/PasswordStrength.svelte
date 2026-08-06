<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import {
    BANDS,
    bandForBits,
    bandForScore,
    bandIndex,
    type StrengthBand,
  } from "./strength";

  /**
   * One meter, two scales — and the caller picks by passing `bits` or
   * `score`, never a band. Deriving the band in here is what stops a
   * caller from pairing "60 bits" with the zxcvbn thresholds, which
   * would be a category error: bits measure a uniform random draw,
   * zxcvbn's 0-4 estimates guessability of a human-chosen string.
   */
  type Props = {
    /** Exact entropy of a generated password. Mutually exclusive with `score`. */
    bits?: number;
    /** zxcvbn score 0-4 of a user-chosen password. Mutually exclusive with `bits`. */
    score?: number | null;
    /** zxcvbn warning slug, rendered under the bar when present. */
    warning?: string | null;
    /** Hide the textual verdict, leaving only the bar (tight layouts). */
    compact?: boolean;
  };

  let { bits, score, warning = null, compact = false }: Props = $props();

  const band = $derived<StrengthBand>(
    bits !== undefined
      ? bandForBits(bits)
      : score === null || score === undefined
        ? "empty"
        : bandForScore(score),
  );

  const filled = $derived(bandIndex(band));

  const label = $derived(
    band === "empty"
      ? ""
      : band === "weak"
        ? m.strength_weak()
        : band === "fair"
          ? m.strength_fair()
          : band === "good"
            ? m.strength_good()
            : m.strength_strong(),
  );

  /**
   * zxcvbn's warning enum, mapped slug by slug. Paraglide compiles one
   * function per message, so there is no dynamic key lookup to use
   * here — and the explicit table is the better trade anyway: an
   * unmapped slug is visible at a glance rather than resolving to an
   * empty string at runtime.
   */
  const WARNINGS: Record<string, () => string> = {
    "straight-rows-of-keys": m.strength_warning_straight_rows_of_keys,
    "short-keyboard-pattern": m.strength_warning_short_keyboard_pattern,
    "repeats-like-aaa": m.strength_warning_repeats_like_aaa,
    "repeats-like-abcabc": m.strength_warning_repeats_like_abcabc,
    "top-10-password": m.strength_warning_top_10_password,
    "top-100-password": m.strength_warning_top_100_password,
    "common-password": m.strength_warning_common_password,
    "similar-to-common-password": m.strength_warning_similar_to_common_password,
    "sequences-like-abc": m.strength_warning_sequences_like_abc,
    "recent-years": m.strength_warning_recent_years,
    "word-by-itself": m.strength_warning_word_by_itself,
    dates: m.strength_warning_dates,
    "names-by-themselves": m.strength_warning_names_by_themselves,
    "common-names": m.strength_warning_common_names,
  };

  const warningText = $derived(warning ? (WARNINGS[warning]?.() ?? null) : null);

  /** Bits are a precise number; rounding to a whole bit is enough. */
  const bitsText = $derived(
    bits !== undefined && bits > 0
      ? m.strength_bits({ count: String(Math.round(bits)) })
      : null,
  );

  // `aria-valuetext` carries the verdict, because "3 out of 4" alone
  // tells a screen-reader user nothing about what the segments mean.
  const valueText = $derived(bitsText ? `${label} — ${bitsText}` : label);
</script>

<div class="strength" data-band={band}>
  <div
    class="strength-bar"
    role="meter"
    aria-valuemin="0"
    aria-valuemax={BANDS.length - 1}
    aria-valuenow={filled}
    aria-valuetext={valueText}
    aria-label={m.strength_label()}
  >
    {#each BANDS.slice(1) as segment, i (segment)}
      <span class="strength-seg" class:on={i < filled}></span>
    {/each}
  </div>
  {#if !compact && band !== "empty"}
    <p class="strength-text">
      <span class="strength-verdict">{label}</span>
      {#if bitsText}<span class="strength-detail">{bitsText}</span>{/if}
    </p>
  {/if}
  {#if warningText}
    <p class="strength-warning">{warningText}</p>
  {/if}
</div>

<style>
  /* Band colours are declared once as custom properties and re-stated
     per theme below. Both dark blocks are required: the @media one for
     the system preference, the :where(:root.force-dark) one for the
     in-app theme toggle — see the comment at base.css:337-350. */
  .strength {
    --strength-track: #e5e7eb;
    --strength-weak: #b91c1c;
    --strength-fair: #b45309;
    --strength-good: #1d4ed8;
    --strength-strong: #18683a;
    --strength-muted: #555;
    margin: 0.3rem 0 0;
  }

  .strength-bar {
    display: flex;
    gap: 3px;
    height: 4px;
  }

  .strength-seg {
    flex: 1;
    background: var(--strength-track);
    border-radius: 2px;
    transition: background 120ms ease-out;
  }

  .strength[data-band="weak"] .strength-seg.on {
    background: var(--strength-weak);
  }
  .strength[data-band="fair"] .strength-seg.on {
    background: var(--strength-fair);
  }
  .strength[data-band="good"] .strength-seg.on {
    background: var(--strength-good);
  }
  .strength[data-band="strong"] .strength-seg.on {
    background: var(--strength-strong);
  }

  .strength-text {
    display: flex;
    justify-content: space-between;
    gap: 0.5rem;
    margin: 0.2rem 0 0;
    font-size: 0.78rem;
  }

  .strength-verdict {
    font-weight: 500;
  }

  .strength[data-band="weak"] .strength-verdict {
    color: var(--strength-weak);
  }
  .strength[data-band="fair"] .strength-verdict {
    color: var(--strength-fair);
  }
  .strength[data-band="good"] .strength-verdict {
    color: var(--strength-good);
  }
  .strength[data-band="strong"] .strength-verdict {
    color: var(--strength-strong);
  }

  .strength-detail {
    color: var(--strength-muted);
    font-variant-numeric: tabular-nums;
  }

  .strength-warning {
    margin: 0.2rem 0 0;
    font-size: 0.78rem;
    color: var(--strength-fair);
  }

  @media (prefers-color-scheme: dark) {
    .strength {
      --strength-track: #3a3a3a;
      --strength-weak: #ff8a8a;
      --strength-fair: #e0a458;
      --strength-good: #8fb0ff;
      --strength-strong: #6ecf9a;
      --strength-muted: #aaa;
    }
  }

  :where(:root.force-dark) .strength {
    --strength-track: #3a3a3a;
    --strength-weak: #ff8a8a;
    --strength-fair: #e0a458;
    --strength-good: #8fb0ff;
    --strength-strong: #6ecf9a;
    --strength-muted: #aaa;
  }
</style>
