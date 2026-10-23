<script lang="ts">
  import { openUrl } from "@tauri-apps/plugin-opener";
  import * as m from "#lib/paraglide/messages.js";

  const DISCLAIMER_URL = "https://github.com/Upellift99/clavix/blob/master/DISCLAIMER.md";

  let { onComplete }: { onComplete: () => void } = $props();

  async function openDisclaimer() {
    try {
      await openUrl(DISCLAIMER_URL);
    } catch (e) {
      console.warn("[clavix] openDisclaimer failed:", e);
    }
  }
</script>

<section class="box onboarding">
  <h2>{m.onboarding_title()}</h2>
  <p>{m.onboarding_intro()}</p>
  <h3>{m.onboarding_what_title()}</h3>
  <ul>
    <li>{m.onboarding_what_1()}</li>
    <li>{m.onboarding_what_2()}</li>
    <li>{m.onboarding_what_3()}</li>
  </ul>
  <div class="callout">
    <strong>{m.onboarding_alpha_title()}</strong>
    <p>{m.onboarding_alpha_body()}</p>
    <button type="button" class="secondary" onclick={openDisclaimer}>
      {m.onboarding_read_disclaimer()}
    </button>
  </div>
  <div class="row">
    <button type="button" onclick={onComplete}>
      {m.onboarding_continue()}
    </button>
  </div>
</section>

<style>
  .box {
    margin-top: 1.5rem;
    padding: 1rem 1.25rem;
    border-radius: 10px;
    background: var(--surface);
    color: var(--text);
    box-shadow: var(--shadow-card);
  }

  .box.onboarding h3 {
    margin-top: 1rem;
    font-size: 0.9rem;
    color: var(--text-label);
  }

  .box.onboarding ul {
    margin: 0.25rem 0 0.75rem;
    padding-left: 1.25rem;
    color: var(--text-secondary);
  }

  .box.onboarding ul li {
    margin-bottom: 0.2rem;
  }

  h2 {
    margin: 0 0 0.75rem;
    font-size: 1rem;
  }

  p {
    margin: 0 0 0.5rem;
  }

  .callout {
    margin: 1rem 0 0.25rem;
    padding: 0.85rem 1rem;
    border-radius: 8px;
    background: var(--warning-bg);
    color: var(--warning-text);
    border: 1px solid var(--warning-border);
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    align-items: flex-start;
  }

  .callout strong {
    font-weight: 600;
    color: var(--warning-text);
  }

  .callout p {
    margin: 0;
    color: var(--warning-text);
    font-size: 0.9rem;
  }

  .callout button {
    padding: 0.35rem 0.7rem;
    font-size: 0.85rem;
  }

  .row {
    display: flex;
    gap: 0.5rem;
    justify-content: flex-end;
  }

  button {
    cursor: pointer;
    background: var(--primary);
    color: var(--on-primary);
    border: 1px solid var(--primary);
    border-radius: 6px;
    padding: 0.55rem 0.8rem;
    font: inherit;
    font-weight: 500;
  }

  button.secondary {
    background: var(--surface);
    color: var(--text-secondary);
    border-color: var(--border-input);
  }

  button:hover:not(:disabled) {

    background: var(--primary-pressed);

    border-color: var(--primary-pressed);

  }

  button.secondary:hover:not(:disabled) {

    background: var(--hover-soft);

    border-color: var(--border-input);

  }
</style>
