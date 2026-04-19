<script lang="ts">
  import { openUrl } from "@tauri-apps/plugin-opener";
  import * as m from "$lib/paraglide/messages";

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
    background: #fff;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
  }

  .box.onboarding h3 {
    margin-top: 1rem;
    font-size: 0.9rem;
    color: #444;
  }

  .box.onboarding ul {
    margin: 0.25rem 0 0.75rem;
    padding-left: 1.25rem;
    color: #333;
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
    background: #fff8e1;
    border-left: 4px solid #d6a400;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    align-items: flex-start;
  }

  .callout strong {
    font-weight: 600;
    color: #6a5000;
  }

  .callout p {
    margin: 0;
    color: #4a3a00;
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
    background: #396cd8;
    color: #fff;
    border: 1px solid #396cd8;
    border-radius: 6px;
    padding: 0.55rem 0.8rem;
    font: inherit;
    font-weight: 500;
  }

  button.secondary {
    background: #fff;
    color: #333;
    border-color: #d0d0d0;
  }

  button:hover {
    filter: brightness(0.95);
  }
</style>
