<script lang="ts">
  import { openUrl } from "@tauri-apps/plugin-opener";
  import * as m from "$lib/paraglide/messages";
  import { api } from "./api";
  import AuthLoginForm from "./AuthLoginForm.svelte";
  import Onboarding from "./Onboarding.svelte";
  import TwoFactorForm from "./TwoFactorForm.svelte";
  import UnlockForm from "./UnlockForm.svelte";
  import type { AuthController } from "./auth.svelte";

  type Props = {
    auth: AuthController;
    askYubikeyPin: boolean;
    onOnboardingComplete: () => void;
  };

  let { auth, askYubikeyPin, onOnboardingComplete }: Props = $props();

  // Build version for the startup footer. Offline, straight from Rust.
  // A failure just leaves the version off — the link still works.
  let version = $state("");
  $effect(() => {
    api
      .appVersion()
      .then((v) => (version = v))
      .catch(() => (version = ""));
  });

  async function openWebsite() {
    await openUrl("https://clavix.org");
  }
</script>

{#if auth.phase === "init"}
  <p class="subtitle">{m.loading()}</p>
{/if}

{#if auth.phase === "onboarding"}
  <Onboarding onComplete={onOnboardingComplete} />
{/if}

{#if auth.phase === "idle" || (auth.phase === "authenticating" && !auth.storedAccount) || auth.phase === "error"}
  <AuthLoginForm
    bind:serverUrl={auth.serverUrl}
    bind:email={auth.email}
    bind:password={auth.password}
    disabled={auth.phase === "authenticating"}
    onSubmit={(e) => auth.submitLogin(e)}
  />
{/if}

{#if auth.phase === "unlock" || (auth.phase === "authenticating" && auth.storedAccount)}
  <UnlockForm
    account={auth.storedAccount}
    bind:password={auth.password}
    disabled={auth.phase === "authenticating"}
    yubikeyAvailable={auth.yubikeyAvailable}
    yubikeyBusy={auth.yubikeyBusy}
    bind:yubikeyPin={auth.yubikeyPin}
    {askYubikeyPin}
    onSubmit={(e) => auth.submitUnlock(e)}
    onYubikey={() => auth.submitYubikey()}
    onSwitchAccount={() => auth.switchAccount()}
  />
{/if}

{#if auth.phase === "twoFactor"}
  <TwoFactorForm
    providers={auth.pendingProviders}
    bind:selectedProvider={auth.selectedProvider}
    bind:totpCode={auth.totpCode}
    bind:yubikeyOtp={auth.yubikeyOtp}
    webauthnBusy={auth.webauthnBusy}
    hasWebauthnChallenge={auth.webauthnChallenge !== null}
    onSubmit={(e) => auth.submitTwoFactor(e)}
    onWebauthn={() => auth.submitWebauthn()}
    onCancel={() => auth.cancelTwoFactor()}
  />
{/if}

{#if auth.phase !== "loggedIn" && auth.phase !== "init"}
  <footer class="auth-footer">
    {#if version}
      <span class="auth-footer-version">Clavix · {m.about_version({ version })}</span>
      <span class="auth-footer-sep" aria-hidden="true">—</span>
    {/if}
    <button type="button" class="auth-footer-link" onclick={openWebsite} title={m.about_website()}>
      clavix.org
    </button>
  </footer>
{/if}

<style>
  .auth-footer {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.4rem;
    margin-top: 1.25rem;
    font-size: 0.8rem;
    color: #777;
  }

  .auth-footer-sep {
    opacity: 0.6;
  }

  .auth-footer-link {
    background: none;
    border: none;
    padding: 0;
    font: inherit;
    color: #2563eb;
    text-decoration: underline;
    cursor: pointer;
  }

  .auth-footer-link:hover {
    color: #1d4ed8;
  }

  @media (prefers-color-scheme: dark) {
    .auth-footer {
      color: #999;
    }
    .auth-footer-link {
      color: #60a5fa;
    }
    .auth-footer-link:hover {
      color: #93c5fd;
    }
  }

  :global(:root.force-dark) .auth-footer {
    color: #999;
  }
  :global(:root.force-dark) .auth-footer-link {
    color: #60a5fa;
  }
  :global(:root.force-dark) .auth-footer-link:hover {
    color: #93c5fd;
  }
</style>
