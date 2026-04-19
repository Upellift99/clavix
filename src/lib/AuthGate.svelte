<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import AuthLoginForm from "./AuthLoginForm.svelte";
  import Onboarding from "./Onboarding.svelte";
  import TwoFactorForm from "./TwoFactorForm.svelte";
  import UnlockForm from "./UnlockForm.svelte";
  import type { AuthController } from "./auth.svelte";

  type Props = {
    auth: AuthController;
    onOnboardingComplete: () => void;
  };

  let { auth, onOnboardingComplete }: Props = $props();
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
    onSubmit={(e) => auth.submitUnlock(e)}
    onSwitchAccount={() => auth.switchAccount()}
  />
{/if}

{#if auth.phase === "twoFactor"}
  <TwoFactorForm
    providers={auth.pendingProviders}
    bind:selectedProvider={auth.selectedProvider}
    bind:totpCode={auth.totpCode}
    bind:yubikeyOtp={auth.yubikeyOtp}
    onSubmit={(e) => auth.submitTwoFactor(e)}
    onCancel={() => auth.cancelTwoFactor()}
  />
{/if}
