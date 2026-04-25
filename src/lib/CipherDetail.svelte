<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import TotpField from "./TotpField.svelte";
  import { cipherTypeLabel, mask } from "./format";
  import type { CipherDetail, CipherSummary, OrganizationSummary } from "./types";

  type Props = {
    detail: CipherDetail;
    summaryEntry: CipherSummary | null;
    organizations: OrganizationSummary[];
    onCopy: (value: string, label: string) => Promise<void> | void;
    onClose: () => void;
    onEdit: () => void;
    onRestore: (id: string) => void;
    onSoftDelete: (id: string) => void;
    onDeleteForever: (id: string) => void;
  };

  let {
    detail,
    summaryEntry,
    organizations,
    onCopy,
    onClose,
    onEdit,
    onRestore,
    onSoftDelete,
    onDeleteForever,
  }: Props = $props();

  let showPassword = $state(false);
  let showCardNumber = $state(false);
  let showCardCode = $state(false);
  let showSsn = $state(false);
  let showSshPrivate = $state(false);

  $effect(() => {
    void detail.id;
    showPassword = false;
    showCardNumber = false;
    showCardCode = false;
    showSsn = false;
    showSshPrivate = false;
  });

  const isDeleted = $derived(summaryEntry?.deletedDate ?? null);
  const orgName = $derived(
    detail.organizationId
      ? (organizations.find((o) => o.id === detail.organizationId)?.name ?? "?")
      : null,
  );
</script>

<section class="box cipher-detail">
  <header class="detail-header">
    <div>
      <span class="badge">{cipherTypeLabel(detail.kind)}</span>
      <h2>{detail.name}</h2>
    </div>
    <div class="row">
      {#if isDeleted}
        <button type="button" class="secondary small" onclick={() => onRestore(detail.id)}>
          {m.action_restore()}
        </button>
        <button type="button" class="small" onclick={() => onDeleteForever(detail.id)}>
          {m.action_delete_forever()}
        </button>
      {:else}
        <button type="button" class="secondary small" onclick={onEdit}>
          {m.action_edit()}
        </button>
        <button type="button" class="secondary small" onclick={() => onSoftDelete(detail.id)}>
          {m.action_soft_delete()}
        </button>
      {/if}
      <button type="button" class="secondary small" onclick={onClose}>{m.action_close()}</button>
    </div>
  </header>

  {#if detail.login}
    {#if detail.login.username}
      <dl class="detail-field">
        <dt>Identifiant</dt>
        <dd>
          <code>{detail.login.username}</code>
          <button
            type="button"
            class="secondary small"
            onclick={() => onCopy(detail.login!.username!, "identifiant")}
          >
            Copier
          </button>
        </dd>
      </dl>
    {/if}

    {#if detail.login.password}
      <dl class="detail-field">
        <dt>Mot de passe</dt>
        <dd>
          <code class="password">
            {showPassword
              ? detail.login.password
              : "•".repeat(Math.min(detail.login.password.length, 16))}
          </code>
          <button
            type="button"
            class="secondary small"
            onclick={() => (showPassword = !showPassword)}
          >
            {showPassword ? "Masquer" : "Afficher"}
          </button>
          <button
            type="button"
            class="small"
            onclick={() => onCopy(detail.login!.password!, "mot de passe")}
          >
            Copier
          </button>
        </dd>
      </dl>
    {/if}

    {#if detail.login.uris.length > 0}
      <dl class="detail-field">
        <dt>URL{detail.login.uris.length > 1 ? "s" : ""}</dt>
        <dd>
          <ul class="uri-list">
            {#each detail.login.uris as u}
              <li><code>{u}</code></li>
            {/each}
          </ul>
        </dd>
      </dl>
    {/if}

    {#if detail.login.totp}
      <dl class="detail-field">
        <dt>{m.detail_field_totp()}</dt>
        <dd>
          <TotpField
            source={detail.login.totp}
            onCopy={(code) => onCopy(code, m.detail_field_totp())}
          />
        </dd>
      </dl>
    {/if}
  {/if}

  {#if detail.card}
    {#if detail.card.cardholderName}
      <dl class="detail-field">
        <dt>Titulaire</dt>
        <dd>
          <code>{detail.card.cardholderName}</code>
          <button
            type="button"
            class="secondary small"
            onclick={() => onCopy(detail.card!.cardholderName!, "titulaire")}
          >
            Copier
          </button>
        </dd>
      </dl>
    {/if}
    {#if detail.card.brand}
      <dl class="detail-field">
        <dt>Réseau</dt>
        <dd>{detail.card.brand}</dd>
      </dl>
    {/if}
    {#if detail.card.number}
      <dl class="detail-field">
        <dt>Numéro</dt>
        <dd>
          <code>{showCardNumber ? detail.card.number : mask(detail.card.number, 16)}</code>
          <button
            type="button"
            class="secondary small"
            onclick={() => (showCardNumber = !showCardNumber)}
          >
            {showCardNumber ? "Masquer" : "Afficher"}
          </button>
          <button
            type="button"
            class="small"
            onclick={() => onCopy(detail.card!.number!, "numéro de carte")}
          >
            Copier
          </button>
        </dd>
      </dl>
    {/if}
    {#if detail.card.expMonth || detail.card.expYear}
      <dl class="detail-field">
        <dt>Expiration</dt>
        <dd>
          {detail.card.expMonth ?? "?"} / {detail.card.expYear ?? "?"}
        </dd>
      </dl>
    {/if}
    {#if detail.card.code}
      <dl class="detail-field">
        <dt>CVV</dt>
        <dd>
          <code>{showCardCode ? detail.card.code : mask(detail.card.code, 3)}</code>
          <button
            type="button"
            class="secondary small"
            onclick={() => (showCardCode = !showCardCode)}
          >
            {showCardCode ? "Masquer" : "Afficher"}
          </button>
          <button
            type="button"
            class="small"
            onclick={() => onCopy(detail.card!.code!, "CVV")}
          >
            Copier
          </button>
        </dd>
      </dl>
    {/if}
  {/if}

  {#if detail.identity}
    {@const identityFields = [
      ["Titre", detail.identity.title],
      ["Prénom", detail.identity.firstName],
      ["Deuxième prénom", detail.identity.middleName],
      ["Nom", detail.identity.lastName],
      ["Entreprise", detail.identity.company],
      ["Adresse 1", detail.identity.address1],
      ["Adresse 2", detail.identity.address2],
      ["Adresse 3", detail.identity.address3],
      ["Ville", detail.identity.city],
      ["Département/État", detail.identity.state],
      ["Code postal", detail.identity.postalCode],
      ["Pays", detail.identity.country],
      ["Email", detail.identity.email],
      ["Téléphone", detail.identity.phone],
      ["Identifiant", detail.identity.username],
      ["N° passeport", detail.identity.passportNumber],
      ["N° permis", detail.identity.licenseNumber],
    ] as Array<[string, string | null]>}
    {#each identityFields as [label, value]}
      {#if value}
        <dl class="detail-field">
          <dt>{label}</dt>
          <dd>
            <code>{value}</code>
            <button
              type="button"
              class="secondary small"
              onclick={() => onCopy(value, label.toLowerCase())}
            >
              Copier
            </button>
          </dd>
        </dl>
      {/if}
    {/each}
    {#if detail.identity.ssn}
      <dl class="detail-field">
        <dt>NIR / SSN</dt>
        <dd>
          <code>{showSsn ? detail.identity.ssn : mask(detail.identity.ssn, 11)}</code>
          <button
            type="button"
            class="secondary small"
            onclick={() => (showSsn = !showSsn)}
          >
            {showSsn ? "Masquer" : "Afficher"}
          </button>
          <button
            type="button"
            class="small"
            onclick={() => onCopy(detail.identity!.ssn!, "NIR")}
          >
            Copier
          </button>
        </dd>
      </dl>
    {/if}
  {/if}

  {#if detail.sshKey}
    {#if detail.sshKey.keyFingerprint}
      <dl class="detail-field">
        <dt>Empreinte</dt>
        <dd>
          <code>{detail.sshKey.keyFingerprint}</code>
          <button
            type="button"
            class="secondary small"
            onclick={() => onCopy(detail.sshKey!.keyFingerprint!, "empreinte")}
          >
            Copier
          </button>
        </dd>
      </dl>
    {/if}
    {#if detail.sshKey.publicKey}
      <dl class="detail-field">
        <dt>Clé publique</dt>
        <dd>
          <code class="ssh-key">{detail.sshKey.publicKey}</code>
          <button
            type="button"
            class="secondary small"
            onclick={() => onCopy(detail.sshKey!.publicKey!, "clé publique")}
          >
            Copier
          </button>
        </dd>
      </dl>
    {/if}
    {#if detail.sshKey.privateKey}
      <dl class="detail-field">
        <dt>Clé privée</dt>
        <dd>
          {#if showSshPrivate}
            <code class="ssh-key">{detail.sshKey.privateKey}</code>
          {:else}
            <code>••••••• (masquée)</code>
          {/if}
          <button
            type="button"
            class="secondary small"
            onclick={() => (showSshPrivate = !showSshPrivate)}
          >
            {showSshPrivate ? "Masquer" : "Afficher"}
          </button>
          <button
            type="button"
            class="small"
            onclick={() => onCopy(detail.sshKey!.privateKey!, "clé privée")}
          >
            Copier
          </button>
        </dd>
      </dl>
    {/if}
  {/if}

  {#if detail.notes}
    <dl class="detail-field">
      <dt>Notes</dt>
      <dd class="notes">{detail.notes}</dd>
    </dl>
  {/if}

  <p class="hint detail-footer">
    Item #{detail.id.slice(0, 8)}
    {#if orgName}
      · Organisation : {orgName}
    {/if}
  </p>
</section>
