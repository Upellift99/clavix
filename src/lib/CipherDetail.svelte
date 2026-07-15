<script lang="ts">
  import * as m from "$lib/paraglide/messages";
  import Icon from "./Icon.svelte";
  import TotpField from "./TotpField.svelte";
  import { api } from "./api";
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

  // Secret fields are no longer in `detail`; they're fetched on demand and held
  // only while revealed. `revealed[field]` caches the fetched value for the
  // currently open item; wiped whenever the item changes.
  let revealed = $state<Record<string, string>>({});

  async function revealValue(field: string): Promise<string> {
    if (revealed[field] === undefined) {
      revealed = { ...revealed, [field]: (await api.revealField(detail.id, field)) ?? "" };
    }
    return revealed[field];
  }

  /** Copy a secret field, fetching it first if needed (kept out of long-lived
      state — only touched transiently for the copy). */
  async function copyField(field: string, label: string) {
    const value = await revealValue(field);
    if (value) await onCopy(value, label);
  }

  $effect(() => {
    void detail.id;
    showPassword = false;
    showCardNumber = false;
    showCardCode = false;
    showSsn = false;
    showSshPrivate = false;
    revealed = {};
  });

  const isDeleted = $derived(summaryEntry?.deletedDate ?? null);
  const orgName = $derived(
    detail.organizationId
      ? (organizations.find((o) => o.id === detail.organizationId)?.name ?? "?")
      : null,
  );

  /**
   * Classify a single character of a revealed password so the CSS can
   * paint digits / letters / symbols differently. Same trick KeePassXC
   * uses to make a typed-out password readable: a quick visual scan
   * tells you "1" from "l" or "0" from "O" without staring.
   */
  function charClass(ch: string): string {
    if (/\d/.test(ch)) return "ch-digit";
    if (/[a-zA-Z]/.test(ch)) return "ch-letter";
    return "ch-symbol";
  }

  // Identity is presented as a flat list — it has no obvious sub-
  // grouping ("address" vs "phone" vs "ID numbers" would all be
  // single-line groups so the layout would be more headers than data).
  // The optional fields are filtered out at render time.
  const identityRows = $derived.by<Array<[string, string | null]>>(() => {
    const id = detail.identity;
    if (!id) return [];
    return [
      ["Titre", id.title],
      ["Prénom", id.firstName],
      ["Deuxième prénom", id.middleName],
      ["Nom", id.lastName],
      ["Entreprise", id.company],
      ["Adresse 1", id.address1],
      ["Adresse 2", id.address2],
      ["Adresse 3", id.address3],
      ["Ville", id.city],
      ["Département/État", id.state],
      ["Code postal", id.postalCode],
      ["Pays", id.country],
      ["Email", id.email],
      ["Téléphone", id.phone],
      ["Identifiant", id.username],
      ["N° passeport", id.passportNumber],
      ["N° permis", id.licenseNumber],
    ];
  });
</script>

<!--
  A "field" snippet renders the canonical { label, value, copy } row.
  The toggle-secret variant adds the show/hide eye toggle and a
  customizable masked rendering. Both share the same grid so labels
  always align across the panel — irrespective of which sections are
  populated for the current cipher type.
-->

{#snippet plainField(label: string, value: string, copyAs?: string)}
  <div class="detail-field" role="group">
    <dt>{label}</dt>
    <dd>
      <code class="value">{value}</code>
      <button
        type="button"
        class="icon-btn"
        title={m.action_copy()}
        aria-label={m.action_copy()}
        onclick={() => onCopy(value, copyAs ?? label.toLowerCase())}
      >
        <Icon name="copy" size={14} />
      </button>
    </dd>
  </div>
{/snippet}

{#snippet secretField(
  label: string,
  value: string,
  shown: boolean,
  toggle: () => void,
  copyAs: string,
  options?: { masked?: string; renderShown?: "default" | "password" | "ssh" }
)}
  <div class="detail-field" role="group">
    <dt>{label}</dt>
    <dd>
      {#if shown && options?.renderShown === "password"}
        <code class="value password">
          {#each [...value] as ch}<span class={charClass(ch)}>{ch}</span>{/each}
        </code>
      {:else if shown && options?.renderShown === "ssh"}
        <code class="value ssh-key">{value}</code>
      {:else if shown}
        <code class="value">{value}</code>
      {:else}
        <code class="value">{options?.masked ?? "•".repeat(Math.min(value.length, 16))}</code>
      {/if}
      <button
        type="button"
        class="icon-btn"
        title={shown ? m.action_hide_value() : m.action_show()}
        aria-label={shown ? m.action_hide_value() : m.action_show()}
        onclick={toggle}
      >
        <Icon name={shown ? "eye-off" : "eye"} size={14} />
      </button>
      <button
        type="button"
        class="icon-btn primary"
        title={m.action_copy()}
        aria-label={m.action_copy()}
        onclick={() => onCopy(value, copyAs)}
      >
        <Icon name="copy" size={14} />
      </button>
    </dd>
  </div>
{/snippet}

<section class="box cipher-detail">
  <header class="detail-header">
    <div class="detail-title">
      <span class="badge">{cipherTypeLabel(detail.kind)}</span>
      <h2>{detail.name}</h2>
    </div>
    <div class="row">
      {#if isDeleted}
        <button type="button" class="secondary small" onclick={() => onRestore(detail.id)}>
          {m.action_restore()}
        </button>
        <button type="button" class="small danger" onclick={() => onDeleteForever(detail.id)}>
          {m.action_delete_forever()}
        </button>
      {:else}
        <button type="button" class="secondary small" onclick={onEdit}>
          <Icon name="edit" size={14} />
          {m.action_edit()}
        </button>
        <button type="button" class="secondary small" onclick={() => onSoftDelete(detail.id)}>
          <Icon name="trash" size={14} />
          {m.action_soft_delete()}
        </button>
      {/if}
      <button
        type="button"
        class="icon-btn"
        title={m.action_close()}
        aria-label={m.action_close()}
        onclick={onClose}
      >
        <Icon name="x" size={16} />
      </button>
    </div>
  </header>

  {#if detail.login && (detail.login.username || detail.login.password)}
    <section class="detail-section">
      <h3 class="detail-section-title">{m.detail_section_credentials()}</h3>
      {#if detail.login.username}
        {@render plainField(m.detail_field_username(), detail.login.username, "identifiant")}
      {/if}
      {#if detail.login.password}
        {@render secretField(
          m.detail_field_password(),
          detail.login.password,
          showPassword,
          () => (showPassword = !showPassword),
          "mot de passe",
          { renderShown: "password" }
        )}
      {/if}
    </section>
  {/if}

  {#if detail.login && detail.login.uris.length > 0}
    <section class="detail-section">
      <h3 class="detail-section-title">
        {detail.login.uris.length > 1 ? m.detail_field_url_many() : m.detail_field_url_one()}
      </h3>
      <ul class="uri-list">
        {#each detail.login.uris as u}
          <li>
            <code class="value">{u}</code>
            <button
              type="button"
              class="icon-btn"
              title={m.action_copy()}
              aria-label={m.action_copy()}
              onclick={() => onCopy(u, "URL")}
            >
              <Icon name="copy" size={14} />
            </button>
          </li>
        {/each}
      </ul>
    </section>
  {/if}

  {#if detail.login?.totp}
    <section class="detail-section">
      <h3 class="detail-section-title">{m.detail_section_security()}</h3>
      <div class="detail-field" role="group">
        <dt>{m.detail_field_totp()}</dt>
        <dd>
          <TotpField
            source={detail.login.totp}
            onCopy={(code) => onCopy(code, m.detail_field_totp())}
          />
        </dd>
      </div>
    </section>
  {/if}

  {#if detail.card}
    <section class="detail-section">
      <h3 class="detail-section-title">{m.detail_section_card()}</h3>
      {#if detail.card.cardholderName}
        {@render plainField(m.detail_field_cardholder(), detail.card.cardholderName, "titulaire")}
      {/if}
      {#if detail.card.brand}
        <div class="detail-field" role="group">
          <dt>{m.detail_field_brand()}</dt>
          <dd><span class="value">{detail.card.brand}</span></dd>
        </div>
      {/if}
      {#if detail.card.number}
        {@render secretField(
          m.detail_field_number(),
          detail.card.number,
          showCardNumber,
          () => (showCardNumber = !showCardNumber),
          "numéro de carte",
          { masked: mask(detail.card.number, 16) }
        )}
      {/if}
      {#if detail.card.expMonth || detail.card.expYear}
        <div class="detail-field" role="group">
          <dt>{m.detail_field_expiry()}</dt>
          <dd>
            <span class="value">
              {detail.card.expMonth ?? "?"} / {detail.card.expYear ?? "?"}
            </span>
          </dd>
        </div>
      {/if}
      {#if detail.card.code}
        {@render secretField(
          m.detail_field_cvv(),
          detail.card.code,
          showCardCode,
          () => (showCardCode = !showCardCode),
          "CVV",
          { masked: mask(detail.card.code, 3) }
        )}
      {/if}
    </section>
  {/if}

  {#if detail.identity}
    <section class="detail-section">
      <h3 class="detail-section-title">{m.detail_section_identity()}</h3>
      {#each identityRows as [label, value]}
        {#if value}
          {@render plainField(label, value)}
        {/if}
      {/each}
      {#if detail.identity.ssn}
        {@render secretField(
          m.detail_field_ssn(),
          detail.identity.ssn,
          showSsn,
          () => (showSsn = !showSsn),
          "NIR",
          { masked: mask(detail.identity.ssn, 11) }
        )}
      {/if}
    </section>
  {/if}

  {#if detail.sshKey}
    <section class="detail-section">
      <h3 class="detail-section-title">{m.detail_section_ssh()}</h3>
      {#if detail.sshKey.keyFingerprint}
        {@render plainField(m.detail_field_fingerprint(), detail.sshKey.keyFingerprint, "empreinte")}
      {/if}
      {#if detail.sshKey.publicKey}
        <div class="detail-field" role="group">
          <dt>{m.detail_field_public_key()}</dt>
          <dd>
            <code class="value ssh-key">{detail.sshKey.publicKey}</code>
            <button
              type="button"
              class="icon-btn"
              title={m.action_copy()}
              aria-label={m.action_copy()}
              onclick={() => onCopy(detail.sshKey!.publicKey!, "clé publique")}
            >
              <Icon name="copy" size={14} />
            </button>
          </dd>
        </div>
      {/if}
      {#if detail.sshKey.hasPrivateKey}
        <div class="detail-field" role="group">
          <dt>{m.detail_field_private_key()}</dt>
          <dd>
            {#if showSshPrivate}
              <code class="value ssh-key">{revealed["sshPrivateKey"] ?? ""}</code>
            {:else}
              <code class="value">{m.detail_field_private_key_hidden()}</code>
            {/if}
            <button
              type="button"
              class="icon-btn"
              title={showSshPrivate ? m.action_hide_value() : m.action_show()}
              aria-label={showSshPrivate ? m.action_hide_value() : m.action_show()}
              onclick={async () => {
                if (!showSshPrivate) await revealValue("sshPrivateKey");
                showSshPrivate = !showSshPrivate;
              }}
            >
              <Icon name={showSshPrivate ? "eye-off" : "eye"} size={14} />
            </button>
            <button
              type="button"
              class="icon-btn primary"
              title={m.action_copy()}
              aria-label={m.action_copy()}
              onclick={() => copyField("sshPrivateKey", "clé privée")}
            >
              <Icon name="copy" size={14} />
            </button>
          </dd>
        </div>
      {/if}
    </section>
  {/if}

  {#if detail.notes}
    <section class="detail-section">
      <h3 class="detail-section-title">{m.detail_section_notes()}</h3>
      <p class="notes">{detail.notes}</p>
    </section>
  {/if}

  <p class="hint detail-footer">
    {m.detail_item_id({ id: detail.id.slice(0, 8) })}
    {#if orgName}
      · {m.detail_organization({ name: orgName })}
    {/if}
  </p>
</section>
