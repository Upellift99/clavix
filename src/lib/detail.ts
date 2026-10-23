import type { CipherDetail, CipherSummary } from "./types";

/**
 * A detail the panel can show the instant a row is clicked, built from
 * what the list already knows. Everything the summary carries is final
 * (name, type, place, username, first URL); everything it cannot know is
 * given the value that renders as "loading" rather than "absent": a
 * login is assumed to have a password until the real detail says
 * otherwise, and the sections that only the decrypted item can reveal
 * (TOTP, custom fields, attachments, history, reprompt) start empty.
 *
 * `openCipher` swaps this for the real detail when decryption lands,
 * so nothing here is ever trusted for a copy or a reveal.
 */
export function provisionalDetail(summary: CipherSummary): CipherDetail {
  return {
    id: summary.id,
    kind: summary.kind,
    name: summary.name,
    notes: null,
    organizationId: summary.organizationId,
    folderId: summary.folderId,
    collectionIds: summary.collectionIds,
    revisionDate: summary.revisionDate,
    favorite: summary.favorite,
    login:
      summary.kind === 1
        ? {
            username: summary.username,
            hasPassword: true,
            uris: summary.primaryUri ? [summary.primaryUri] : [],
            hasTotp: false,
          }
        : null,
    card: null,
    identity: null,
    sshKey: null,
    fields: [],
    passwordHistoryCount: 0,
    attachments: [],
    reprompt: false,
  };
}

/** Item kinds the detail column can edit in place; the rest take the dialog. */
export function isInlineEditable(kind: number): boolean {
  return kind === 1 || kind === 2;
}
