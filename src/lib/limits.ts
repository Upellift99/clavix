/**
 * Server-side size limits.
 *
 * Bitwarden — and Vaultwarden, which mirrors it — rejects any single
 * encrypted value longer than 10 000 characters. The cap applies to the
 * *EncString* (`2.<iv>|<ciphertext>|<mac>`, all base64), not to the
 * plaintext, so the real ceiling in typed characters is roughly 7 400.
 * That is what makes an armored PGP key block fail to import while
 * looking well under any limit the user can see.
 *
 * Vaultwarden can raise the cap to 100 000 with
 * `INCREASE_NOTE_SIZE_LIMIT=true`, at the cost of compatibility with
 * official Bitwarden servers and clients.
 */
export const MAX_ENCRYPTED_VALUE_LENGTH = 10_000;

const b64Len = (bytes: number) => 4 * Math.ceil(bytes / 3);

/**
 * Length of the EncString that encrypting `plaintext` produces, in
 * characters. AES-256-CBC with PKCS#7 always appends a padding block, so
 * even a 16-byte input grows to 32 bytes of ciphertext.
 */
export function encryptedLength(plaintext: string): number {
  const bytes = new TextEncoder().encode(plaintext).length;
  const ciphertext = Math.floor(bytes / 16) * 16 + 16;
  return (
    "2.".length + b64Len(16) + 1 + b64Len(ciphertext) + 1 + b64Len(32)
  );
}

/** Would the server reject this value for being too long once encrypted? */
export function exceedsEncryptedLimit(
  plaintext: string,
  limit: number = MAX_ENCRYPTED_VALUE_LENGTH,
): boolean {
  return plaintext.length > 0 && encryptedLength(plaintext) > limit;
}
