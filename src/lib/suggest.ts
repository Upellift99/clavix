import type { CipherSummary } from "./types";
import { compareBy } from "./filter";

/**
 * The usernames already in the vault, offered as suggestions in the
 * editor's username fields. Only logins count (they are the only kind
 * whose summary carries one), and the trash does not: a username the
 * user threw away is not one to keep proposing. Archived items stay in,
 * since the account is usually still theirs.
 *
 * Most used first, so the address on half the vault is the first thing
 * offered; ties fall back to the list's own alphabetical order.
 */
export function usernameSuggestions(ciphers: CipherSummary[] | undefined): string[] {
  const counts = new Map<string, number>();
  for (const c of ciphers ?? []) {
    if (c.kind !== 1 || c.deletedDate !== null) continue;
    const u = c.username?.trim();
    if (!u) continue;
    counts.set(u, (counts.get(u) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort(([a, na], [b, nb]) => nb - na || compareBy(a, b))
    .map(([u]) => u);
}
