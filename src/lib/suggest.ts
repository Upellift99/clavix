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

/** How many suggestions the editor shows at once. */
export const MAX_SUGGESTIONS = 8;

/**
 * The suggestions worth showing for what is typed so far: case-insensitive,
 * entries that start with the text first, then those that merely contain
 * it, each group keeping the incoming (most used first) order. An entry
 * equal to the text is left out, there is nothing left to complete.
 * Empty text offers the head of the list.
 */
export function matchSuggestions(all: string[], typed: string, max = MAX_SUGGESTIONS): string[] {
  const q = typed.trim().toLowerCase();
  if (!q) return all.slice(0, max);
  const starts: string[] = [];
  const contains: string[] = [];
  for (const s of all) {
    const l = s.toLowerCase();
    if (l === q) continue;
    if (l.startsWith(q)) starts.push(s);
    else if (l.includes(q)) contains.push(s);
  }
  return [...starts, ...contains].slice(0, max);
}
