import { normalizeForSearch } from "./filter";

/**
 * Identity of an entry for re-import purposes: name + username, both
 * normalised (case- and accent-insensitive, trimmed).
 *
 * Deliberately ignores password, notes and URL. Re-running the same
 * KeePassXC file must not duplicate what is already in the vault, and must
 * not overwrite an item the user has edited since importing it — matching
 * on the mutable fields would do exactly that. Name + username is also what
 * makes an entry recognisable to a human.
 */
export function importIdentity(name: string, username: string): string {
  return `${normalizeForSearch(name.trim())}\n${normalizeForSearch(username.trim())}`;
}
