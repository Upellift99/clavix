/**
 * Tiny RFC 4180-ish CSV parser. Handles:
 * - comma separator,
 * - double-quoted fields (with "" to escape a literal quote),
 * - commas and newlines inside quoted fields,
 * - optional trailing newline.
 *
 * Not for arbitrary CSV dialects — just enough to eat KeePassXC's export.
 */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;
  let i = 0;
  const n = text.length;

  while (i < n) {
    const ch = text[i];

    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i++;
        continue;
      }
      field += ch;
      i++;
      continue;
    }

    if (ch === '"') {
      inQuotes = true;
      i++;
      continue;
    }
    if (ch === ",") {
      row.push(field);
      field = "";
      i++;
      continue;
    }
    if (ch === "\n" || ch === "\r") {
      row.push(field);
      field = "";
      rows.push(row);
      row = [];
      if (ch === "\r" && text[i + 1] === "\n") i += 2;
      else i++;
      continue;
    }
    field += ch;
    i++;
  }

  // Flush trailing field / row (no newline at EOF).
  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }

  // Drop entirely-empty rows (they come from trailing newlines).
  return rows.filter((r) => r.some((c) => c.length > 0));
}

export type KeepassEntry = {
  group: string;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  totp: string;
};

/**
 * Map a parsed KeePassXC CSV to a list of login entries. The header line
 * is the source of truth for column positions — KeePassXC ships `TOTP`
 * only in recent versions and ordering may vary if the user tweaked
 * export settings.
 */
export function parseKeepassCsv(text: string): KeepassEntry[] {
  const rows = parseCsv(text);
  if (rows.length < 2) return [];

  const header = rows[0].map((h) => h.trim().toLowerCase());
  const idx = (name: string) => header.indexOf(name);
  const cols = {
    group: idx("group"),
    title: idx("title"),
    username: idx("username"),
    password: idx("password"),
    url: idx("url"),
    notes: idx("notes"),
    totp: idx("totp"),
  };

  if (cols.title < 0) {
    throw new Error(
      `CSV header missing "Title" column (got: ${header.join(", ")})`,
    );
  }

  const pick = (row: string[], i: number) => (i >= 0 ? (row[i] ?? "") : "");

  return rows.slice(1).map((row) => ({
    group: pick(row, cols.group).trim(),
    title: pick(row, cols.title).trim(),
    username: pick(row, cols.username),
    password: pick(row, cols.password),
    url: pick(row, cols.url).trim(),
    notes: pick(row, cols.notes),
    totp: pick(row, cols.totp).trim(),
  }));
}
