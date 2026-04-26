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

// ============ Bitwarden-format CSV export ============
//
// Matches the column set Bitwarden Desktop produces with File → Export
// vault → .csv, so the file imports cleanly back into Bitwarden if a
// user wants to migrate elsewhere. CSV only carries Login and
// SecureNote — Cards, Identities and SSH keys don't fit the Bitwarden
// CSV schema (the matching field columns aren't standardised) and
// would have to ship through the JSON export instead. We mirror that
// behaviour: the caller filters down to logins + notes before passing
// rows in here.

export type CsvExportRow = {
  /** Folder name, empty string for "no folder" / personal root. */
  folder: string;
  favorite: boolean;
  type: "login" | "note";
  name: string;
  notes: string;
  /** All login URIs; serialised newline-separated inside the quoted CSV cell. */
  loginUris: string[];
  loginUsername: string;
  loginPassword: string;
  loginTotp: string;
};

const BITWARDEN_HEADERS = [
  "folder",
  "favorite",
  "type",
  "name",
  "notes",
  "fields",
  "reprompt",
  "login_uri",
  "login_username",
  "login_password",
  "login_totp",
] as const;

/**
 * RFC 4180 escape: wrap in double-quotes when the cell contains a comma,
 * a quote, or a newline; double up any inner quote.
 */
export function escapeCsvField(value: string): string {
  if (
    value.includes(",") ||
    value.includes('"') ||
    value.includes("\n") ||
    value.includes("\r")
  ) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

/**
 * Serialise a list of cipher rows to the Bitwarden CSV dialect:
 * CRLF line endings, header row first, `fields`/`reprompt` columns
 * always empty / 0 (Clavix has no custom fields and no per-cipher
 * reprompt setting). Multiple URIs join with `\n` inside the
 * `login_uri` cell.
 */
export function serializeBitwardenCsv(rows: CsvExportRow[]): string {
  const lines: string[] = [BITWARDEN_HEADERS.join(",")];
  for (const row of rows) {
    const cells = [
      row.folder,
      row.favorite ? "1" : "0",
      row.type,
      row.name,
      row.notes,
      "", // fields (unsupported in Clavix)
      "0", // reprompt (unsupported in Clavix)
      row.loginUris.join("\n"),
      row.loginUsername,
      row.loginPassword,
      row.loginTotp,
    ].map(escapeCsvField);
    lines.push(cells.join(","));
  }
  return lines.join("\r\n") + "\r\n";
}
