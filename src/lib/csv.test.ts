import { describe, expect, it } from "vitest";
import { escapeCsvField, parseCsv, serializeBitwardenCsv, type CsvExportRow } from "./csv";

describe("escapeCsvField", () => {
  it("leaves trivial values untouched", () => {
    expect(escapeCsvField("hello")).toBe("hello");
    expect(escapeCsvField("")).toBe("");
    expect(escapeCsvField("alice@example.com")).toBe("alice@example.com");
  });

  it("quotes commas, quotes, CR and LF", () => {
    expect(escapeCsvField("a,b")).toBe('"a,b"');
    expect(escapeCsvField('he said "hi"')).toBe('"he said ""hi"""');
    expect(escapeCsvField("line1\nline2")).toBe('"line1\nline2"');
    expect(escapeCsvField("line1\r\nline2")).toBe('"line1\r\nline2"');
  });
});

function emptyRow(over: Partial<CsvExportRow>): CsvExportRow {
  return {
    folder: "",
    favorite: false,
    type: "login",
    name: "",
    notes: "",
    loginUris: [],
    loginUsername: "",
    loginPassword: "",
    loginTotp: "",
    ...over,
  };
}

describe("serializeBitwardenCsv", () => {
  it("emits the Bitwarden header on its own line", () => {
    const out = serializeBitwardenCsv([]);
    expect(out).toBe(
      "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\r\n",
    );
  });

  it("serialises a plain login with no quoting needed", () => {
    const out = serializeBitwardenCsv([
      emptyRow({
        type: "login",
        name: "Twitter",
        loginUris: ["https://twitter.com"],
        loginUsername: "alice",
        loginPassword: "p4ss",
      }),
    ]);
    const lines = out.split("\r\n");
    expect(lines[1]).toBe(",0,login,Twitter,,,0,https://twitter.com,alice,p4ss,");
    // Trailing CRLF after the last data row.
    expect(lines[2]).toBe("");
    expect(lines).toHaveLength(3);
  });

  it("flips favorite to 1 and preserves folder + notes", () => {
    const out = serializeBitwardenCsv([
      emptyRow({
        folder: "Work",
        favorite: true,
        type: "note",
        name: "API keys",
        notes: "rotate every 90 days",
      }),
    ]);
    expect(out).toContain("Work,1,note,API keys,rotate every 90 days,,0,,,,");
  });

  it("CSV-escapes commas and quotes inside fields", () => {
    const out = serializeBitwardenCsv([
      emptyRow({
        name: 'A name, with "quotes"',
        notes: "comma, and\nnewline",
      }),
    ]);
    expect(out).toContain('"A name, with ""quotes"""');
    expect(out).toContain('"comma, and\nnewline"');
  });

  it("joins multiple URIs with a newline inside one cell", () => {
    const out = serializeBitwardenCsv([
      emptyRow({
        type: "login",
        name: "Multi",
        loginUris: ["https://a.test", "https://b.test"],
      }),
    ]);
    // Joined cell contains a newline → must be wrapped in quotes by escapeCsvField.
    expect(out).toContain('"https://a.test\nhttps://b.test"');
  });

  it("round-trips through parseCsv into the same cell values", () => {
    const rows = [
      emptyRow({
        folder: "Personal",
        favorite: true,
        type: "login",
        name: 'Edge, "Case"',
        notes: "line1\nline2",
        loginUris: ["https://a.test", "https://b.test"],
        loginUsername: "user",
        loginPassword: "pw",
        loginTotp: "JBSWY3DPEHPK3PXP",
      }),
    ];
    const csv = serializeBitwardenCsv(rows);
    const parsed = parseCsv(csv);

    // Header row + 1 data row.
    expect(parsed).toHaveLength(2);
    const data = parsed[1];
    expect(data[0]).toBe("Personal");
    expect(data[1]).toBe("1");
    expect(data[2]).toBe("login");
    expect(data[3]).toBe('Edge, "Case"');
    expect(data[4]).toBe("line1\nline2");
    expect(data[7]).toBe("https://a.test\nhttps://b.test");
    expect(data[8]).toBe("user");
    expect(data[9]).toBe("pw");
    expect(data[10]).toBe("JBSWY3DPEHPK3PXP");
  });
});
