import { describe, expect, it } from "vitest";
import { isInlineEditable, provisionalDetail } from "./detail";
import type { CipherSummary } from "./types";

const row: CipherSummary = {
  id: "c1",
  kind: 1,
  name: "Proxmox VE",
  folderId: "f-serveurs",
  organizationId: null,
  collectionIds: [],
  favorite: true,
  primaryUri: "https://pve.example.net:8006",
  username: "root@pam",
  revisionDate: "2026-09-12T10:21:00Z",
  deletedDate: null,
  archivedDate: null,
};

describe("provisionalDetail", () => {
  it("carries everything the list row knows", () => {
    const d = provisionalDetail(row);
    expect(d.id).toBe("c1");
    expect(d.name).toBe("Proxmox VE");
    expect(d.folderId).toBe("f-serveurs");
    expect(d.favorite).toBe(true);
    expect(d.login).toEqual({
      username: "root@pam",
      hasPassword: true,
      uris: ["https://pve.example.net:8006"],
      hasTotp: false,
    });
  });

  it("starts the unknown sections empty rather than inventing them", () => {
    const d = provisionalDetail(row);
    expect(d.fields).toEqual([]);
    expect(d.attachments).toEqual([]);
    expect(d.passwordHistoryCount).toBe(0);
    expect(d.reprompt).toBe(false);
    expect(d.notes).toBeNull();
  });

  it("gives a note no login block", () => {
    const d = provisionalDetail({ ...row, kind: 2, username: null, primaryUri: null });
    expect(d.login).toBeNull();
    expect(d.card).toBeNull();
  });
});

describe("isInlineEditable", () => {
  it("accepts logins and notes, sends the rest to the dialog", () => {
    expect(isInlineEditable(1)).toBe(true);
    expect(isInlineEditable(2)).toBe(true);
    expect(isInlineEditable(3)).toBe(false);
    expect(isInlineEditable(4)).toBe(false);
    expect(isInlineEditable(5)).toBe(false);
  });
});
