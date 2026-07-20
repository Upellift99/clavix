// @vitest-environment jsdom
import { beforeEach, describe, expect, it } from "vitest";

import { PrefsController } from "./prefs.svelte";

describe("sshAgentAutoStart", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("defaults to off", () => {
    const prefs = new PrefsController();
    prefs.bootstrap();
    expect(prefs.sshAgentAutoStart).toBe(false);
  });

  it("round-trips through localStorage", () => {
    const a = new PrefsController();
    a.setSshAgentAutoStart(true);
    expect(localStorage.getItem("clavix.sshAgentAutoStart")).toBe("true");

    const b = new PrefsController();
    b.bootstrap();
    expect(b.sshAgentAutoStart).toBe(true);
  });

  // The setting decides whether SSH keys get exposed on a socket without
  // the user asking, so anything short of an explicit "true" must leave
  // it off — a corrupted or half-written value must not opt someone in.
  it.each(["", "1", "yes", "TRUE", "null", "{}"])(
    "stays off for the non-true value %j",
    (stored) => {
      localStorage.setItem("clavix.sshAgentAutoStart", stored);
      const prefs = new PrefsController();
      prefs.bootstrap();
      expect(prefs.sshAgentAutoStart).toBe(false);
    },
  );

  it("can be turned back off", () => {
    const a = new PrefsController();
    a.setSshAgentAutoStart(true);
    a.setSshAgentAutoStart(false);

    const b = new PrefsController();
    b.bootstrap();
    expect(b.sshAgentAutoStart).toBe(false);
  });
});
