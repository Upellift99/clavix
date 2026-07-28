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

describe("auto-lock", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("defaults to a 10 min idle window", () => {
    const prefs = new PrefsController();
    prefs.bootstrap();
    expect(prefs.autoLockTrigger).toBe("idle");
    expect(prefs.autoLockMinutes).toBe(10);
  });

  it("round-trips a screen-lock delay through localStorage", () => {
    const a = new PrefsController();
    a.setAutoLock("screenLock", 60);
    expect(localStorage.getItem("clavix.autoLockTrigger")).toBe("screenLock");
    expect(localStorage.getItem("clavix.autoLockMinutes")).toBe("60");

    const b = new PrefsController();
    b.bootstrap();
    expect(b.autoLockTrigger).toBe("screenLock");
    expect(b.autoLockMinutes).toBe(60);
  });

  // "Immediately" is 0 minutes, which under the old minutes-only encoding
  // meant "Jamais". The trigger key is what disambiguates them, so a
  // stored screenLock:0 must survive a reload as an immediate lock and
  // not be read back as the vault never locking at all.
  it("keeps an immediate screen-lock from decaying into never", () => {
    const a = new PrefsController();
    a.setAutoLock("screenLock", 0);

    const b = new PrefsController();
    b.bootstrap();
    expect(b.autoLockTrigger).toBe("screenLock");
    expect(b.autoLockMinutes).toBe(0);
  });

  // Pre-0.14 installs — and the E2E lock helper — write only the minutes
  // key. Reconstruct the meaning it had then rather than falling back to
  // the default window, which would silently change someone's setting.
  it("migrates a legacy minutes-only value to the idle trigger", () => {
    localStorage.setItem("clavix.autoLockMinutes", "5");
    const prefs = new PrefsController();
    prefs.bootstrap();
    expect(prefs.autoLockTrigger).toBe("idle");
    expect(prefs.autoLockMinutes).toBe(5);
  });

  it("migrates a legacy zero to never, not to an instant lock", () => {
    localStorage.setItem("clavix.autoLockMinutes", "0");
    const prefs = new PrefsController();
    prefs.bootstrap();
    expect(prefs.autoLockTrigger).toBe("off");
    expect(prefs.autoLockMinutes).toBe(0);
  });

  // A garbled trigger must not be trusted into a mode the user never
  // picked — fall back to the legacy derivation, same as if it were absent.
  it.each(["", "screenlock", "Idle", "null", "{}"])(
    "ignores the malformed trigger %j",
    (stored) => {
      localStorage.setItem("clavix.autoLockTrigger", stored);
      localStorage.setItem("clavix.autoLockMinutes", "15");
      const prefs = new PrefsController();
      prefs.bootstrap();
      expect(prefs.autoLockTrigger).toBe("idle");
      expect(prefs.autoLockMinutes).toBe(15);
    },
  );
});
