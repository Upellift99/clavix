// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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

describe("auto-sync", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("defaults to every 30 min", () => {
    const prefs = new PrefsController();
    prefs.bootstrap();
    expect(prefs.autoSyncMinutes).toBe(30);
  });

  it("round-trips through localStorage", () => {
    const a = new PrefsController();
    a.setAutoSyncMinutes(5);
    expect(localStorage.getItem("clavix.autoSyncMinutes")).toBe("5");

    const b = new PrefsController();
    b.bootstrap();
    expect(b.autoSyncMinutes).toBe(5);
  });

  // Zero is a real choice ("Jamais"), not a missing value: it must
  // survive a reload instead of being read back as the 30 min default.
  it("keeps an explicit zero as off", () => {
    const a = new PrefsController();
    a.setAutoSyncMinutes(0);

    const b = new PrefsController();
    b.bootstrap();
    expect(b.autoSyncMinutes).toBe(0);
  });

  // A garbled or negative value would either disable the timer behind
  // the user's back or make it fire on every poll — keep the default.
  it.each(["", "soon", "-5", "null", "{}", "NaN"])(
    "falls back to the default for the malformed value %j",
    (stored) => {
      localStorage.setItem("clavix.autoSyncMinutes", stored);
      const prefs = new PrefsController();
      prefs.bootstrap();
      expect(prefs.autoSyncMinutes).toBe(30);
    },
  );
});

describe("toolbar alignment", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("defaults to left", () => {
    const prefs = new PrefsController();
    prefs.bootstrap();
    expect(prefs.toolbarAlign).toBe("left");
  });

  it("round-trips through localStorage", () => {
    const a = new PrefsController();
    a.setToolbarAlign("center");
    expect(localStorage.getItem("clavix.toolbarAlign")).toBe("center");

    const b = new PrefsController();
    b.bootstrap();
    expect(b.toolbarAlign).toBe("center");
  });

  it.each(["", "centre", "Center", "right", "{}"])(
    "ignores the unknown value %j",
    (stored) => {
      localStorage.setItem("clavix.toolbarAlign", stored);
      const prefs = new PrefsController();
      prefs.bootstrap();
      expect(prefs.toolbarAlign).toBe("left");
    },
  );
});

describe("document language", () => {
  beforeEach(() => {
    localStorage.clear();
    document.documentElement.lang = "en";
  });

  it("follows a saved French locale", () => {
    localStorage.setItem("clavix.locale", "fr");
    new PrefsController().bootstrap();
    expect(document.documentElement.lang).toBe("fr");
  });

  it("follows a locale change", () => {
    const prefs = new PrefsController();
    prefs.applyLocale("fr");
    expect(document.documentElement.lang).toBe("fr");
    prefs.applyLocale("en");
    expect(document.documentElement.lang).toBe("en");
  });
});

describe("blurNotes", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("defaults to on", () => {
    const prefs = new PrefsController();
    prefs.bootstrap();
    expect(prefs.blurNotes).toBe(true);
  });

  it("turns off only on an explicit false", () => {
    const a = new PrefsController();
    a.setBlurNotes(false);
    const b = new PrefsController();
    b.bootstrap();
    expect(b.blurNotes).toBe(false);
  });

  // A protection that is on by default must not be switched off by a
  // corrupted value.
  it.each(["", "0", "no", "FALSE", "null"])("stays on for a stored %j", (stored) => {
    localStorage.setItem("clavix.blurNotes", stored);
    const prefs = new PrefsController();
    prefs.bootstrap();
    expect(prefs.blurNotes).toBe(true);
  });
});

describe("searchNotes", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("defaults to on", () => {
    const prefs = new PrefsController();
    prefs.bootstrap();
    expect(prefs.searchNotes).toBe(true);
  });

  it("turns off only on an explicit false", () => {
    const a = new PrefsController();
    a.setSearchNotes(false);
    const b = new PrefsController();
    b.bootstrap();
    expect(b.searchNotes).toBe(false);
  });

  it.each(["", "0", "no", "FALSE", "null"])("stays on for a stored %j", (stored) => {
    localStorage.setItem("clavix.searchNotes", stored);
    const prefs = new PrefsController();
    prefs.bootstrap();
    expect(prefs.searchNotes).toBe(true);
  });
});

describe("locale", () => {
  beforeEach(() => {
    localStorage.clear();
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  function bootstrapWithSystemLanguage(language: string): PrefsController {
    vi.spyOn(navigator, "language", "get").mockReturnValue(language);
    const prefs = new PrefsController();
    prefs.bootstrap();
    return prefs;
  }

  // The UI ships in French and English only: a system language that is
  // neither gets the one more people can read.
  it.each(["en-US", "en-GB", "de-DE", "es-ES", "pt-BR", "ja-JP", "zh-Hans-CN"])(
    "starts in English for the system language %j",
    (language) => {
      expect(bootstrapWithSystemLanguage(language).currentLocale).toBe("en");
    },
  );

  it.each(["fr", "fr-FR", "fr-CA", "FR-be"])(
    "starts in French for the system language %j",
    (language) => {
      expect(bootstrapWithSystemLanguage(language).currentLocale).toBe("fr");
    },
  );

  it("starts in English when the system reports no language", () => {
    expect(bootstrapWithSystemLanguage("").currentLocale).toBe("en");
  });

  it("remembers the language it picked", () => {
    bootstrapWithSystemLanguage("de-DE");
    expect(localStorage.getItem("clavix.locale")).toBe("en");
  });

  // A profile that already landed on French, by choice or through the old
  // fallback, keeps it: only a profile with nothing saved follows the
  // system language.
  it.each([
    ["fr", "en-US"],
    ["en", "fr-FR"],
    ["fr", "de-DE"],
  ])("keeps the saved %s over the system language %s", (saved, language) => {
    localStorage.setItem("clavix.locale", saved);
    expect(bootstrapWithSystemLanguage(language).currentLocale).toBe(saved);
  });

  it.each(["", "de", "FR", "null"])("ignores the saved value %j", (saved) => {
    localStorage.setItem("clavix.locale", saved);
    expect(bootstrapWithSystemLanguage("de-DE").currentLocale).toBe("en");
  });
});
