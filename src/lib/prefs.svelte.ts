import { getLocale, setLocale } from "$lib/paraglide/runtime";
import type { Locale, ThemePref } from "./types";

const LOCALE_STORAGE_KEY = "clavix.locale";
const THEME_STORAGE_KEY = "clavix.theme";
const TREE_WIDTH_STORAGE_KEY = "clavix.treeWidth";
const DETAIL_HEIGHT_STORAGE_KEY = "clavix.detailHeight";
const AUTO_LOCK_STORAGE_KEY = "clavix.autoLockMinutes";
const CLOSE_TO_TRAY_STORAGE_KEY = "clavix.closeToTray";
const MINIMIZE_TO_TRAY_STORAGE_KEY = "clavix.minimizeToTray";
const HIDE_DOCK_ON_TRAY_STORAGE_KEY = "clavix.hideDockOnTray";
const ONBOARDED_STORAGE_KEY = "clavix.onboarded";
const VISIBLE_COLUMNS_STORAGE_KEY = "clavix.visibleColumns";
const REQUIRE_NARROWING_STORAGE_KEY = "clavix.requireNarrowing";
const ASK_YUBIKEY_PIN_STORAGE_KEY = "clavix.askYubikeyPin";

// On by default: a freshly-enrolled Yubikey may or may not carry a PIN,
// so we show the (optional) PIN field until the user tells us their key
// has none. Turning it off hides the field on the unlock screen and
// attempts the touch without a PIN.
const ASK_YUBIKEY_PIN_DEFAULT = true;

// On by default: opening a 3000-item vault straight onto the full list
// puts every entry on screen at once, which is noise at best and a
// shoulder-surfing surface at worst. The list is virtualised, so this is
// not a rendering cost — it is a "show me what I asked for" default.
const REQUIRE_NARROWING_DEFAULT = true;

/** Cipher-list columns the user can hide. The Type icon and the Name
 *  are not in here because hiding either makes the list unusable. */
export type CipherListColumns = {
  username: boolean;
  uri: boolean;
};

const VISIBLE_COLUMNS_DEFAULT: CipherListColumns = {
  username: true,
  uri: true,
};

export const TREE_WIDTH_MIN = 180;
export const TREE_WIDTH_MAX = 560;
const TREE_WIDTH_DEFAULT = 260;
export const DETAIL_HEIGHT_MIN = 160;
export const DETAIL_HEIGHT_MAX = 900;
const DETAIL_HEIGHT_DEFAULT = 320;
const AUTO_LOCK_DEFAULT_MINUTES = 10;
// Hide-to-tray default matches the Rust mirror: on for Windows/macOS
// (KeePassXC, Bitwarden Desktop shape), off for Linux. GNOME ships
// tray support behind an extension whose runtime state is unreliable
// (ubuntu-appindicators sits enabled-but-inactive on a stock Ubuntu
// session, Wayland restricts SNI further), so defaulting to hide on
// Linux strands the window with no way back. Users with a working
// tray can flip it on in Préférences.
const IS_LINUX =
  typeof navigator !== "undefined" && /Linux/i.test(navigator.userAgent);
const CLOSE_TO_TRAY_DEFAULT = !IS_LINUX;
const MINIMIZE_TO_TRAY_DEFAULT = !IS_LINUX;

export class PrefsController {
  currentLocale = $state<Locale>("fr");
  themePref = $state<ThemePref>("auto");
  treeWidth = $state<number>(TREE_WIDTH_DEFAULT);
  detailHeight = $state<number>(DETAIL_HEIGHT_DEFAULT);
  autoLockMinutes = $state<number>(AUTO_LOCK_DEFAULT_MINUTES);
  closeToTray = $state<boolean>(CLOSE_TO_TRAY_DEFAULT);
  minimizeToTray = $state<boolean>(MINIMIZE_TO_TRAY_DEFAULT);
  hideDockOnTray = $state<boolean>(false);
  lastActivityAt = $state<number>(Date.now());
  visibleColumns = $state<CipherListColumns>({ ...VISIBLE_COLUMNS_DEFAULT });
  requireNarrowing = $state<boolean>(REQUIRE_NARROWING_DEFAULT);
  askYubikeyPin = $state<boolean>(ASK_YUBIKEY_PIN_DEFAULT);

  /** Loads persisted values from localStorage and applies side effects. */
  bootstrap() {
    try {
      const savedTheme = localStorage.getItem(THEME_STORAGE_KEY) as ThemePref | null;
      this.applyTheme(savedTheme === "dark" ? "dark" : "auto");
    } catch {
      this.applyTheme("auto");
    }

    try {
      const savedLocale = localStorage.getItem(LOCALE_STORAGE_KEY) as Locale | null;
      if (savedLocale === "fr" || savedLocale === "en") {
        this.applyLocale(savedLocale);
      } else {
        const browser = (navigator.language || "fr").toLowerCase();
        this.applyLocale(browser.startsWith("en") ? "en" : "fr");
      }
    } catch {
      this.applyLocale(getLocale() === "en" ? "en" : "fr");
    }

    try {
      const saved = localStorage.getItem(TREE_WIDTH_STORAGE_KEY);
      if (saved) {
        const parsed = parseInt(saved, 10);
        if (Number.isFinite(parsed)) {
          this.treeWidth = Math.max(TREE_WIDTH_MIN, Math.min(TREE_WIDTH_MAX, parsed));
        }
      }
      const savedDetail = localStorage.getItem(DETAIL_HEIGHT_STORAGE_KEY);
      if (savedDetail) {
        const parsed = parseInt(savedDetail, 10);
        if (Number.isFinite(parsed)) {
          this.detailHeight = Math.max(DETAIL_HEIGHT_MIN, Math.min(DETAIL_HEIGHT_MAX, parsed));
        }
      }
      const savedLock = localStorage.getItem(AUTO_LOCK_STORAGE_KEY);
      if (savedLock) {
        const parsed = parseFloat(savedLock);
        if (Number.isFinite(parsed) && parsed >= 0) {
          this.autoLockMinutes = parsed;
        }
      }
      // Honour an explicit stored value either way; absence keeps the
      // platform default (off on Linux, on elsewhere) so a user who
      // turned hide-to-tray on under a working tray keeps it across
      // restarts even on Linux.
      const savedTray = localStorage.getItem(CLOSE_TO_TRAY_STORAGE_KEY);
      if (savedTray === "true") {
        this.closeToTray = true;
      } else if (savedTray === "false") {
        this.closeToTray = false;
      }
      const savedMinTray = localStorage.getItem(MINIMIZE_TO_TRAY_STORAGE_KEY);
      if (savedMinTray === "true") {
        this.minimizeToTray = true;
      } else if (savedMinTray === "false") {
        this.minimizeToTray = false;
      }
      const savedHideDock = localStorage.getItem(HIDE_DOCK_ON_TRAY_STORAGE_KEY);
      if (savedHideDock === "true") {
        this.hideDockOnTray = true;
      } else if (savedHideDock === "false") {
        this.hideDockOnTray = false;
      }
      const savedNarrowing = localStorage.getItem(REQUIRE_NARROWING_STORAGE_KEY);
      if (savedNarrowing === "true") {
        this.requireNarrowing = true;
      } else if (savedNarrowing === "false") {
        this.requireNarrowing = false;
      }
      const savedAskPin = localStorage.getItem(ASK_YUBIKEY_PIN_STORAGE_KEY);
      if (savedAskPin === "true") {
        this.askYubikeyPin = true;
      } else if (savedAskPin === "false") {
        this.askYubikeyPin = false;
      }
      const savedColumns = localStorage.getItem(VISIBLE_COLUMNS_STORAGE_KEY);
      if (savedColumns) {
        try {
          const parsed = JSON.parse(savedColumns) as Partial<CipherListColumns>;
          this.visibleColumns = {
            username:
              typeof parsed.username === "boolean"
                ? parsed.username
                : VISIBLE_COLUMNS_DEFAULT.username,
            uri:
              typeof parsed.uri === "boolean"
                ? parsed.uri
                : VISIBLE_COLUMNS_DEFAULT.uri,
          };
        } catch {
          // malformed JSON in localStorage — keep defaults
        }
      }
    } catch {
      // ignore
    }
  }

  setRequireNarrowing(value: boolean) {
    this.requireNarrowing = value;
    try {
      localStorage.setItem(REQUIRE_NARROWING_STORAGE_KEY, String(value));
    } catch {
      // best-effort
    }
  }

  setAskYubikeyPin(value: boolean) {
    this.askYubikeyPin = value;
    try {
      localStorage.setItem(ASK_YUBIKEY_PIN_STORAGE_KEY, String(value));
    } catch {
      // best-effort
    }
  }

  setVisibleColumn(key: keyof CipherListColumns, value: boolean) {
    this.visibleColumns = { ...this.visibleColumns, [key]: value };
    try {
      localStorage.setItem(
        VISIBLE_COLUMNS_STORAGE_KEY,
        JSON.stringify(this.visibleColumns),
      );
    } catch {
      // best-effort
    }
  }

  applyLocale(loc: Locale, opts: { reload?: boolean } = {}) {
    this.currentLocale = loc;
    try {
      localStorage.setItem(LOCALE_STORAGE_KEY, loc);
    } catch {
      // ignore
    }
    setLocale(loc, { reload: opts.reload === true });
  }

  applyTheme(next: ThemePref) {
    this.themePref = next;
    try {
      if (typeof document !== "undefined") {
        document.documentElement.classList.toggle("force-dark", next === "dark");
      }
      localStorage.setItem(THEME_STORAGE_KEY, next);
    } catch {
      // best-effort
    }
  }

  setTreeWidth(width: number) {
    this.treeWidth = Math.max(TREE_WIDTH_MIN, Math.min(TREE_WIDTH_MAX, width));
  }

  persistTreeWidth() {
    try {
      localStorage.setItem(TREE_WIDTH_STORAGE_KEY, String(this.treeWidth));
    } catch {
      // ignore
    }
  }

  setDetailHeight(height: number) {
    this.detailHeight = Math.max(DETAIL_HEIGHT_MIN, Math.min(DETAIL_HEIGHT_MAX, height));
  }

  persistDetailHeight() {
    try {
      localStorage.setItem(DETAIL_HEIGHT_STORAGE_KEY, String(this.detailHeight));
    } catch {
      // ignore
    }
  }

  setAutoLockMinutes(minutes: number) {
    this.autoLockMinutes = minutes;
    try {
      localStorage.setItem(AUTO_LOCK_STORAGE_KEY, String(minutes));
    } catch {
      // ignore
    }
  }

  setCloseToTray(value: boolean) {
    this.closeToTray = value;
    try {
      localStorage.setItem(CLOSE_TO_TRAY_STORAGE_KEY, String(value));
    } catch {
      // ignore
    }
  }

  setMinimizeToTray(value: boolean) {
    this.minimizeToTray = value;
    try {
      localStorage.setItem(MINIMIZE_TO_TRAY_STORAGE_KEY, String(value));
    } catch {
      // ignore
    }
  }

  setHideDockOnTray(value: boolean) {
    this.hideDockOnTray = value;
    try {
      localStorage.setItem(HIDE_DOCK_ON_TRAY_STORAGE_KEY, String(value));
    } catch {
      // ignore
    }
  }

  markActivity() {
    this.lastActivityAt = Date.now();
  }

  isOnboarded(): boolean {
    try {
      return localStorage.getItem(ONBOARDED_STORAGE_KEY) === "1";
    } catch {
      return false;
    }
  }

  markOnboarded() {
    try {
      localStorage.setItem(ONBOARDED_STORAGE_KEY, "1");
    } catch {
      // best-effort
    }
  }
}
