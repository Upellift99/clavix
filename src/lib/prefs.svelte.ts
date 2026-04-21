import { getLocale, setLocale } from "$lib/paraglide/runtime";
import type { Locale, ThemePref } from "./types";

const LOCALE_STORAGE_KEY = "clavix.locale";
const THEME_STORAGE_KEY = "clavix.theme";
const TREE_WIDTH_STORAGE_KEY = "clavix.treeWidth";
const DETAIL_HEIGHT_STORAGE_KEY = "clavix.detailHeight";
const AUTO_LOCK_STORAGE_KEY = "clavix.autoLockMinutes";
const ONBOARDED_STORAGE_KEY = "clavix.onboarded";

export const TREE_WIDTH_MIN = 180;
export const TREE_WIDTH_MAX = 560;
const TREE_WIDTH_DEFAULT = 260;
export const DETAIL_HEIGHT_MIN = 160;
export const DETAIL_HEIGHT_MAX = 900;
const DETAIL_HEIGHT_DEFAULT = 320;
const AUTO_LOCK_DEFAULT_MINUTES = 10;

export class PrefsController {
  currentLocale = $state<Locale>("fr");
  themePref = $state<ThemePref>("auto");
  treeWidth = $state<number>(TREE_WIDTH_DEFAULT);
  detailHeight = $state<number>(DETAIL_HEIGHT_DEFAULT);
  autoLockMinutes = $state<number>(AUTO_LOCK_DEFAULT_MINUTES);
  lastActivityAt = $state<number>(Date.now());

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
    } catch {
      // ignore
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
