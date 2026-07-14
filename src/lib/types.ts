export type Locale = "fr" | "en";

export type ThemePref = "auto" | "dark";

export type Phase =
  | "init"
  | "onboarding"
  | "idle"
  | "authenticating"
  | "twoFactor"
  | "unlock"
  | "loggedIn"
  | "error";

export type StoredAccount = { serverUrl: string; email: string };

export type TauriError = {
  code: string;
  message: string;
  data?: Record<string, unknown>;
};

// ---------------------------------------------------------------------------
// Types that cross the Tauri IPC boundary are GENERATED from the Rust
// definitions (`src/lib/generated/`, produced by ts-rs) and re-exported here.
//
// They used to be hand-written mirrors, and the two sides drifted without a
// sound: Rust sent `webauthn_challenge`, this file declared
// `webauthnChallenge`, and logging in with a security key was impossible —
// the challenge arrived as `undefined` every time, and nothing in the build
// could see it. Renaming a field in Rust now breaks `svelte-check` instead of
// breaking users. Do not re-declare these by hand.
// ---------------------------------------------------------------------------
import type { LoginDetail } from "./generated/LoginDetail";
import type { CardDetail } from "./generated/CardDetail";
import type { IdentityDetail } from "./generated/IdentityDetail";
import type { SshKeyDetail } from "./generated/SshKeyDetail";

export type { LoginOk } from "./generated/LoginOk";
export type { TwoFactorProvider } from "./generated/TwoFactorProvider";
export type { TypeCounts } from "./generated/TypeCounts";
export type { FolderSummary } from "./generated/FolderSummary";
export type { OrganizationSummary } from "./generated/OrganizationSummary";
export type { CollectionSummary } from "./generated/CollectionSummary";
export type { CipherSummary } from "./generated/CipherSummary";
export type { SyncSummary } from "./generated/SyncSummary";
export type { LoginDetail, CardDetail, IdentityDetail, SshKeyDetail };
export type { CipherDetail } from "./generated/CipherDetail";
export type { CipherCreateInput } from "./generated/CipherCreateInput";

// Rust calls it LoginOutcome; the frontend has always called it LoginResult.
export type { LoginOutcome as LoginResult } from "./generated/LoginOutcome";

// Small IPC return types, also generated from Rust (totp.rs / update.rs).
export type { TotpCode } from "./generated/TotpCode";
export type { UpdateInfo } from "./generated/UpdateInfo";

export type DecryptedSshKey = {
  privateKey: string;
  publicKey: string;
  keyFingerprint: string;
};

export type CipherKind = 1 | 2 | 3 | 4 | 5;

export type CardFields = {
  cardholderName: string;
  brand: string;
  number: string;
  expMonth: string;
  expYear: string;
  code: string;
};

export type IdentityFields = {
  title: string;
  firstName: string;
  middleName: string;
  lastName: string;
  address1: string;
  address2: string;
  address3: string;
  city: string;
  state: string;
  postalCode: string;
  country: string;
  company: string;
  email: string;
  phone: string;
  ssn: string;
  username: string;
  passportNumber: string;
  licenseNumber: string;
};

export type SshKeyFields = {
  privateKey: string;
  publicKey: string;
  keyFingerprint: string;
};

export type EditorInitial = {
  id: string | null;
  cipherType: CipherKind;
  name: string;
  folderId: string | null;
  favorite: boolean;
  notes: string;
  username: string;
  password: string;
  uris: string[];
  totp: string;
  card: CardFields;
  identity: IdentityFields;
  sshKey: SshKeyFields;
  /** When non-null, create/edit targets this organization. */
  organizationId: string | null;
  /** Collections the item will belong to inside the organization. */
  collectionIds: string[];
};

export const EMPTY_CARD_FIELDS: CardFields = {
  cardholderName: "",
  brand: "",
  number: "",
  expMonth: "",
  expYear: "",
  code: "",
};

export const EMPTY_IDENTITY_FIELDS: IdentityFields = {
  title: "",
  firstName: "",
  middleName: "",
  lastName: "",
  address1: "",
  address2: "",
  address3: "",
  city: "",
  state: "",
  postalCode: "",
  country: "",
  company: "",
  email: "",
  phone: "",
  ssn: "",
  username: "",
  passportNumber: "",
  licenseNumber: "",
};

export const EMPTY_SSH_FIELDS: SshKeyFields = {
  privateKey: "",
  publicKey: "",
  keyFingerprint: "",
};

export const EMPTY_EDITOR_INITIAL: EditorInitial = {
  id: null,
  cipherType: 1,
  name: "",
  folderId: null,
  favorite: false,
  notes: "",
  username: "",
  password: "",
  uris: [],
  totp: "",
  card: { ...EMPTY_CARD_FIELDS },
  identity: { ...EMPTY_IDENTITY_FIELDS },
  sshKey: { ...EMPTY_SSH_FIELDS },
  organizationId: null,
  collectionIds: [],
};

export type EditorPayload = Omit<EditorInitial, "id">;

export type ExposedKey = {
  comment: string;
  algorithm: string;
  fingerprint: string;
};

export type SkippedKey = {
  name: string;
  reason: string;
};

export type SshAgentStatus = {
  running: boolean;
  socketPath: string | null;
  keys: ExposedKey[];
  skipped: SkippedKey[];
};

export type AuditEntry = { cipherId: string; name: string; count: number };
export type ReusedGroup = { cipherIds: string[]; names: string[] };
export type WeakEntry = { cipherId: string; name: string; score: number };
export type AuditResult = {
  checked: number;
  pwned: AuditEntry[];
  reused: ReusedGroup[];
  weak: WeakEntry[];
};

export type TreeNode = {
  key: string;
  label: string;
  kind: "folder" | "organization" | "collection";
  folderId: string | null;
  organizationId: string | null;
  collectionId: string | null;
  children: TreeNode[];
  itemCount: number;
};

export type SortKey = "name" | "username" | "uri";
export type QuickFilter = "all" | "favorites" | "trash" | `type:${number}`;
