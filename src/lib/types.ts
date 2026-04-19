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

export type TokenSet = {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: string;
  key: string | null;
  privateKey: string | null;
  kdf: 0 | 1 | null;
  kdfIterations: number | null;
};

export type LoginResult =
  | { type: "success"; data: TokenSet }
  | {
      type: "twoFactorRequired";
      data: { providers: number[]; webauthnChallenge?: string };
    };

export type TypeCounts = {
  login: number;
  secureNote: number;
  card: number;
  identity: number;
  sshKey: number;
};

export type FolderSummary = { id: string; name: string };
export type OrganizationSummary = { id: string; name: string };
export type CollectionSummary = { id: string; organizationId: string; name: string };

export type CipherSummary = {
  id: string;
  kind: number;
  name: string;
  folderId: string | null;
  organizationId: string | null;
  collectionIds: string[];
  favorite: boolean;
  primaryUri: string | null;
  username: string | null;
  revisionDate: string | null;
  deletedDate: string | null;
};

export type SyncSummary = {
  email: string;
  name: string | null;
  itemCount: number;
  folderCount: number;
  collectionCount: number;
  organizationCount: number;
  typeCounts: TypeCounts;
  folders: FolderSummary[];
  organizations: OrganizationSummary[];
  collections: CollectionSummary[];
  ciphers: CipherSummary[];
};

export type LoginDetail = {
  username: string | null;
  password: string | null;
  uris: string[];
  totp: string | null;
};

export type CardDetail = {
  cardholderName: string | null;
  brand: string | null;
  number: string | null;
  expMonth: string | null;
  expYear: string | null;
  code: string | null;
};

export type IdentityDetail = {
  title: string | null;
  firstName: string | null;
  middleName: string | null;
  lastName: string | null;
  address1: string | null;
  address2: string | null;
  address3: string | null;
  city: string | null;
  state: string | null;
  postalCode: string | null;
  country: string | null;
  company: string | null;
  email: string | null;
  phone: string | null;
  ssn: string | null;
  username: string | null;
  passportNumber: string | null;
  licenseNumber: string | null;
};

export type SshKeyDetail = {
  privateKey: string | null;
  publicKey: string | null;
  keyFingerprint: string | null;
};

export type CipherDetail = {
  id: string;
  kind: number;
  name: string;
  notes: string | null;
  organizationId: string | null;
  folderId: string | null;
  collectionIds: string[];
  revisionDate: string | null;
  favorite: boolean;
  login: LoginDetail | null;
  card: CardDetail | null;
  identity: IdentityDetail | null;
  sshKey: SshKeyDetail | null;
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
};

export type EditorPayload = Omit<EditorInitial, "id">;

export type SshAgentStatus = {
  running: boolean;
  socketPath: string | null;
  keyCount: number;
  skippedCount: number;
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
