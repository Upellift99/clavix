import { invoke } from "@tauri-apps/api/core";
import type {
  AuditResult,
  AutoLockTrigger,
  CipherDetail,
  DecryptedSshKey,
  EditorPayload,
  ImportedItem,
  LoginOk,
  LoginResult,
  PasswordHistoryEntry,
  PasswordStrength,
  SessionOrigin,
  SshAgentStatus,
  StoredAccount,
  SyncSummary,
  TotpCode,
  UpdateInfo,
  YubikeyUnlockInfo,
} from "./types";

function nullIfEmpty(s: string): string | null {
  return s.length > 0 ? s : null;
}

function payloadToRust(input: EditorPayload): Record<string, unknown> {
  const base: Record<string, unknown> = {
    cipherType: input.cipherType,
    name: input.name,
    folderId: input.organizationId ? null : input.folderId,
    favorite: input.favorite,
    notes: nullIfEmpty(input.notes),
    organizationId: input.organizationId,
    collectionIds: input.organizationId ? input.collectionIds : [],
    // Fields with neither a name nor a value are the empty row the editor
    // leaves behind when someone adds one and changes their mind.
    fields: input.fields
      .filter((f) => f.name.length > 0 || f.value.length > 0)
      .map((f) => ({
        kind: f.kind,
        name: nullIfEmpty(f.name),
        value: nullIfEmpty(f.value),
        linkedId: f.linkedId,
      })),
    reprompt: input.reprompt,
  };
  if (input.cipherType === 1) {
    base.login = {
      username: nullIfEmpty(input.username),
      password: nullIfEmpty(input.password),
      uris: input.uris,
      totp: nullIfEmpty(input.totp),
    };
  } else if (input.cipherType === 3) {
    base.card = {
      cardholderName: nullIfEmpty(input.card.cardholderName),
      brand: nullIfEmpty(input.card.brand),
      number: nullIfEmpty(input.card.number),
      expMonth: nullIfEmpty(input.card.expMonth),
      expYear: nullIfEmpty(input.card.expYear),
      code: nullIfEmpty(input.card.code),
    };
  } else if (input.cipherType === 4) {
    const id = input.identity;
    base.identity = {
      title: nullIfEmpty(id.title),
      firstName: nullIfEmpty(id.firstName),
      middleName: nullIfEmpty(id.middleName),
      lastName: nullIfEmpty(id.lastName),
      address1: nullIfEmpty(id.address1),
      address2: nullIfEmpty(id.address2),
      address3: nullIfEmpty(id.address3),
      city: nullIfEmpty(id.city),
      state: nullIfEmpty(id.state),
      postalCode: nullIfEmpty(id.postalCode),
      country: nullIfEmpty(id.country),
      company: nullIfEmpty(id.company),
      email: nullIfEmpty(id.email),
      phone: nullIfEmpty(id.phone),
      ssn: nullIfEmpty(id.ssn),
      username: nullIfEmpty(id.username),
      passportNumber: nullIfEmpty(id.passportNumber),
      licenseNumber: nullIfEmpty(id.licenseNumber),
    };
  } else if (input.cipherType === 5) {
    base.sshKey = {
      privateKey: nullIfEmpty(input.sshKey.privateKey),
      publicKey: nullIfEmpty(input.sshKey.publicKey),
      keyFingerprint: nullIfEmpty(input.sshKey.keyFingerprint),
    };
  }
  // type 2 (SecureNote): name + notes only, no extra field
  return base;
}

export const api = {
  storedAccount: () => invoke<StoredAccount | null>("stored_account"),

  login: (serverUrl: string, email: string, password: string) =>
    invoke<LoginResult>("login", { serverUrl, email, password }),

  loginWithTwoFactor: (code: string, provider: number) =>
    invoke<LoginOk>("login_with_two_factor", { code, provider }),

  cancelTwoFactor: () => invoke<void>("cancel_two_factor"),

  unlock: (password: string) => invoke<LoginOk>("unlock", { password }),

  lock: () => invoke<void>("lock"),

  logout: () => invoke<void>("logout"),

  setAutoLock: (trigger: AutoLockTrigger, minutes: number) =>
    invoke<void>("set_auto_lock", { trigger, minutes }),

  /// Whether this desktop session can report its lock state. Probed at
  /// runtime, not derived from the platform — see `screen_lock.rs`.
  screenLockAvailable: () => invoke<boolean>("screen_lock_available"),

  setCloseToTray: (value: boolean) => invoke<void>("set_close_to_tray", { value }),

  setMinimizeToTray: (value: boolean) =>
    invoke<void>("set_minimize_to_tray", { value }),

  setHideDockOnTray: (value: boolean) =>
    invoke<void>("set_hide_dock_on_tray", { value }),

  setTrayLocale: (locale: string) => invoke<void>("set_tray_locale", { locale }),

  webauthnSignChallenge: (challengeJson: string) =>
    invoke<string>("webauthn_sign_challenge", { challengeJson }),

  yubikeyUnlockState: () => invoke<YubikeyUnlockInfo>("yubikey_unlock_state"),

  enrollYubikeyUnlock: (pin: string | null) =>
    invoke<void>("enroll_yubikey_unlock", { pin }),

  disenrollYubikeyUnlock: (password: string) =>
    invoke<void>("disenroll_yubikey_unlock", { password }),

  unlockWithYubikey: (pin: string | null) =>
    invoke<LoginOk>("unlock_with_yubikey", { pin }),

  sync: () => invoke<SyncSummary>("sync"),

  loadCachedVault: () => invoke<SyncSummary | null>("load_cached_vault"),

  createFolder: (name: string) => invoke<string>("create_folder", { name }),

  deleteFolder: (folderId: string) => invoke<void>("delete_folder", { folderId }),

  renameFolder: (folderId: string, name: string) =>
    invoke<void>("rename_folder", { folderId, name }),

  renameFolderPath: (sourcePath: string, newPath: string) =>
    invoke<void>("rename_folder_path", { sourcePath, newPath }),

  getCipher: (id: string) => invoke<CipherDetail>("get_cipher", { id }),

  /** Decrypt a single secret field on demand (kept out of get_cipher / JS
      reactive state). field: password | cardNumber | cardCode | ssn |
      sshPrivateKey. */
  revealField: (id: string, field: string) =>
    invoke<string | null>("reveal_field", { id, field }),

  /** Current TOTP code + seconds remaining, computed in Rust (the seed never
      reaches JS). */
  totpCode: (id: string) => invoke<TotpCode>("totp_code", { id }),

  /** Raw TOTP secret — only for the editor and export. */
  revealLoginTotp: (id: string) => invoke<string | null>("reveal_login_totp", { id }),

  createCipher: (input: EditorPayload) =>
    invoke<string>("create_cipher", { input: payloadToRust(input) }),

  updateCipher: (cipherId: string, input: EditorPayload) =>
    invoke<void>("update_cipher", { cipherId, input: payloadToRust(input) }),

  restoreCipher: (cipherId: string) => invoke<void>("restore_cipher", { cipherId }),

  softDeleteCipher: (cipherId: string) =>
    invoke<void>("soft_delete_cipher", { cipherId }),

  deleteCipher: (cipherId: string) => invoke<void>("delete_cipher", { cipherId }),

  /** Server-side copy of an item. The plaintext never leaves Rust: the
      copy is decrypted, renamed and re-encrypted there. Returns the new id. */
  duplicateCipher: (cipherId: string, nameSuffix: string) =>
    invoke<string>("duplicate_cipher", { cipherId, nameSuffix }),

  /** Past passwords, newest first. Fetched on demand like any secret. */
  passwordHistory: (id: string) =>
    invoke<PasswordHistoryEntry[]>("password_history", { id }),

  /** Decrypted attachment, base64-encoded (see the Rust side on why not
      a byte array). */
  downloadAttachment: (cipherId: string, attachmentId: string) =>
    invoke<string>("download_attachment", { cipherId, attachmentId }),

  uploadAttachment: (cipherId: string, fileName: string, dataBase64: string) =>
    invoke<void>("upload_attachment", { cipherId, fileName, dataBase64 }),

  deleteAttachment: (cipherId: string, attachmentId: string) =>
    invoke<void>("delete_attachment", { cipherId, attachmentId }),

  /** Local master-password check for the per-item reprompt gate. No
      network, no session change — false just means "wrong password". */
  verifyMasterPassword: (password: string) =>
    invoke<boolean>("verify_master_password", { password }),

  moveCipherToFolder: (cipherId: string, folderId: string | null) =>
    invoke<void>("move_cipher_to_folder", { cipherId, folderId }),

  moveCipherToCollection: (cipherId: string, collectionId: string) =>
    invoke<void>("move_cipher_to_collection", { cipherId, collectionId }),

  moveFolderPath: (sourcePath: string, targetParentPath: string | null) =>
    invoke<void>("move_folder_path", { sourcePath, targetParentPath }),

  shareCipherToCollection: (cipherId: string, collectionId: string) =>
    invoke<void>("share_cipher_to_collection", { cipherId, collectionId }),

  auditVaultPasswords: () => invoke<AuditResult>("audit_vault_passwords"),

  /** Score a password the user is typing. `userInputs` (item name,
      username, domain) let zxcvbn penalise a password that merely
      echoes the item it protects. */
  scorePassword: (password: string, userInputs: string[] = []) =>
    invoke<PasswordStrength>("score_password", { password, userInputs }),

  /** Score a stored item's password *without* revealing it: the
      decryption happens in Rust and only the verdict crosses back, so
      the detail pane can show a strength bar on a still-masked field.
      Null when the item has no login password. */
  scoreCipherPassword: (id: string) =>
    invoke<PasswordStrength | null>("score_cipher_password", { id }),

  startSshAgent: (policy: string) =>
    invoke<SshAgentStatus>("start_ssh_agent", { policy }),

  /** Answer a pending agent signature-confirmation prompt. */
  respondSshAgentConfirm: (id: number, approved: boolean) =>
    invoke<void>("respond_ssh_agent_confirm", { id, approved }),

  stopSshAgent: () => invoke<void>("stop_ssh_agent"),

  sshAgentStatus: () => invoke<SshAgentStatus>("ssh_agent_status"),

  decryptSshPrivateKey: (privateKey: string, passphrase: string | null) =>
    invoke<DecryptedSshKey>("decrypt_ssh_private_key", { privateKey, passphrase }),

  generateSshKey: () => invoke<DecryptedSshKey>("generate_ssh_key"),

  sshAuthSock: () => invoke<string | null>("ssh_auth_sock"),

  parseKdbx: (bytes: Uint8Array, password: string) =>
    invoke<KdbxEntry[]>("parse_kdbx", { bytes: Array.from(bytes), password }),

  /** Open an encrypted export file as a standalone, read-only vault —
      no account, no server, no stored session. Refused while another
      vault is open. */
  openExportFile: (bytes: Uint8Array, filePassword: string) =>
    invoke<LoginOk>("open_export_file", { bytes: Array.from(bytes), filePassword }),

  /** Item list for a file-backed standalone session. The cache-backed
      one gets its list from `loadCachedVault` instead. */
  standaloneSummary: () => invoke<SyncSummary>("standalone_summary"),

  /** How the open vault was reached, or null when nothing is open. */
  sessionOrigin: () => invoke<SessionOrigin | null>("session_origin"),

  /** Seal the whole vault into a password-protected export file. The
      bytes coming back are already ciphertext — the vault is
      re-encrypted under a fresh key in Rust and never assembled here
      in the clear. */
  exportEncrypted: (filePassword: string) =>
    invoke<number[]>("export_encrypted", { filePassword }).then(
      (bytes) => new Uint8Array(bytes),
    ),

  /** Open an encrypted export. Session-free: the file carries its own
      key. Returns items ready to replay through `createCipher`, the
      same shape the CSV and KDBX paths use. */
  importEncrypted: (bytes: Uint8Array, filePassword: string) =>
    invoke<ImportedItem[]>("import_encrypted", {
      bytes: Array.from(bytes),
      filePassword,
    }),

  /** Ask GitHub (from Rust — the CSP blocks the WebView from reaching it)
      whether a newer Clavix has been published. */
  checkForUpdate: () => invoke<UpdateInfo>("check_for_update"),

  /** This build's version, straight from Rust (offline, no network). */
  appVersion: () => invoke<string>("app_version"),
};

/// Flat entry shape returned by `parse_kdbx` — mirrors the CSV
/// `KeepassEntry` so the import dialog can pour either source into
/// the same `createCipher` loop. Empty strings rather than `null`
/// for missing fields, same convention as the CSV path.
export type KdbxEntry = {
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  totp: string;
  group: string;
};
