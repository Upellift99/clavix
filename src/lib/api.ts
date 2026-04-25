import { invoke } from "@tauri-apps/api/core";
import type {
  AuditResult,
  CipherDetail,
  EditorPayload,
  LoginOk,
  LoginResult,
  SshAgentStatus,
  StoredAccount,
  SyncSummary,
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

  loginWithTwoFactor: (
    serverUrl: string,
    email: string,
    password: string,
    code: string,
    provider: number,
  ) =>
    invoke<LoginOk>("login_with_two_factor", {
      serverUrl,
      email,
      password,
      code,
      provider,
    }),

  unlock: (password: string) => invoke<LoginOk>("unlock", { password }),

  lock: () => invoke<void>("lock"),

  logout: () => invoke<void>("logout"),

  setAutoLockMinutes: (minutes: number) => invoke<void>("set_auto_lock_minutes", { minutes }),

  webauthnSignChallenge: (serverUrl: string, challengeJson: string) =>
    invoke<string>("webauthn_sign_challenge", { serverUrl, challengeJson }),

  sync: () => invoke<SyncSummary>("sync"),

  loadCachedVault: () => invoke<SyncSummary | null>("load_cached_vault"),

  createFolder: (name: string) => invoke<string>("create_folder", { name }),

  getCipher: (id: string) => invoke<CipherDetail>("get_cipher", { id }),

  createCipher: (input: EditorPayload) =>
    invoke<string>("create_cipher", { input: payloadToRust(input) }),

  updateCipher: (cipherId: string, input: EditorPayload) =>
    invoke<void>("update_cipher", { cipherId, input: payloadToRust(input) }),

  restoreCipher: (cipherId: string) => invoke<void>("restore_cipher", { cipherId }),

  deleteCipher: (cipherId: string) => invoke<void>("delete_cipher", { cipherId }),

  moveCipherToFolder: (cipherId: string, folderId: string | null) =>
    invoke<void>("move_cipher_to_folder", { cipherId, folderId }),

  moveCipherToCollection: (cipherId: string, collectionId: string) =>
    invoke<void>("move_cipher_to_collection", { cipherId, collectionId }),

  moveFolderPath: (sourcePath: string, targetParentPath: string | null) =>
    invoke<void>("move_folder_path", { sourcePath, targetParentPath }),

  shareCipherToCollection: (cipherId: string, collectionId: string) =>
    invoke<void>("share_cipher_to_collection", { cipherId, collectionId }),

  auditVaultPasswords: () => invoke<AuditResult>("audit_vault_passwords"),

  startSshAgent: () => invoke<SshAgentStatus>("start_ssh_agent"),

  stopSshAgent: () => invoke<void>("stop_ssh_agent"),

  sshAgentStatus: () => invoke<SshAgentStatus>("ssh_agent_status"),
};
