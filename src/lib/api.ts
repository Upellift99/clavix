import { invoke } from "@tauri-apps/api/core";
import type {
  AuditResult,
  CipherDetail,
  EditorPayload,
  LoginResult,
  SshAgentStatus,
  StoredAccount,
  SyncSummary,
  TokenSet,
} from "./types";

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
    invoke<TokenSet>("login_with_two_factor", {
      serverUrl,
      email,
      password,
      code,
      provider,
    }),

  unlock: (password: string) => invoke<TokenSet>("unlock", { password }),

  lock: () => invoke<void>("lock"),

  logout: () => invoke<void>("logout"),

  sync: () => invoke<SyncSummary>("sync"),

  loadCachedVault: () => invoke<SyncSummary | null>("load_cached_vault"),

  getCipher: (id: string) => invoke<CipherDetail>("get_cipher", { id }),

  createLoginCipher: (input: Omit<EditorPayload, "id">) =>
    invoke<string>("create_login_cipher", {
      input: {
        name: input.name,
        folderId: input.folderId,
        favorite: input.favorite,
        notes: input.notes || null,
        login: {
          username: input.username || null,
          password: input.password || null,
          uris: input.uris,
          totp: input.totp || null,
        },
      },
    }),

  updateLoginCipher: (cipherId: string, input: Omit<EditorPayload, "id">) =>
    invoke<void>("update_login_cipher", {
      cipherId,
      input: {
        name: input.name,
        folderId: input.folderId,
        favorite: input.favorite,
        notes: input.notes || null,
        login: {
          username: input.username || null,
          password: input.password || null,
          uris: input.uris,
          totp: input.totp || null,
        },
      },
    }),

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
