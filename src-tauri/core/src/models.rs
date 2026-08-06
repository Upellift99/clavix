use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use ts_rs::TS;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ============ Prelogin ============

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum KdfType {
    Pbkdf2 = 0,
    Argon2id = 1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Prelogin {
    pub kdf: KdfType,
    pub kdf_iterations: u32,
    pub kdf_memory: Option<u32>,
    pub kdf_parallelism: Option<u32>,
}

// ============ Login / 2FA / tokens ============

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr, TS)]
#[ts(export)]
// serde_repr puts these on the wire as bare numbers (0, 3, 7…), but ts-rs
// cannot see that and would happily generate a union of *variant names* —
// a generated type that lies is worse than none. Pin it to the number it
// actually is.
#[ts(as = "u8")]
#[repr(u8)]
pub enum TwoFactorProvider {
    Authenticator = 0,
    Email = 1,
    Duo = 2,
    YubiKey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,
    WebAuthn = 7,
}

impl TryFrom<u8> for TwoFactorProvider {
    type Error = ();

    fn try_from(value: u8) -> std::result::Result<Self, ()> {
        match value {
            0 => Ok(Self::Authenticator),
            1 => Ok(Self::Email),
            2 => Ok(Self::Duo),
            3 => Ok(Self::YubiKey),
            4 => Ok(Self::U2f),
            5 => Ok(Self::Remember),
            6 => Ok(Self::OrganizationDuo),
            7 => Ok(Self::WebAuthn),
            _ => Err(()),
        }
    }
}

// ZeroizeOnDrop wipes the access + refresh tokens (and the wrapped key
// material) from memory when a Session is torn down (lock / logout /
// auto-lock), instead of leaving them readable in freed heap for a
// core-dump/swap attacker. Mirrors the ZeroizeOnDrop the key types already
// carry. (String zeroization without mlock is best-effort, so this is
// defense-in-depth.)
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
pub struct TokenSet {
    // The four secret fields are zeroized on drop; the rest are non-secret
    // metadata (and `KdfType` doesn't implement Zeroize), so they're skipped.
    #[serde(rename = "access_token")]
    pub access_token: String,
    #[serde(rename = "refresh_token")]
    pub refresh_token: String,
    #[serde(rename = "expires_in")]
    #[zeroize(skip)]
    pub expires_in: u64,
    #[serde(rename = "token_type")]
    #[zeroize(skip)]
    pub token_type: String,

    #[serde(default, alias = "Key")]
    pub key: Option<String>,
    #[serde(default, alias = "PrivateKey")]
    pub private_key: Option<String>,
    #[serde(default, alias = "Kdf")]
    #[zeroize(skip)]
    pub kdf: Option<KdfType>,
    #[serde(default, alias = "KdfIterations")]
    #[zeroize(skip)]
    pub kdf_iterations: Option<u32>,
}

/// Internal result of an HTTP login call. The `TokenSet` here is consumed
/// by `commands::auth` to build the in-memory `Session`; it is **not**
/// serialised to the frontend (see `LoginOutcome` for the IPC-facing
/// shape).
#[derive(Debug, Clone)]
pub enum LoginResult {
    Success(TokenSet),
    TwoFactorRequired {
        providers: Vec<TwoFactorProvider>,
        /// When the server offers WebAuthn (provider 7), the challenge
        /// object it wants us to sign. Serialised JSON string so we can
        /// hand it to the CTAP2 backend verbatim without re-shaping.
        webauthn_challenge: Option<String>,
    },
}

/// Public payload returned to the frontend on a successful login/unlock.
/// Intentionally token-free: the access/refresh tokens and the user key
/// stay inside the Rust `AppState` and never cross the IPC boundary.
#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct LoginOk {
    pub email: String,
    /// How this vault was opened. Anything other than `server` means
    /// the session is read-only, and the UI says so rather than letting
    /// the user discover it by having a save rejected.
    pub origin: crate::session::SessionOrigin,
}

/// IPC-facing variant of `LoginResult` — same shape as the old type, minus
/// the `TokenSet` payload that has no business reaching the WebView.
#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
// `rename_all` on an enum renames the *variants*, not the fields inside a
// struct variant — `rename_all_fields` is what camel-cases those. Without
// it `webauthn_challenge` crossed the IPC boundary in snake_case while the
// frontend read `webauthnChallenge`, so the WebAuthn challenge always
// arrived as `undefined` and 2FA with a security key reported "the server
// sent no challenge". `providers` never showed the bug: one word, same
// spelling in both conventions.
#[serde(
    tag = "type",
    content = "data",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum LoginOutcome {
    Success(LoginOk),
    TwoFactorRequired {
        providers: Vec<TwoFactorProvider>,
        // `skip_serializing_if` omits the key entirely rather than sending
        // null, so the generated type has to say `?:`, not `| null`.
        #[serde(skip_serializing_if = "Option::is_none")]
        #[ts(optional)]
        webauthn_challenge: Option<String>,
    },
}

// ============ Sync response ============

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub profile: Profile,
    #[serde(default)]
    pub folders: Vec<Folder>,
    #[serde(default)]
    pub collections: Vec<Collection>,
    #[serde(default)]
    pub ciphers: Vec<Cipher>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    pub id: String,
    pub email: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub organizations: Vec<Organization>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Organization {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Folder {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub revision_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Collection {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    #[serde(default)]
    pub external_id: Option<String>,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub hide_passwords: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum CipherType {
    Login = 1,
    SecureNote = 2,
    Card = 3,
    Identity = 4,
    SshKey = 5,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cipher {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: CipherType,
    /// The cipher's own encryption key, wrapped under the owning key (org
    /// key for an org item, user key otherwise). When present, every field
    /// below is encrypted under *this* key instead of the owning one — see
    /// `crypto::decrypt_cipher_key`. Absent on items last written by a
    /// client that predates cipher key encryption.
    #[serde(default)]
    pub key: Option<String>,
    pub name: String,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub collection_ids: Vec<String>,
    #[serde(default)]
    pub revision_date: Option<String>,
    #[serde(default)]
    pub deleted_date: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub login: Option<CipherLogin>,
    #[serde(default)]
    pub card: Option<CipherCard>,
    #[serde(default)]
    pub identity: Option<CipherIdentity>,
    #[serde(default)]
    pub ssh_key: Option<CipherSshKey>,
    /// Custom fields. `name`/`value` are EncStrings; `type`/`linked_id` are
    /// plaintext metadata. Modelled so sharing to an org can rewrap them
    /// instead of silently dropping them (the share PUT has replace semantics).
    #[serde(default)]
    pub fields: Option<Vec<CipherField>>,
    /// Password history entries; `password` is an EncString.
    #[serde(default)]
    pub password_history: Option<Vec<CipherPasswordHistory>>,
    /// Master-password reprompt: 0 (or absent) = none, 1 = ask again before
    /// revealing this item's secrets. Advisory by construction — the server
    /// enforces nothing and any client can ignore it — so it guards against
    /// a shoulder-surfer at an unlocked vault, not against an attacker who
    /// owns the machine.
    #[serde(default)]
    pub reprompt: Option<u8>,
    /// Files attached to this cipher. `file_name` and `key` are EncStrings;
    /// `key` wraps the per-attachment key the payload itself is encrypted
    /// under (absent on legacy attachments, which use the cipher key).
    #[serde(default)]
    pub attachments: Option<Vec<CipherAttachment>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherAttachment {
    pub id: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub file_name: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    /// Ciphertext length in bytes, as a string on the wire (Bitwarden sends
    /// it as a string; Vaultwarden mirrors that).
    #[serde(default)]
    pub size: Option<String>,
    #[serde(default)]
    pub size_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherField {
    #[serde(rename = "type", default)]
    pub kind: Option<u8>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub linked_id: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherPasswordHistory {
    #[serde(default)]
    pub last_used_date: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherCard {
    #[serde(default)]
    pub cardholder_name: Option<String>,
    #[serde(default)]
    pub brand: Option<String>,
    #[serde(default)]
    pub number: Option<String>,
    #[serde(default)]
    pub exp_month: Option<String>,
    #[serde(default)]
    pub exp_year: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherIdentity {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub middle_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub address1: Option<String>,
    #[serde(default)]
    pub address2: Option<String>,
    #[serde(default)]
    pub address3: Option<String>,
    #[serde(default)]
    pub city: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub postal_code: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub company: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub ssn: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub passport_number: Option<String>,
    #[serde(default)]
    pub license_number: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherSshKey {
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub key_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherLogin {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub uris: Option<Vec<CipherLoginUri>>,
    #[serde(default)]
    pub totp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherLoginUri {
    #[serde(default)]
    pub uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct CipherDetail {
    pub id: String,
    pub kind: u8,
    pub name: String,
    pub notes: Option<String>,
    pub organization_id: Option<String>,
    pub folder_id: Option<String>,
    pub collection_ids: Vec<String>,
    pub revision_date: Option<String>,
    pub favorite: bool,
    pub login: Option<LoginDetail>,
    pub card: Option<CardDetail>,
    pub identity: Option<IdentityDetail>,
    pub ssh_key: Option<SshKeyDetail>,
    /// Custom fields, in vault order. Hidden ones carry no value — same
    /// rule as every other secret (see `reveal_field("custom:<index>")`).
    pub fields: Vec<CustomFieldDetail>,
    /// How many past passwords the item carries. The passwords themselves
    /// come from `password_history`, on demand.
    pub password_history_count: u32,
    pub attachments: Vec<AttachmentDetail>,
    /// Whether the item asks for the master password before revealing.
    pub reprompt: bool,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct CustomFieldDetail {
    pub name: Option<String>,
    /// Bitwarden field type: 0 text, 1 hidden, 2 boolean, 3 linked.
    pub kind: u8,
    /// Plaintext for text/boolean/linked fields; `None` for hidden ones.
    pub value: Option<String>,
    /// True when the value was withheld because the field is hidden.
    pub hidden: bool,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentDetail {
    pub id: String,
    /// Decrypted file name, or `None` when it fails to decrypt.
    pub file_name: Option<String>,
    /// Server-rendered size, e.g. "1.4 MB".
    pub size_name: Option<String>,
    /// Ciphertext size in bytes; 0 when the server sent no usable value.
    /// `u32` rather than `u64` on purpose: ts-rs maps a 64-bit integer to
    /// `bigint`, which is a lie on this boundary — Tauri serialises it as
    /// a JSON number and the WebView receives a plain `number`. 4 GiB is
    /// far above any attachment this app will accept anyway.
    pub size: u32,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHistoryEntry {
    pub password: String,
    pub last_used_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct LoginDetail {
    pub username: Option<String>,
    /// Presence only — the password is fetched on demand via
    /// `reveal_field(id, "password")` so it doesn't sit in long-lived JS state.
    pub has_password: bool,
    pub uris: Vec<String>,
    /// Whether the item carries a TOTP secret. The secret itself is NOT sent to
    /// the WebView (it would let a compromised renderer mint valid codes
    /// forever — a permanent 2FA bypass). The renderer asks
    /// `commands::cipher::totp_code` for the current code, and
    /// `reveal_login_totp` for the raw secret only when the editor/export needs
    /// it.
    pub has_totp: bool,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct CardDetail {
    pub cardholder_name: Option<String>,
    pub brand: Option<String>,
    /// Card number + CVV are fetched on demand (`reveal_field(id, "cardNumber"
    /// | "cardCode")`); only their presence is sent eagerly.
    pub has_number: bool,
    pub exp_month: Option<String>,
    pub exp_year: Option<String>,
    pub has_code: bool,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct IdentityDetail {
    pub title: Option<String>,
    pub first_name: Option<String>,
    pub middle_name: Option<String>,
    pub last_name: Option<String>,
    pub address1: Option<String>,
    pub address2: Option<String>,
    pub address3: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
    pub company: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    /// SSN is fetched on demand via `reveal_field(id, "ssn")`.
    pub has_ssn: bool,
    pub username: Option<String>,
    pub passport_number: Option<String>,
    pub license_number: Option<String>,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SshKeyDetail {
    /// The private key never crosses to JS (it's the worst leak — reused across
    /// servers). Fetch it on demand with `reveal_field(id, "sshPrivateKey")`.
    pub has_private_key: bool,
    pub public_key: Option<String>,
    pub key_fingerprint: Option<String>,
}

// ============ Inputs for create/update ============

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct LoginInput {
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub uris: Vec<String>,
    #[serde(default)]
    pub totp: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct CardInput {
    #[serde(default)]
    pub cardholder_name: Option<String>,
    #[serde(default)]
    pub brand: Option<String>,
    #[serde(default)]
    pub number: Option<String>,
    #[serde(default)]
    pub exp_month: Option<String>,
    #[serde(default)]
    pub exp_year: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct IdentityInput {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub middle_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub address1: Option<String>,
    #[serde(default)]
    pub address2: Option<String>,
    #[serde(default)]
    pub address3: Option<String>,
    #[serde(default)]
    pub city: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub postal_code: Option<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub company: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub ssn: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub passport_number: Option<String>,
    #[serde(default)]
    pub license_number: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SshKeyInput {
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub key_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct CipherCreateInput {
    pub name: String,
    #[serde(default)]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub login: Option<LoginInput>,
    #[serde(default)]
    pub card: Option<CardInput>,
    #[serde(default)]
    pub identity: Option<IdentityInput>,
    #[serde(default)]
    pub ssh_key: Option<SshKeyInput>,
    /// Discriminator chosen by the UI. Accepted values: 1 (Login),
    /// 2 (SecureNote), 3 (Card), 4 (Identity), 5 (SshKey).
    #[serde(default = "default_cipher_type")]
    pub cipher_type: u8,
    /// When set, the cipher is created inside the named organization and
    /// gets encrypted with the matching org key instead of the user key.
    /// Ignored on personal items.
    #[serde(default)]
    pub organization_id: Option<String>,
    /// Collection(s) the cipher should live in when it belongs to an
    /// organization.  Ignored when `organization_id` is `None`.
    #[serde(default)]
    pub collection_ids: Vec<String>,
    /// Custom fields, in display order. Sent on every write: the cipher
    /// PUT has replace semantics, so omitting them deletes them.
    #[serde(default)]
    pub fields: Vec<CustomFieldInput>,
    /// Ask for the master password before revealing this item's secrets.
    #[serde(default)]
    pub reprompt: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct CustomFieldInput {
    /// 0 text, 1 hidden, 2 boolean, 3 linked.
    #[serde(default)]
    pub kind: u8,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    /// Only meaningful for linked fields (kind 3); echoed back untouched
    /// so an item edited here keeps a link another client set up.
    #[serde(default)]
    pub linked_id: Option<i32>,
}

fn default_cipher_type() -> u8 {
    1
}

// ============ Sync summary (vers Svelte) ============

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct SyncSummary {
    pub email: String,
    pub name: Option<String>,
    pub item_count: usize,
    pub folder_count: usize,
    pub collection_count: usize,
    pub organization_count: usize,
    pub type_counts: TypeCounts,
    pub folders: Vec<FolderSummary>,
    pub organizations: Vec<OrganizationSummary>,
    pub collections: Vec<CollectionSummary>,
    pub ciphers: Vec<CipherSummary>,
}

#[derive(Debug, Clone, Default, Serialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct TypeCounts {
    pub login: usize,
    pub secure_note: usize,
    pub card: usize,
    pub identity: usize,
    pub ssh_key: usize,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct FolderSummary {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationSummary {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct CollectionSummary {
    pub id: String,
    pub organization_id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct CipherSummary {
    pub id: String,
    pub kind: u8,
    pub name: String,
    pub folder_id: Option<String>,
    pub organization_id: Option<String>,
    pub collection_ids: Vec<String>,
    pub favorite: bool,
    pub primary_uri: Option<String>,
    pub username: Option<String>,
    pub revision_date: Option<String>,
    pub deleted_date: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The frontend reads `data.webauthnChallenge`. Serde's `rename_all` on
    /// an enum only touches variant names, so without `rename_all_fields`
    /// this field ships as `webauthn_challenge`, the WebView sees
    /// `undefined`, and logging in with a security key dies on "the server
    /// sent no WebAuthn challenge" — with the server having sent one.
    #[test]
    fn two_factor_outcome_is_camel_cased_for_the_webview() {
        let json = serde_json::to_value(LoginOutcome::TwoFactorRequired {
            providers: vec![
                TwoFactorProvider::Authenticator,
                TwoFactorProvider::WebAuthn,
            ],
            webauthn_challenge: Some("{\"publicKey\":{}}".into()),
        })
        .expect("serialise");

        assert_eq!(json["type"], "twoFactorRequired");
        assert_eq!(json["data"]["webauthnChallenge"], "{\"publicKey\":{}}");
        assert!(
            json["data"].get("webauthn_challenge").is_none(),
            "snake_case field leaked to the IPC boundary: {json}"
        );
        assert_eq!(json["data"]["providers"][1], 7);
    }

    #[test]
    fn two_factor_outcome_omits_an_absent_challenge() {
        let json = serde_json::to_value(LoginOutcome::TwoFactorRequired {
            providers: vec![TwoFactorProvider::Authenticator],
            webauthn_challenge: None,
        })
        .expect("serialise");

        assert!(json["data"].get("webauthnChallenge").is_none());
    }
}
