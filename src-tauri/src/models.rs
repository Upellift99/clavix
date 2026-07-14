use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenSet {
    #[serde(rename = "access_token")]
    pub access_token: String,
    #[serde(rename = "refresh_token")]
    pub refresh_token: String,
    #[serde(rename = "expires_in")]
    pub expires_in: u64,
    #[serde(rename = "token_type")]
    pub token_type: String,

    #[serde(default, alias = "Key")]
    pub key: Option<String>,
    #[serde(default, alias = "PrivateKey")]
    pub private_key: Option<String>,
    #[serde(default, alias = "Kdf")]
    pub kdf: Option<KdfType>,
    #[serde(default, alias = "KdfIterations")]
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
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginOk {
    pub email: String,
}

/// IPC-facing variant of `LoginResult` — same shape as the old type, minus
/// the `TokenSet` payload that has no business reaching the WebView.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "camelCase")]
pub enum LoginOutcome {
    Success(LoginOk),
    TwoFactorRequired {
        providers: Vec<TwoFactorProvider>,
        #[serde(skip_serializing_if = "Option::is_none")]
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

#[derive(Debug, Clone, Serialize)]
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
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginDetail {
    pub username: Option<String>,
    pub password: Option<String>,
    pub uris: Vec<String>,
    pub totp: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardDetail {
    pub cardholder_name: Option<String>,
    pub brand: Option<String>,
    pub number: Option<String>,
    pub exp_month: Option<String>,
    pub exp_year: Option<String>,
    pub code: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
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
    pub ssn: Option<String>,
    pub username: Option<String>,
    pub passport_number: Option<String>,
    pub license_number: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshKeyDetail {
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub key_fingerprint: Option<String>,
}

// ============ Inputs for create/update ============

#[derive(Debug, Clone, Default, Deserialize)]
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

#[derive(Debug, Clone, Default, Deserialize)]
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

#[derive(Debug, Clone, Default, Deserialize)]
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

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshKeyInput {
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub key_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
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
}

fn default_cipher_type() -> u8 {
    1
}

// ============ Sync summary (vers Svelte) ============

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeCounts {
    pub login: usize,
    pub secure_note: usize,
    pub card: usize,
    pub identity: usize,
    pub ssh_key: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderSummary {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationSummary {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionSummary {
    pub id: String,
    pub organization_id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
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
