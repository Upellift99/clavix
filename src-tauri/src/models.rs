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

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "data", rename_all = "camelCase")]
pub enum LoginResult {
    Success(TokenSet),
    TwoFactorRequired { providers: Vec<TwoFactorProvider> },
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
}
