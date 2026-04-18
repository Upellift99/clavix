use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use pbkdf2::pbkdf2_hmac_array;
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::models::KdfType;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

pub struct MasterPasswordHash(String);

impl MasterPasswordHash {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub fn derive_master_key(
    password: &SecretString,
    email: &str,
    kdf: KdfType,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
) -> Result<MasterKey> {
    let email_lower = email.trim().to_ascii_lowercase();
    let password_bytes = password.expose_secret().as_bytes();

    let bytes = match kdf {
        KdfType::Pbkdf2 => {
            pbkdf2_hmac_array::<Sha256, 32>(password_bytes, email_lower.as_bytes(), iterations)
        }
        KdfType::Argon2id => {
            let memory_mib = memory.ok_or_else(|| Error::Crypto {
                reason: "kdfMemory required for Argon2id".into(),
            })?;
            let parallelism = parallelism.ok_or_else(|| Error::Crypto {
                reason: "kdfParallelism required for Argon2id".into(),
            })?;

            let salt: [u8; 32] = Sha256::digest(email_lower.as_bytes()).into();
            let params =
                Params::new(memory_mib.saturating_mul(1024), iterations, parallelism, Some(32))
                    .map_err(|e| Error::Crypto {
                        reason: format!("invalid Argon2 parameters: {e}"),
                    })?;
            let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

            let mut out = [0u8; 32];
            argon
                .hash_password_into(password_bytes, &salt, &mut out)
                .map_err(|e| Error::Crypto {
                    reason: format!("Argon2id derivation failed: {e}"),
                })?;
            out
        }
    };

    Ok(MasterKey(bytes))
}

pub fn derive_master_password_hash(
    master_key: &MasterKey,
    password: &SecretString,
) -> MasterPasswordHash {
    let hash = pbkdf2_hmac_array::<Sha256, 32>(
        &master_key.0,
        password.expose_secret().as_bytes(),
        1,
    );
    MasterPasswordHash(STANDARD.encode(hash))
}
