use aes::Aes256;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac_array;
use rand::RngCore;
use rsa::{pkcs8::DecodePrivateKey, Oaep, RsaPrivateKey};
use secrecy::{ExposeSecret, SecretString};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::models::KdfType;

type Aes256CbcDec = cbc::Decryptor<Aes256>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

pub struct MasterPasswordHash(String);

impl MasterPasswordHash {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey {
    enc: [u8; 32],
    mac: [u8; 32],
}

impl SymmetricKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(Error::Crypto {
                reason: format!("symmetric key must be 64 bytes, got {}", bytes.len()),
            });
        }
        let mut enc = [0u8; 32];
        let mut mac = [0u8; 32];
        enc.copy_from_slice(&bytes[..32]);
        mac.copy_from_slice(&bytes[32..]);
        Ok(Self { enc, mac })
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
            let params = Params::new(
                memory_mib.saturating_mul(1024),
                iterations,
                parallelism,
                Some(32),
            )
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
    let hash =
        pbkdf2_hmac_array::<Sha256, 32>(&master_key.0, password.expose_secret().as_bytes(), 1);
    MasterPasswordHash(STANDARD.encode(hash))
}

pub fn stretch_master_key(master_key: &MasterKey) -> Result<SymmetricKey> {
    let hk = Hkdf::<Sha256>::from_prk(&master_key.0).map_err(|e| Error::Crypto {
        reason: format!("HKDF from_prk: {e}"),
    })?;
    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    hk.expand(b"enc", &mut enc).map_err(|e| Error::Crypto {
        reason: format!("HKDF expand enc: {e}"),
    })?;
    hk.expand(b"mac", &mut mac).map_err(|e| Error::Crypto {
        reason: format!("HKDF expand mac: {e}"),
    })?;
    Ok(SymmetricKey { enc, mac })
}

pub enum EncString {
    AesCbc256HmacSha256 {
        iv: Vec<u8>,
        ciphertext: Vec<u8>,
        mac: Vec<u8>,
    },
    Rsa2048OaepSha1 {
        ciphertext: Vec<u8>,
    },
}

impl EncString {
    pub fn parse(s: &str) -> Result<Self> {
        let (kind_str, rest) = s.split_once('.').ok_or_else(|| Error::Crypto {
            reason: "EncString missing type prefix".into(),
        })?;

        match kind_str {
            "2" => {
                let parts: Vec<&str> = rest.split('|').collect();
                if parts.len() != 3 {
                    return Err(Error::Crypto {
                        reason: format!("EncString type 2 expects 3 parts, got {}", parts.len()),
                    });
                }
                let iv = STANDARD.decode(parts[0]).map_err(|e| Error::Crypto {
                    reason: format!("invalid IV base64: {e}"),
                })?;
                let ciphertext = STANDARD.decode(parts[1]).map_err(|e| Error::Crypto {
                    reason: format!("invalid ciphertext base64: {e}"),
                })?;
                let mac = STANDARD.decode(parts[2]).map_err(|e| Error::Crypto {
                    reason: format!("invalid MAC base64: {e}"),
                })?;
                if iv.len() != 16 {
                    return Err(Error::Crypto {
                        reason: format!("IV must be 16 bytes, got {}", iv.len()),
                    });
                }
                if mac.len() != 32 {
                    return Err(Error::Crypto {
                        reason: format!("MAC must be 32 bytes, got {}", mac.len()),
                    });
                }
                Ok(Self::AesCbc256HmacSha256 {
                    iv,
                    ciphertext,
                    mac,
                })
            }
            "4" => {
                let ciphertext = STANDARD.decode(rest).map_err(|e| Error::Crypto {
                    reason: format!("invalid RSA ciphertext base64: {e}"),
                })?;
                Ok(Self::Rsa2048OaepSha1 { ciphertext })
            }
            other => Err(Error::Crypto {
                reason: format!("unsupported EncString type: {other}"),
            }),
        }
    }

    pub fn decrypt_sym(&self, key: &SymmetricKey) -> Result<Vec<u8>> {
        match self {
            Self::AesCbc256HmacSha256 {
                iv,
                ciphertext,
                mac,
            } => {
                let mut hmac = HmacSha256::new_from_slice(&key.mac).map_err(|e| Error::Crypto {
                    reason: format!("HMAC init: {e}"),
                })?;
                hmac.update(iv);
                hmac.update(ciphertext);
                hmac.verify_slice(mac).map_err(|_| Error::Crypto {
                    reason: "MAC verification failed (wrong key or tampered data)".into(),
                })?;

                let cipher =
                    Aes256CbcDec::new_from_slices(&key.enc, iv).map_err(|e| Error::Crypto {
                        reason: format!("AES-CBC init: {e}"),
                    })?;
                cipher
                    .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
                    .map_err(|e| Error::Crypto {
                        reason: format!("AES-CBC decrypt: {e}"),
                    })
            }
            Self::Rsa2048OaepSha1 { .. } => Err(Error::Crypto {
                reason: "RSA EncString cannot be decrypted with a symmetric key".into(),
            }),
        }
    }

    pub fn decrypt_rsa(&self, private_key: &RsaPrivateKey) -> Result<Vec<u8>> {
        match self {
            Self::Rsa2048OaepSha1 { ciphertext } => {
                let padding = Oaep::new::<Sha1>();
                private_key
                    .decrypt(padding, ciphertext)
                    .map_err(|e| Error::Crypto {
                        reason: format!("RSA-OAEP-SHA1 decrypt: {e}"),
                    })
            }
            Self::AesCbc256HmacSha256 { .. } => Err(Error::Crypto {
                reason: "symmetric EncString cannot be decrypted with an RSA key".into(),
            }),
        }
    }

    pub fn decrypt_string_sym(&self, key: &SymmetricKey) -> Result<String> {
        let bytes = self.decrypt_sym(key)?;
        String::from_utf8(bytes).map_err(|e| Error::Crypto {
            reason: format!("decrypted bytes are not valid UTF-8: {e}"),
        })
    }
}

pub fn decrypt_user_key(master_key: &MasterKey, token_set_key: &str) -> Result<SymmetricKey> {
    let stretched = stretch_master_key(master_key)?;
    let encstring = EncString::parse(token_set_key)?;
    let bytes = encstring.decrypt_sym(&stretched)?;
    SymmetricKey::from_bytes(&bytes)
}

pub fn decrypt_private_key(
    user_key: &SymmetricKey,
    encrypted_pkcs8: &str,
) -> Result<RsaPrivateKey> {
    let encstring = EncString::parse(encrypted_pkcs8)?;
    let pkcs8_bytes = encstring.decrypt_sym(user_key)?;
    RsaPrivateKey::from_pkcs8_der(&pkcs8_bytes).map_err(|e| Error::Crypto {
        reason: format!("invalid PKCS8 private key: {e}"),
    })
}

pub fn decrypt_org_key(
    user_key: &SymmetricKey,
    private_key: Option<&RsaPrivateKey>,
    encrypted: &str,
) -> Result<SymmetricKey> {
    let encstring = EncString::parse(encrypted)?;
    let bytes = match &encstring {
        EncString::AesCbc256HmacSha256 { .. } => encstring.decrypt_sym(user_key)?,
        EncString::Rsa2048OaepSha1 { .. } => {
            let pk = private_key.ok_or_else(|| Error::Crypto {
                reason:
                    "RSA-encrypted org key requires the user's private key, which is not available"
                        .into(),
            })?;
            encstring.decrypt_rsa(pk)?
        }
    };
    SymmetricKey::from_bytes(&bytes)
}

pub fn decrypt_name(encrypted: &str, key: &SymmetricKey) -> Result<String> {
    EncString::parse(encrypted)?.decrypt_string_sym(key)
}

pub fn reencrypt_with_key(
    encrypted: &str,
    from_key: &SymmetricKey,
    to_key: &SymmetricKey,
) -> Result<String> {
    let plaintext = EncString::parse(encrypted)?.decrypt_string_sym(from_key)?;
    encrypt_string(&plaintext, to_key)
}

pub fn encrypt_string(plaintext: &str, key: &SymmetricKey) -> Result<String> {
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    let cipher = Aes256CbcEnc::new_from_slices(&key.enc, &iv).map_err(|e| Error::Crypto {
        reason: format!("AES-CBC encrypt init: {e}"),
    })?;
    let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_bytes());

    let mut mac = HmacSha256::new_from_slice(&key.mac).map_err(|e| Error::Crypto {
        reason: format!("HMAC init: {e}"),
    })?;
    mac.update(&iv);
    mac.update(&ciphertext);
    let mac_bytes = mac.finalize().into_bytes();

    Ok(format!(
        "2.{}|{}|{}",
        STANDARD.encode(iv),
        STANDARD.encode(&ciphertext),
        STANDARD.encode(mac_bytes)
    ))
}
