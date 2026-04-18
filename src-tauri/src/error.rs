use serde::{Serialize, Serializer};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("URL invalide : {0}")]
    InvalidUrl(String),

    #[error("Erreur réseau : {0}")]
    Network(#[from] reqwest::Error),

    #[error("Réponse serveur invalide : {0}")]
    InvalidResponse(String),

    #[error("Le serveur a renvoyé une erreur HTTP {status} : {message}")]
    HttpStatus { status: u16, message: String },
}

pub type Result<T> = std::result::Result<T, Error>;

impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
