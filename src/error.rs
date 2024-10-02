use thiserror::Error;

#[derive(Error, Debug)]
pub enum EstampaError {
    #[error("io error: {0}")]
    IO(#[from] std::io::Error),
    #[error("failed to set up logger")]
    Logger,
    #[error("failed to parse request")]
    Parse,
    #[error("tls error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("config error: {0}")]
    Config(#[from] toml::de::Error),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("no key provided")]
    KeyNotProvided,
    #[error("request too large")]
    RequestTooLarge,
    #[error("certificate error: {0}")]
    Certificate(#[from] x509_cert::der::Error),
    #[error("verification error")]
    Verification,
}
