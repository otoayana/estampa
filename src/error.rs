use thiserror::Error;
use x509_parser::error::X509Error;

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
    #[error("invalid signature")]
    InvalidSignature,
    #[error("no key provided")]
    KeyNotProvided,
    #[error("request too large")]
    RequestTooLarge,
    #[error("certificate error: {0}")]
    Certificate(#[from] X509Error),
}
