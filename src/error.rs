use crate::response::Status;
use thiserror::Error;

pub trait Responder {
    fn into_response(&self) -> Status;
}

#[derive(Error, Debug)]
pub enum EstampaError {
    #[error("incomplete x509 chain")]
    IncompleteX509Chain,
    #[error("io error: {0}")]
    IO(#[from] std::io::Error),
    #[error("failed to set up logger")]
    Logger(#[from] tracing::subscriber::SetGlobalDefaultError),
    #[error("tls error: {0}")]
    Tls(#[from] tokio_rustls::rustls::Error),
    #[error("certificate generation error: {0}")]
    CertificateGen(#[from] rcgen::Error),
    #[error("config error: {0}")]
    Config(#[from] toml::de::Error),
    #[error("request error: {0}")]
    Request(#[from] RequestError),
}

#[derive(Error, Debug)]
pub enum RequestError {
    #[error("max size exceeded")]
    MaxSizeExceeded,
    #[error("invalid request")]
    InvalidRequest,
    #[error("mailbox not found")]
    MailboxNotFound,
    #[error("domain not serviced")]
    DomainNotServiced,
    #[error("mailbox disabled")]
    MailboxDisabled,
    // Parenthesis format is used, since this is only considered a "sub-error"
    #[error("(verification error) {0}")]
    Verification(#[from] VerificationError),
    #[error("(io error) {0}")]
    IO(#[from] std::io::Error),
}

#[derive(Error, Debug)]
pub enum VerificationError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid certificate")]
    InvalidCertificate,
    #[error("invalid hostname")]
    InvalidHostname,
    #[error("(from x509_cert) {0}")]
    X509(#[from] x509_cert::der::Error),
    #[error("(io error) {0}")]
    IO(#[from] std::io::Error),
}

impl Responder for RequestError {
    fn into_response(&self) -> Status {
        match self {
            RequestError::MailboxNotFound => Status::MAILBOX_DOESNT_EXIST,
            RequestError::DomainNotServiced => Status::DOMAIN_NOT_SERVICED,
            RequestError::MailboxDisabled => Status::MAILBOX_GONE,
            RequestError::MaxSizeExceeded | RequestError::InvalidRequest => Status::BAD_REQUEST,
            RequestError::IO(_) => Status::PERMANENT_ERROR,
            RequestError::Verification(inner) => inner.into_response(),
        }
    }
}

impl Responder for VerificationError {
    fn into_response(&self) -> Status {
        match self {
            VerificationError::InvalidSignature => Status::UNAUTHORIZED_SENDER,
            VerificationError::InvalidCertificate => Status::CERTIFICATE_INVALID,
            VerificationError::InvalidHostname => Status::YOURE_A_LIAR,
            VerificationError::IO(_) => Status::PERMANENT_ERROR,
            VerificationError::X509(_) => Status::PERMANENT_ERROR,
        }
    }
}
