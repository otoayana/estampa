use crate::response::Status;
use thiserror::Error;

pub trait Responder {
    fn as_response(&self) -> Status;
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

    #[error("time error: {0}")]
    Time(#[from] time::error::ComponentRange),

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

    #[error("bad mailbox certificate")]
    BadMailboxCertificate,

    #[error("authentication required")]
    CertificateRequired,

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

    #[error("(from x509_parser) {0}")]
    X509(#[from] x509_parser::error::X509Error),

    #[error("(io error) {0}")]
    IO(#[from] std::io::Error),
}

impl Responder for RequestError {
    fn as_response(&self) -> Status {
        match self {
            Self::CertificateRequired => Status::CERTIFICATE_REQUIRED,
            Self::MailboxNotFound => Status::MAILBOX_DOESNT_EXIST,
            Self::DomainNotServiced => Status::DOMAIN_NOT_SERVICED,
            Self::MailboxDisabled => Status::MAILBOX_GONE,
            Self::BadMailboxCertificate => Status::PERMANENT_ERROR,
            Self::MaxSizeExceeded | Self::InvalidRequest => Status::BAD_REQUEST,
            Self::IO(_) => Status::PERMANENT_ERROR,
            Self::Verification(inner) => inner.as_response(),
        }
    }
}

impl Responder for VerificationError {
    fn as_response(&self) -> Status {
        match self {
            Self::InvalidCertificate => Status::CERTIFICATE_INVALID,
            Self::InvalidSignature | Self::InvalidHostname => Status::YOURE_A_LIAR,
            _ => Status::PERMANENT_ERROR,
        }
    }
}
