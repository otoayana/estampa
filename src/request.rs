use crate::config::Mailbox;
use crate::error::RequestError;
use crate::tls::Cert;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::{
    collections::HashMap,
    fmt::Display,
    fs,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncBufRead, AsyncBufReadExt};
use tokio_rustls::rustls::pki_types::CertificateDer;
use tracing::{debug, info, warn};
use x509_cert::der::{Encode, Length};
use x509_cert::Certificate;

/*
    Only Misfin(B) will be implemented at first. Once we have basic
    functionality working, focus will shift to implementing Misfin(C).
*/

#[derive(Debug)]
pub struct Identity {
    pub mailbox: String,
    pub hostname: String,
}

#[derive(Debug)]
pub struct Message {
    pub sender: Identity,
    pub recipient: Identity,
    pub message: String,
}

impl FromStr for Message {
    type Err = RequestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (mailbox, remainder) = s
            .strip_prefix("misfin://")
            .and_then(|s| s.split_once('@'))
            .ok_or(RequestError::InvalidRequest)?;
        let (hostname, remainder) = remainder
            .split_once(' ')
            .ok_or(RequestError::InvalidRequest)?;
        let message = remainder
            .strip_suffix("\r\n")
            .ok_or(RequestError::InvalidRequest)?;

        Ok(Message {
            sender: Identity {
                hostname: String::new(),
                mailbox: String::new(),
            },
            recipient: Identity {
                mailbox: mailbox.to_string(),
                hostname: hostname.to_string(),
            },
            message: message.to_string(),
        })
    }
}

impl Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.mailbox, self.hostname)
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} -> {}", self.sender, self.recipient)
    }
}

impl Message {
    /// Issue a new Request object from a sender certificate and a Tokio stream
    pub async fn from<I: AsyncBufRead + Unpin>(
        trust_store: PathBuf,
        cert: CertificateDer<'_>,
        stream: &mut I,
    ) -> Result<Self, RequestError> {
        let sender = Cert::verify(&cert, trust_store).await?;

        let mut buf = String::new();

        while !buf.contains("\r\n") {
            stream.read_line(&mut buf).await?;

            // Misfin(B) only supports up to 2048 bytes per request
            if buf.clone().len() > 2048 {
                return Err(RequestError::MaxSizeExceeded);
            }
        }

        let mut request = buf.parse::<Message>()?;
        request.sender = sender;

        debug!("request received ({request})");
        Ok(request)
    }

    /// Stores the message created in the request to the filesystem
    pub async fn save<'a>(
        &self,
        available_mailboxes: &HashMap<String, Mailbox>,
        hostname: &'a str,
    ) -> Result<String, RequestError> {
        let mailbox = available_mailboxes
            .get(&self.recipient.mailbox)
            .ok_or(RequestError::MailboxNotFound)?;

        if self.recipient.hostname != hostname {
            return Err(RequestError::DomainNotServiced);
        }

        if !mailbox.enabled {
            return Err(RequestError::MailboxDisabled);
        }

        if !mailbox.path.exists() {
            warn!(
                "mailbox {} doesn't exist. making directory at requested path...",
                self.recipient.mailbox
            );

            fs::create_dir_all(&mailbox.path)?;
            info!("mailbox {} created successfully", self.recipient.mailbox)
        }

        let now = SystemTime::now();
        let time = now
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::new(0, 0))
            .as_millis();

        let path = mailbox
            .path
            .clone()
            .join(format!("{}-{}.gmi", time, self.sender));

        let mut file = File::create(path)?;
        file.write(self.message.as_bytes())?;

        // Certificate is read to respond with a fingerprint
        let mut cert_file = File::open(&mailbox.certificate)?;
        let mut cert_buf: Vec<u8> = vec![];
        debug!(
            "opening certificate for mailbox {} at {:?}",
            &self.recipient.mailbox, &mailbox.certificate
        );

        cert_file.read_to_end(&mut cert_buf)?;

        let mut hasher = Sha256::new();
        let pemchain = Certificate::load_pem_chain(&cert_buf)
            .map_err(|e| RequestError::Verification(crate::error::VerificationError::X509(e)))?;

        hasher.update(
            pemchain
                .first()
                // This unwrap might be a little overcomplicated, but does the trick :^)
                .ok_or(RequestError::Verification(
                    crate::error::VerificationError::X509(x509_cert::der::Error::new(
                        x509_cert::der::ErrorKind::FileNotFound,
                        Length::new(0),
                    )),
                ))?
                .to_der()
                .map_err(|e| RequestError::Verification(crate::error::VerificationError::X509(e)))?
                .to_vec(),
        );

        let fingerprint = hasher.finalize();
        let mut fp_fmt = String::new();

        for oct in fingerprint {
            fp_fmt.push_str(format!("{:x}", oct).as_str())
        }

        debug!("fingerprint is {:?}", &fingerprint);

        Ok(fp_fmt)
    }
}
