use crate::config::Mailbox;
use crate::error::RequestError;
use crate::tls::Cert;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::{
    collections::HashMap,
    fmt::Display,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncBufRead, AsyncBufReadExt};
use tokio_rustls::rustls::pki_types::CertificateDer;
use tracing::{debug, error};

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

        let mut message = remainder
            .strip_suffix("\r\n")
            .ok_or(RequestError::InvalidRequest)?
            .to_string();

        message.push('\n');

        Ok(Message {
            sender: Identity {
                hostname: String::new(),
                mailbox: String::new(),
            },
            recipient: Identity {
                mailbox: mailbox.to_string(),
                hostname: hostname.to_string(),
            },
            message,
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
        if !self.message.is_empty() {
            write!(f, "{} -> {}", self.sender, self.recipient)
        } else {
            write!(f, "{}", self.recipient)
        }
    }
}

impl Message {
    /// Issue a new Request object from a sender certificate and a Tokio stream
    pub async fn from<I: AsyncBufRead + Unpin>(
        trust_store: PathBuf,
        cert: Option<CertificateDer<'_>>,
        stream: &mut I,
    ) -> Result<Self, RequestError> {
        let mut buf = String::new();

        while !buf.contains("\r\n") {
            stream.read_line(&mut buf).await?;

            // Misfin(B) only supports up to 2048 bytes per request
            if buf.clone().len() > 2048 {
                return Err(RequestError::MaxSizeExceeded);
            }
        }

        let mut request = buf.parse::<Message>()?;

        // Empty messages won't be verified
        if !request.message.trim().is_empty() {
            if let Some(inner) = cert {
                let sender = Cert::verify(&inner, trust_store).await?;
                request.sender = sender;
            } else {
                return Err(RequestError::CertificateRequired);
            }
        }

        debug!("request received ({request})");
        Ok(request)
    }

    /// Stores the message created in the request to the filesystem
    pub async fn save<'a>(
        &self,
        store: &Path,
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

        if !self.message.trim().is_empty() {
            let now = SystemTime::now();
            let time = now
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::new(0, 0))
                .as_millis();

            let path = store.join(format!(
                "mbox/{}/{}-{}.gmi",
                self.recipient.mailbox, time, self.sender
            ));

            let mut file = File::create(path)?;
            file.write_all(self.message.as_bytes())?;
        }

        // Certificate is read to respond with a fingerprint
        let mut cert_file =
            File::open(store.join(format!("certs/{}.pem", self.recipient.mailbox)))?;
        let mut cert_buf: Vec<u8> = vec![];

        debug!("opening certificate for mailbox {}", self.recipient.mailbox);

        cert_file.read_to_end(&mut cert_buf)?;

        let mut hasher = Sha256::new();

        let pem = pem::parse(&cert_buf).map_err(|err| {
            error!(
                "certificate invalid for local mailbox {}: {err}",
                self.recipient.mailbox
            );
            RequestError::BadMailboxCertificate
        })?;
        let cert = pem.contents();

        hasher.update(cert);
        let fingerprint = hasher.finalize();

        // Certificate fingerprints need to be sent in an octet format
        let mut fp_fmt = String::new();
        for oct in fingerprint {
            fp_fmt.push_str(format!("{:02x}", oct).as_str())
        }

        debug!(
            "fingerprint for mailbox {} is {}",
            &self.recipient.mailbox, &fp_fmt
        );

        Ok(fp_fmt)
    }
}
