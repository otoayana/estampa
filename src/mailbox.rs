use crate::config::Mailbox;
use crate::error::RequestError;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::{
    collections::HashMap,
    fmt::Display,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::{debug, error};

#[derive(Debug, Clone)]
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

            // Creates a BLAKE3 hash for the message ID
            let id = blake3::hash(format!("{}{}", time, self.sender).into_bytes().as_slice());
            debug!("message id: {}", id.to_string());

            let path = store.join(format!(
                "mbox/{}/{}.msfn",
                self.recipient.mailbox,
                id.to_string()
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
