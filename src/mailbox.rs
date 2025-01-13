use crate::error::RequestError;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::{
    fmt::Display,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::{debug, error};

#[derive(Debug, Default, Clone)]
pub struct Identity {
    pub mailbox: String,
    pub hostname: String,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub sender: Identity,
    pub recipient: Identity,
    pub message: String,
}

#[derive(Debug)]
pub struct Mailbox<'a> {
    pub owner: Identity,
    pub path: PathBuf,
    pub cert: PathBuf,
    pub tags: Vec<&'a str>,
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

impl Mailbox<'_> {
    /// Saves provided message into the mailbox
    pub fn save(&self, message: Message) -> Result<String, RequestError> {
        if !message.message.trim().is_empty() {
            let now = SystemTime::now();
            let time = now
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::new(0, 0))
                .as_millis();

            // Creates a BLAKE3 hash for the message ID
            let id = blake3::hash(
                format!("{}{}", time, message.sender)
                    .into_bytes()
                    .as_slice(),
            );

            debug!("message id: {}", id.to_string());

            let path = self.path.clone().join(format!("{}.msfn", id.to_string()));

            let mut file = File::create(path)?;
            file.write_all(message.message.as_bytes())?;
            self.tag(&id.to_string(), "Inbox")?;
        }

        // Certificate is read to respond with a fingerprint
        let mut cert_file = File::open(self.cert.clone())?;
        let mut cert_buf: Vec<u8> = vec![];

        debug!("opening certificate for mailbox {}", self.owner.mailbox);

        cert_file.read_to_end(&mut cert_buf)?;

        let mut hasher = Sha256::new();

        let pem = pem::parse(&cert_buf).map_err(|err| {
            error!(
                "certificate invalid for local mailbox {}: {err}",
                self.owner.mailbox
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
            self.owner.mailbox, &fp_fmt
        );

        Ok(fp_fmt)
    }

    /// Fetches a message from a mailbox by its ID
    pub fn get<'a>(&self, id: &'a str) -> Result<Message, RequestError> {
        let message_path = self.path.join(format!("{}.msfn", id));
        debug!("message path: {:?}", &message_path);
        let mut message_file = File::open(message_path)?;
        let mut message = String::new();

        message_file.read_to_string(&mut message)?;

        Ok(Message {
            sender: Identity::default(),
            recipient: self.owner.clone(),
            message,
        })
    }

    /// Lists either all messages, or messages contained in a tag
    pub fn list<'a>(
        &self,
        tag: Option<&'a str>,
        date: Option<DateTime<Utc>>,
    ) -> Result<Vec<String>, RequestError> {
        let files = fs::read_dir(self.path.clone())?.flatten();

        let mut messages = if let Some(tag) = tag {
            // Handles listing messages contained in a tag
            if !self.tags.contains(&tag) {
                // TODO: create custom error for missing tag
                return Err(RequestError::InvalidRequest);
            }

            let tag_path = self.path.join(format!(".{}", tag));
            let mut tag_file =
                File::open(tag_path.clone()).or_else(|_| File::create(tag_path.clone()))?;
            let mut tag_contents = String::new();

            tag_file.read_to_string(&mut tag_contents)?;

            // Iterate over each line, in order to convert them to strings
            tag_contents
                .lines()
                .map(|l| l.to_string())
                .collect::<Vec<String>>()
        } else {
            // Handles listing all messages
            let mut file_list: Vec<String> = vec![];

            for file in files {
                // TODO: handle failed string convertion
                let name = file
                    .file_name()
                    .into_string()
                    .map_err(|_| RequestError::InvalidRequest)?;

                if name.ends_with(".msfn") {
                    file_list.push(name.trim_end_matches(".msfn").to_string());
                }
            }

            file_list
        };

        // Filters message IDs by date, removing them accordingly from the existing message list
        if let Some(max_date) = date {
            debug!("{:?}", max_date);
            for msgid in messages.clone() {
                let mut file_name = msgid.clone();
                file_name.push_str(".msfn");

                let file_path = self.path.clone().join(file_name);

                let created: DateTime<Utc> = fs::metadata(file_path)?.created()?.into();
                if max_date > created {
                    if let Some(pos) = messages.iter().position(|m| *m == msgid) {
                        messages.remove(pos);
                    }
                }
            }
        }

        Ok(messages)
    }

    /// Toggles a tag for a message
    pub fn tag<'a>(&self, id: &'a str, tag: &'a str) -> Result<(), RequestError> {
        if !self.tags.contains(&tag) {
            // TODO: create custom error for missing tag
            return Err(RequestError::InvalidRequest);
        }

        if !self.path.join(format!("{}.msfn", id)).exists() {
            return Err(RequestError::NotFound);
        }

        // Reads tag to inspect if the ID is present in it
        let tag_path = self.path.join(format!(".{}", tag));
        let mut tag_contents = String::new();

        if tag_path.exists() {
            let mut tag_file = File::open(tag_path.clone())?;
            tag_file.read_to_string(&mut tag_contents)?;
        }

        let mut common_tag_opts = OpenOptions::new();
        common_tag_opts.write(true).create(true);

        if !tag_contents.contains(id) {
            // Add message ID to tag
            let mut tag_mod = common_tag_opts
                .clone()
                .append(true)
                .open(tag_path.clone())?;
            tag_mod.write_all(id.as_bytes())?;
        }

        Ok(())
    }

    pub fn untag<'a>(&self, id: &'a str, tag: &'a str) -> Result<(), RequestError> {
        if !self.tags.contains(&tag) {
            // TODO: create custom error for missing tag
            return Err(RequestError::InvalidRequest);
        }

        if !self.path.join(format!("{}.msfn", tag)).exists() {
            return Err(RequestError::NotFound);
        }

        // Reads tag to inspect if the ID is present in it
        let tag_path = self.path.join(format!(".{}", tag));
        let mut tag_file = File::open(tag_path.clone())?;
        let mut tag_contents = String::new();
        tag_file.read_to_string(&mut tag_contents)?;

        let mut common_tag_opts = OpenOptions::new();
        common_tag_opts.write(true).create(true);

        if tag_contents.contains(id) {
            // Remove message ID from tag
            let mut tag_mod = common_tag_opts
                .clone()
                .truncate(true)
                .open(tag_path.clone())?;

            tag_mod.write_all(
                tag_contents
                    .lines()
                    .filter(|l| l != &id)
                    .collect::<String>()
                    .as_bytes(),
            )?;
        } else {
            return Err(RequestError::NotFound);
        }

        Ok(())
    }

    /// Deletes a message if it's present in the Trash tag
    pub fn delete<'a>(&self, id: &'a str) -> Result<(), RequestError> {
        let messages = self.list(Some("Trash"), None)?;

        if messages.contains(&id.to_string()) {
            self.tag(id, "Trash")?;
            fs::remove_file(self.path.join(format!("{}.msfn", id)))?;
        } else {
            return Err(RequestError::NotFound);
        }

        Ok(())
    }
}
