use tokio_rustls::rustls::pki_types::CertificateDer;

use crate::{
    error::RequestError,
    mailbox::{Identity, Message},
    protocol::AsMessage,
    tls::Cert,
};
use std::{path::PathBuf, str::FromStr};

#[derive(Debug)]
pub struct Request {
    pub mailbox: String,
    pub hostname: String,
    pub content_length: u16,
    pub message: Option<String>,
}

impl FromStr for Request {
    type Err = RequestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (mailbox, remainder) = s
            .strip_prefix("misfin://")
            .and_then(|s| s.split_once('@'))
            .ok_or(RequestError::InvalidRequest)?;

        let (hostname, content_length) = remainder
            .split_once(0x09 as char)
            .ok_or(RequestError::InvalidRequest)?;

        let content_length = content_length
            .to_string()
            .trim_end()
            .parse::<u16>()
            .map_err(|_| RequestError::InvalidRequest)?;

        Ok(Request {
            mailbox: mailbox.to_string(),
            hostname: hostname.to_string(),
            content_length,
            message: None,
        })
    }
}

impl AsMessage for Request {
    type Err = RequestError;

    async fn as_message(
        &self,
        cert: Option<CertificateDer<'_>>,
        trust: PathBuf,
    ) -> Result<Message, Self::Err> {
        let mut message = Message {
            sender: Identity {
                mailbox: String::new(),
                hostname: String::new(),
            },
            recipient: Identity {
                mailbox: self.mailbox.clone(),
                hostname: self.hostname.clone(),
            },
            message: String::new(),
        };

        if let Some(text) = self.message.clone() {
            if let Some(inner) = cert {
                let sender = Cert::verify(&inner, trust).await?;
                message.sender = sender;
                message.message = text
            } else {
                return Err(RequestError::CertificateRequired);
            }
        }
        Ok(message)
    }
}
