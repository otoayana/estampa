use crate::error::EstampaError;
use std::fmt::Display;
use tokio::io::{AsyncWrite, AsyncWriteExt};

#[derive(Clone, Debug)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
pub enum Response {
    MESSAGE_DELIVERED(String),
    SEND_HERE_INSTEAD(String),
    SEND_HERE_FOREVER(String),
    TEMPORARY_ERROR,
    SERVER_IS_UNAVAILABLE,
    CGI_ERROR,
    PROXYING_ERROR,
    SLOW_DOWN,
    MAILBOX_FULL,
    PERMANENT_ERROR,
    MAILBOX_DOESNT_EXIST,
    MAILBOX_GONE,
    DOMAIN_NOT_SERVICED,
    BAD_REQUEST,
    CERTIFICATE_REQUIRED,
    UNAUTHORIZED_SENDER,
    CERTIFICATE_INVALID,
    YOURE_A_LIAR,
    PROVE_IT,
}

impl Response {
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::MESSAGE_DELIVERED(_) => 20,
            Self::SEND_HERE_INSTEAD(_) => 30,
            Self::SEND_HERE_FOREVER(_) => 31,
            Self::TEMPORARY_ERROR => 40,
            Self::SERVER_IS_UNAVAILABLE => 41,
            Self::CGI_ERROR => 42,
            Self::PROXYING_ERROR => 43,
            Self::SLOW_DOWN => 44,
            Self::MAILBOX_FULL => 45,
            Self::PERMANENT_ERROR => 50,
            Self::MAILBOX_DOESNT_EXIST => 51,
            Self::MAILBOX_GONE => 52,
            Self::DOMAIN_NOT_SERVICED => 53,
            Self::BAD_REQUEST => 59,
            Self::CERTIFICATE_REQUIRED => 60,
            Self::UNAUTHORIZED_SENDER => 61,
            Self::CERTIFICATE_INVALID => 62,
            Self::YOURE_A_LIAR => 63,
            Self::PROVE_IT => 64,
        }
    }
}

impl Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}",
            self.as_u8(),
            match self {
                Self::MESSAGE_DELIVERED(fprint) => fprint.clone(),
                Self::SEND_HERE_INSTEAD(addr) => addr.clone(),
                Self::SEND_HERE_FOREVER(addr) => addr.clone(),
                _ => String::new(),
            }
        )
    }
}

impl Response {
    pub async fn write<O: AsyncWrite + Unpin>(&self, stream: &mut O) -> Result<(), EstampaError> {
        let response = format!("{}\r\n", self).into_bytes();

        stream.write_all(&response).await?;
        stream.flush().await?;

        Ok(())
    }
}
