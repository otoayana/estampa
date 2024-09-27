use crate::error::EstampaError;
use std::fmt::Display;
use tokio::io::{AsyncWrite, AsyncWriteExt};

#[derive(Clone, Debug)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
pub enum Status {
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

#[derive(Debug)]
pub struct Response {
    status: Status,
}

impl Status {
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

impl Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}",
            self.as_u8(),
            match self {
                Self::MESSAGE_DELIVERED(fprint) => format!(" {}", fprint),
                Self::SEND_HERE_INSTEAD(addr) => format!(" {}", addr),
                Self::SEND_HERE_FOREVER(addr) => format!(" {}", addr),
                _ => String::new(),
            }
        )
    }
}

impl Response {
    pub fn from(status: Status) -> Response {
        Response { status }
    }

    pub async fn write<O: AsyncWrite + Unpin>(&self, stream: &mut O) -> Result<(), EstampaError> {
        let response = format!("{}\r\n", self.status).into_bytes();

        stream.write_all(&response).await?;
        stream.flush().await?;

        Ok(())
    }
}
