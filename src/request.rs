use crate::error::EstampaError;
use std::{fmt::Display, str::FromStr};
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

#[derive(Debug)]
#[allow(dead_code)]
pub struct Request {
    pub mailbox: String,
    pub hostname: String,
    pub message: String,
}

impl FromStr for Request {
    type Err = EstampaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (mailbox, remainder) = s
            .strip_prefix("misfin://")
            .and_then(|s| s.split_once('@'))
            .ok_or(EstampaError::Parse)?;
        let (hostname, remainder) = remainder.split_once(' ').ok_or(EstampaError::Parse)?;
        let message = remainder.strip_suffix("\r\n").ok_or(EstampaError::Parse)?;

        Ok(Request {
            mailbox: mailbox.to_string(),
            hostname: hostname.to_string(),
            message: message.to_string(),
        })
    }
}

impl Display for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.mailbox, self.hostname)
    }
}

impl Request {
    #[allow(dead_code)]
    pub async fn fetch<I: AsyncBufRead + Unpin>(stream: &mut I) -> Result<Self, EstampaError> {
        let mut buf = String::new();

        while !buf.contains("\r\n") {
            stream.read_line(&mut buf).await?;

            if buf.clone().len() > 2048 {
                return Err(EstampaError::RequestTooLarge);
            }
        }

        let request = buf.parse::<Request>()?;

        Ok(request)
    }
}
