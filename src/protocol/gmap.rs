use crate::error::{EstampaError, RequestError};
use std::{fmt::Display, str::FromStr};
use tokio::io::{AsyncWrite, AsyncWriteExt};

#[allow(dead_code)]
#[derive(Debug)]
pub struct Request {
    pub host: String,
    pub path: String,
}

impl FromStr for Request {
    type Err = RequestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (host, path) = s
            .strip_prefix("gemini://")
            .and_then(|s| s.split_once('/'))
            .ok_or(RequestError::InvalidRequest)?;

        Ok(Request {
            host: host.to_string(),
            path: path.trim().to_string(),
        })
    }
}

#[derive(Debug)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
pub enum Response {
    SUCCESS((String, Vec<u8>)),
    NOT_FOUND,
    INTERNAL_SERVER_ERROR,
    CERTIFICATE_REQUIERED,
}

#[allow(dead_code)]
impl Response {
    pub async fn write<O: AsyncWrite + Unpin>(&self, stream: &mut O) -> Result<(), EstampaError> {
        let mut response = format!("{} ", self).into_bytes();

        if let Response::SUCCESS((mime, _)) = self {
            for byte in mime.clone().into_bytes() {
                response.push(byte);
            }
        }

        for byte in "\r\n".as_bytes() {
            response.push(*byte)
        }

        if let Response::SUCCESS((_, data)) = self {
            for byte in data.clone().iter() {
                response.push(*byte);
            }
        }

        stream.write_all(&response).await?;
        stream.flush().await?;

        Ok(())
    }
}

impl Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Response::SUCCESS(_) => 20,
                Response::NOT_FOUND => 51,
                Response::INTERNAL_SERVER_ERROR => 41,
                Response::CERTIFICATE_REQUIERED => 60,
            }
        )
    }
}
