use crate::error::{EstampaError, RequestError};
use std::str::FromStr;
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
            path: path.to_string(),
        })
    }
}

#[derive(Debug)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
pub enum Status {
    SUCCESS((String, Vec<u8>)),
    NOT_FOUND(String),
    INTERNAL_SERVER_ERROR(String),
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct Response {
    pub status: u8,
    pub content: Vec<u8>,
}

#[allow(dead_code)]
impl Response {
    pub async fn write<O: AsyncWrite + Unpin>(&self, stream: &mut O) -> Result<(), EstampaError> {
        let mut response = format!("{} ", self.status).into_bytes();

        for byte in self.content.clone().iter() {
            response.push(*byte);
        }

        stream.write_all(&response).await?;
        stream.flush().await?;

        Ok(())
    }
}
