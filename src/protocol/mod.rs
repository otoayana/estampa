pub mod gmap;
pub mod misfin;

use crate::{
    error::{EstampaError, RequestError, Responder},
    mailbox::Message,
};
use misfin::{b, c9};
use std::{fmt::Display, path::PathBuf, str::FromStr};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite};
use tokio_rustls::rustls::pki_types::CertificateDer;
use tracing::debug;

#[derive(Debug)]
pub enum Request {
    MisfinB(b::Request),
    MisfinC(c9::Request),
    // TODO(otoayana): implement GMAP support
    #[allow(dead_code)]
    GMAP(gmap::Request),
}

pub trait AsMessage {
    type Err: Responder;

    async fn as_message(
        &self,
        cert: Option<CertificateDer<'_>>,
        trust: PathBuf,
    ) -> Result<Message, Self::Err>;
}

impl Request {
    /// Parses and identifies a request
    pub async fn parse<I: AsyncBufRead + Unpin>(stream: &mut I) -> Result<Self, RequestError> {
        let mut buffer: Vec<u8> = Vec::new();
        stream.read_until(0x0d, &mut buffer).await?;
        let buffer_string =
            String::from_utf8(buffer.clone()).map_err(|_| RequestError::InvalidRequest)?;

        debug!("buffer contents: {}", &buffer_string);

        if let Ok(message) = b::Request::from_str(&buffer_string) {
            debug!("request identified as misfin(b)");

            if buffer.len() > 2048 {
                return Err(RequestError::MaxSizeExceeded);
            }

            return Ok(Self::MisfinB(message));
        }

        // Any other protocols require their header piece to be 1024 bytes at most.
        if buffer.len() > 1024 {
            return Err(RequestError::MaxSizeExceeded);
        }

        if let Ok(mut message) = c9::Request::from_str(&buffer_string) {
            debug!("request identified as misfin(c9)");
            if message.content_length > 16384 {
                return Err(RequestError::MaxSizeExceeded);
            }

            if message.content_length > 0 {
                // Consumes the line feed in CRLF
                stream.consume(1);

                let message_buf = stream
                    .fill_buf()
                    .await?
                    .iter()
                    .take(message.content_length.into())
                    .map(|v| v.to_owned())
                    .collect::<Vec<u8>>();

                // Marks the buffer as consumed
                stream.consume(message.content_length.into());

                let mut parsed_message =
                    String::from_utf8(message_buf).map_err(|_| RequestError::InvalidRequest)?;

                parsed_message.push_str("\n");
                message.message = Some(parsed_message);
            }

            return Ok(Self::MisfinC(message));
        }

        if let Ok(request) = gmap::Request::from_str(&buffer_string) {
            debug!("request identified as gmap");
            return Ok(Self::GMAP(request));
        }

        debug!("unknown request");

        Err(RequestError::InvalidRequest)
    }
}

#[derive(Debug)]
pub enum Response {
    Misfin(misfin::Response),
    GMAP(gmap::Response),
}

impl Response {
    pub async fn write<O: AsyncWrite + Unpin>(&self, stream: &mut O) -> Result<(), EstampaError> {
        match self {
            Self::Misfin(res) => res.write(stream).await,
            Self::GMAP(res) => res.write(stream).await,
        }
    }
}

impl Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Response::Misfin(inner) => format!("{}", inner),
                Response::GMAP(inner) => format!("{}", inner),
            }
        )
    }
}
