pub mod gmap;
pub mod misfin;

use crate::{
    error::{RequestError, Responder},
    mailbox::Message,
};
use misfin::{b, c9};
use std::{path::PathBuf, str::FromStr};
use tokio::io::{AsyncBufRead, AsyncBufReadExt};
use tokio_rustls::rustls::pki_types::CertificateDer;
use tracing::debug;

#[derive(Debug)]
pub enum Protocol {
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

impl Protocol {
    /// Parses and identifies a request
    pub async fn parse<I: AsyncBufRead + Unpin>(stream: &mut I) -> Result<Self, RequestError> {
        let mut buffer: Vec<u8> = Vec::new();
        stream.read_until(0x0d, &mut buffer).await?;
        let buffer_string =
            String::from_utf8(buffer.clone()).map_err(|_| RequestError::InvalidRequest)?;

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

        debug!("unknown request");

        Err(RequestError::InvalidRequest)
    }
}
