pub mod misfin_b;

use crate::error::RequestError;
use std::{path::PathBuf, str::FromStr};
use tokio::io::{AsyncBufRead, AsyncBufReadExt};
use tokio_rustls::rustls::pki_types::CertificateDer;
use tracing::debug;

#[derive(Debug)]
pub enum Protocol {
    MisfinB(misfin_b::Request),
    // TODO(otoayana): implement Misfin(C) support
    _MisfinC,
    // TODO(otoayana): implement GMAP support
    _GMAP,
}

pub trait AsMessage {
    type Err;

    async fn as_message(
        &self,
        cert: Option<CertificateDer<'_>>,
        trust: PathBuf,
    ) -> Result<crate::request::Message, Self::Err>;
}

impl Protocol {
    /// Parses and identifies a request
    pub async fn parse<I: AsyncBufRead + Unpin>(stream: &mut I) -> Result<Self, RequestError> {
        let mut buffer: Vec<u8> = Vec::new();
        stream.read_until(0x0d, &mut buffer).await?;

        if buffer.len() > 2048 {
            return Err(RequestError::MaxSizeExceeded);
        }

        if let Ok(message) = misfin_b::Request::from_str(
            String::from_utf8(buffer)
                .map_err(|_| RequestError::InvalidRequest)?
                .as_str(),
        ) {
            return Ok(Self::MisfinB(message));
        }

        debug!("unknown request");

        Err(RequestError::InvalidRequest)
    }
}
