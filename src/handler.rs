use crate::{
    config::Config,
    error::{RequestError, Responder},
    mailbox::Message,
    protocol::{
        misfin::{Response, Status},
        AsMessage, Protocol,
    },
};
use std::sync::Arc;
use tokio::{
    io::{AsyncWriteExt, BufStream},
    net::TcpStream,
};
use tokio_rustls::{rustls::pki_types::CertificateDer, TlsAcceptor};
use tracing::{debug, error, info, warn};

/// Reads requests and writes responses to an open TLS stream
pub async fn handler(mut socket: TcpStream, acceptor: TlsAcceptor, memory: Arc<Config>) {
    match acceptor.accept(&mut socket).await {
        Ok(stream) => {
            let certs: Option<CertificateDer> = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|v| v.first().map(|v| v.to_owned()));
            let mut buf = BufStream::new(stream);

            let (status, message): (Status, Option<Message>) = match Protocol::parse(&mut buf).await
            {
                Ok(proto) => match proto {
                    Protocol::MisfinB(req) => misfin_handler(req, certs, memory).await,
                    Protocol::MisfinC(req) => misfin_handler(req, certs, memory).await,
                    _ => (RequestError::InvalidRequest.as_response(), None),
                },
                Err(err) => (err.as_response(), None),
            };

            match Response::from(status.clone()).write(&mut buf).await {
                Ok(_) => {
                    debug!("response sent ({status})");
                    if matches!(status, Status::MESSAGE_DELIVERED(_)) {
                        if let Some(inner) = message {
                            info!("message received ({} -> {})", inner.sender, inner.recipient)
                        } else {
                            warn!("message received, but contents unavailable")
                        };
                    }
                }
                Err(msg) => error!("response failed ({msg})"),
            }

            if buf.shutdown().await.ok().is_none() {
                error!("connection closed early");
            };
        }
        Err(err) => error!("connection error ({err})"),
    }
}

/// Stores Misfin messages, regardless of version
async fn misfin_handler(
    request: impl AsMessage,
    cert: Option<CertificateDer<'_>>,
    memory: Arc<Config>,
) -> (Status, Option<Message>) {
    match request
        .as_message(cert, memory.base.store.join("trust/"))
        .await
    {
        Ok(msg) => (
            match memory.mailbox(msg.recipient.clone()) {
                Ok(mbox) => match mbox.save(msg.clone()) {
                    Ok(fingerprint) => Status::MESSAGE_DELIVERED(fingerprint),
                    Err(err) => err.as_response(),
                },
                Err(err) => err.as_response(),
            },
            Some(msg),
        ),
        Err(err) => (err.as_response(), None),
    }
}
