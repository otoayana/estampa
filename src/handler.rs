use crate::{
    config::Config,
    error::Responder,
    request::Message,
    response::{Response, Status},
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

            let (status, message): (Status, Option<Message>) =
                match Message::from(memory.base.store.join("trust/"), certs, &mut buf).await {
                    Ok(msg) => (
                        match msg
                            .save(&memory.base.store, &memory.mailbox, &memory.base.host)
                            .await
                        {
                            Ok(fingerprint) => Status::MESSAGE_DELIVERED(fingerprint),
                            Err(err) => err.as_response(),
                        },
                        Some(msg),
                    ),
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
