use crate::{
    config::Config,
    error::Responder,
    request::Message,
    response::{Response, Status},
};
use std::sync::Arc;
use tokio::{io::BufStream, net::TcpStream};
use tokio_rustls::{rustls::pki_types::CertificateDer, TlsAcceptor};
use tracing::{debug, error, info};

/// Reads requests and writes responses to an open TLS stream
pub async fn handler(mut socket: TcpStream, acceptor: TlsAcceptor, memory: Arc<Config>) {
    match acceptor.accept(&mut socket).await {
        Ok(stream) => {
            let certs: Option<CertificateDer> =
                if let Some(val) = stream.get_ref().1.peer_certificates() {
                    Some(val.get(0).unwrap().to_owned())
                } else {
                    None
                };
            let mut buf = BufStream::new(stream);

            let (status, message): (Status, Option<Message>) = if let Some(val) = certs {
                match Message::from(memory.base.store.join("trust/"), val, &mut buf).await {
                    Ok(msg) => (
                        match msg
                            .save(&memory.base.store, &memory.mailbox, &memory.base.host)
                            .await
                        {
                            Ok(fingerprint) => Status::MESSAGE_DELIVERED(fingerprint),
                            Err(err) => err.into_response(),
                        },
                        Some(msg),
                    ),
                    Err(err) => (err.into_response(), None),
                }
            } else {
                (Status::CERTIFICATE_REQUIRED, None)
            };

            match Response::from(status.clone()).write(&mut buf).await {
                Ok(_) => {
                    debug!("response sent ({status})");
                    if matches!(status, Status::MESSAGE_DELIVERED(_)) {
                        let u_message = message.unwrap();
                        info!(
                            "message received ({} -> {})",
                            u_message.sender, u_message.recipient
                        );
                    }
                }
                Err(msg) => error!("response failed ({msg})"),
            }
        }
        Err(err) => error!("connection error ({err})"),
    }
}
