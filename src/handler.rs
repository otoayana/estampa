use crate::{
    config::Config,
    error::{RequestError, Responder},
    mailbox::Message,
    protocol::{gmap, misfin, AsMessage, Request, Response},
    tls::Cert,
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

            let (response, message, path): (Response, Option<Message>, Option<String>) = async {
                let proto = Request::parse(&mut buf).await?;

                let result = match proto {
                    Request::MisfinB(req) => misfin_handler(req, certs, memory).await,
                    Request::MisfinC(req) => misfin_handler(req, certs, memory).await,
                    Request::GMAP(req) => {
                        let path = req.path.clone();

                        (
                            async move {
                                let mut host = memory.base.host.clone();
                                host.push_str(":1958");

                                if req.host != host {
                                    return Err(RequestError::InvalidRequest);
                                }

                                if let Some(cert) = certs.clone() {
                                    let identity = Cert::parse(&cert).await?;
                                    let mailbox = memory.mailbox(identity)?;

                                    let response = if req.path.starts_with("msgid/") {
                                        mailbox
                                            .get(req.path.trim_start_matches("msgid/"))?
                                            .message
                                            .into_bytes()
                                    } else if req.path.starts_with("tag/") {
                                        let tag_raw = req.path.trim_start_matches("tag/");

                                        let tag = if tag_raw.len() > 0 {
                                            Some(tag_raw)
                                        } else {
                                            None
                                        };

                                        mailbox.list(tag)?.join("\n").into_bytes()
                                    } else {
                                        return Err(RequestError::InvalidRequest);
                                    };

                                    return Ok::<gmap::Response, _>(gmap::Response::SUCCESS((
                                        "text/plain".to_string(),
                                        response,
                                    )));
                                } else {
                                    return Err(RequestError::CertificateRequired);
                                }
                            }
                            .await
                            .map_or_else(
                                |e| Response::GMAP(e.as_response().gmap),
                                |v| Response::GMAP(v),
                            ),
                            None,
                            Some(path),
                        )
                    }
                };

                Ok::<_, RequestError>(result)
            }
            .await
            .map_or_else(
                |e| (Response::Misfin(e.as_response().misfin), None, None),
                |v| v,
            );

            match response.write(&mut buf).await {
                Ok(_) => {
                    debug!("response sent ({response})");
                    if matches!(response, Response::Misfin(_)) {
                        if let Some(inner) = message {
                            info!("message received ({} -> {})", inner.sender, inner.recipient)
                        } else {
                            warn!("message received, but contents unavailable")
                        };
                    } else if let Response::GMAP(status) = response {
                        info!(
                            "gmap response sent ({}, /{})",
                            status,
                            path.unwrap_or(String::new())
                        )
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
) -> (Response, Option<Message>, Option<String>) {
    let out = async move {
        let trust = memory.base.store.join("trust/");
        let message = request
            .as_message(cert, trust)
            .await
            .map_err(|_| RequestError::InvalidRequest)?;
        let fingerprint = memory
            .mailbox(message.recipient.clone())?
            .save(message.clone())?;
        Ok::<_, RequestError>((misfin::Response::MESSAGE_DELIVERED(fingerprint), message))
    }
    .await
    .map_or_else(|e| (e.as_response().misfin, None), |v| (v.0, Some(v.1)));

    (Response::Misfin(out.0), out.1, None)
}
