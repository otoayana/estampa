use crate::{
    config::Config,
    error::{RequestError, Responder},
    mailbox::Message,
    protocol::{gmap, misfin, AsMessage, Request, Response},
    tls::Cert,
};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio::{
    io::{AsyncWriteExt, BufStream},
    net::TcpStream,
};
use tokio_rustls::{rustls::pki_types::CertificateDer, TlsAcceptor};
use tracing::{debug, error, info, warn};

#[derive(Debug)]
enum Context {
    Message(Message),
    Path(String),
}

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

            let (response, context): (Response, Option<Context>) = async {
                let proto = Request::parse(&mut buf).await?;

                let result = match proto {
                    Request::MisfinB(req) => misfin_handler(req, certs, memory).await,
                    Request::MisfinC(req) => misfin_handler(req, certs, memory).await,
                    Request::GMAP(req) => gmap_handler(req, certs, memory).await,
                };

                Ok::<_, RequestError>(result)
            }
            .await
            .map_or_else(|e| (Response::Misfin(e.as_response().misfin), None), |v| v);

            match response.write(&mut buf).await {
                Ok(_) => {
                    debug!("response sent ({response})");
                    if matches!(response, Response::Misfin(_)) {
                        if let Some(Context::Message(inner)) = context {
                            info!("message received ({} -> {})", inner.sender, inner.recipient)
                        } else {
                            warn!("message received, but contents unavailable")
                        };
                    } else if let Response::GMAP(status) = response {
                        info!(
                            "gmap response sent ({}, /{})",
                            status,
                            if let Some(Context::Path(path)) = context {
                                path
                            } else {
                                String::new()
                            }
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
) -> (Response, Option<Context>) {
    async move {
        let trust = memory.base.store.join("trust/");
        let message = request
            .as_message(cert, trust)
            .await
            .map_err(|_| RequestError::InvalidRequest)?;

        let fingerprint = if message.recipient.mailbox == "gmap".to_string() {
            memory.mailbox(message.sender.clone())
        } else {
            memory.mailbox(message.recipient.clone())
        }?
        .save(message.clone())?;

        Ok::<_, RequestError>((misfin::Response::MESSAGE_DELIVERED(fingerprint), message))
    }
    .await
    .map_or_else(
        |e| (Response::Misfin(e.as_response().misfin), None),
        |v| (Response::Misfin(v.0), Some(Context::Message(v.1))),
    )
}

/// Handles GMAP requests
async fn gmap_handler(
    request: gmap::Request,
    cert: Option<CertificateDer<'_>>,
    memory: Arc<Config>,
) -> (Response, Option<Context>) {
    let path = request.path.clone();

    (
        async move {
            let mut host = memory.base.host.clone();
            host.push_str(":1958");

            if request.host != host {
                return Err(RequestError::InvalidRequest);
            }

            if let Some(cert) = cert.clone() {
                let identity = Cert::parse(&cert).await?;
                let mailbox = memory.mailbox(identity)?;

                let response = if request.path.starts_with("msgid/") {
                    mailbox
                        .get(request.path.trim_start_matches("msgid/"))?
                        .message
                        .into_bytes()
                } else if request.path.starts_with("tag/") {
                    let metadata = request.path.trim_start_matches("tag/");

                    if let Some((tag, msgid)) = metadata.split_once("?") {
                        mailbox.tag(msgid, tag)?;
                        "ok".as_bytes().to_vec()
                    } else {
                        let date: Option<DateTime<Utc>>;

                        let filtered_tag = if let Some((tag, date_raw)) = metadata.split_once("/") {
                            date = Some(
                                DateTime::parse_from_rfc3339(date_raw)
                                    .map_err(|_| RequestError::InvalidRequest)?
                                    .into(),
                            );
                            tag
                        } else {
                            // Tries to parse a date just in case there is not a tag present
                            date = DateTime::parse_from_rfc3339(metadata)
                                .ok()
                                .map(|v| v.into());

                            if date.is_some() {
                                ""
                            } else {
                                metadata
                            }
                        };

                        let tag = if filtered_tag.len() > 0 {
                            Some(filtered_tag)
                        } else {
                            None
                        };

                        mailbox.list(tag, date)?.join(",").into_bytes()
                    }
                } else if request.path.starts_with("untag/") {
                    if let Some((tag, id)) =
                        request.path.trim_start_matches("untag/").split_once("?")
                    {
                        mailbox.untag(id, tag)?;
                        "ok".as_bytes().to_vec()
                    } else {
                        return Err(RequestError::InvalidRequest);
                    }
                } else if request.path.starts_with("delete?") {
                    mailbox.delete(request.path.trim_start_matches("delete?"))?;
                    "ok".as_bytes().to_vec()
                } else {
                    return Err(RequestError::NotFound);
                };

                return Ok::<(String, Vec<u8>), _>(("text/plain".to_string(), response));
            } else {
                return Err(RequestError::CertificateRequired);
            }
        }
        .await
        .map_or_else(
            |e| Response::GMAP(e.as_response().gmap),
            |v| Response::GMAP(gmap::Response::SUCCESS(v)),
        ),
        Some(Context::Path(path)),
    )
}
