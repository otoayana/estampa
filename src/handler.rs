use crate::{
    config::Config,
    error::Responder,
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

            let (response, message, path): (Response, Option<Message>, Option<String>) =
                match Request::parse(&mut buf).await {
                    Ok(proto) => match proto {
                        Request::MisfinB(req) => misfin_handler(req, certs, memory).await,
                        Request::MisfinC(req) => misfin_handler(req, certs, memory).await,
                        Request::GMAP(req) => {
                            let mut host = memory.base.host.clone();
                            host.push_str(":1958");

                            if req.host != host {
                                (
                                    Response::GMAP(gmap::Response::INTERNAL_SERVER_ERROR),
                                    None,
                                    Some(req.path),
                                )
                            } else {
                                if let Some(cert) = certs.clone() {
                                    match Cert::parse(&cert).await {
                                        Ok(inner_cert) => match memory.mailbox(inner_cert) {
                                            Ok(mailbox) => (
                                                Response::GMAP(if req.path.starts_with("msgid/") {
                                                    match mailbox
                                                        .get(req.path.trim_start_matches("msgid/"))
                                                    {
                                                        Ok(res) => gmap::Response::SUCCESS((
                                                            "text/plain".to_string(),
                                                            res.message.into_bytes(),
                                                        )),
                                                        Err(err) => err.as_response().gmap,
                                                    }
                                                } else if req.path.starts_with("tag/") {
                                                    let tag_raw =
                                                        req.path.trim_start_matches("tag/");
                                                    let tag = if tag_raw.len() > 0 {
                                                        Some(tag_raw)
                                                    } else {
                                                        None
                                                    };

                                                    match mailbox.list(tag) {
                                                        Ok(res) => gmap::Response::SUCCESS((
                                                            "text/plain".to_string(),
                                                            res.join("\n").into_bytes(),
                                                        )),
                                                        Err(err) => err.as_response().gmap,
                                                    }
                                                } else {
                                                    gmap::Response::NOT_FOUND
                                                }),
                                                None,
                                                Some(req.path),
                                            ),
                                            Err(err) => (
                                                Response::GMAP(err.as_response().gmap),
                                                None,
                                                Some(req.path),
                                            ),
                                        },
                                        Err(err) => (
                                            Response::GMAP(err.as_response().gmap),
                                            None,
                                            Some(req.path),
                                        ),
                                    }
                                } else {
                                    (
                                        Response::GMAP(gmap::Response::CERTIFICATE_REQUIERED),
                                        None,
                                        Some(req.path),
                                    )
                                }
                            }
                        }
                    },
                    Err(err) => (Response::Misfin(err.as_response().misfin), None, None),
                };

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
    let out = match request
        .as_message(cert, memory.base.store.join("trust/"))
        .await
    {
        Ok(msg) => (
            match memory.mailbox(msg.recipient.clone()) {
                Ok(mbox) => match mbox.save(msg.clone()) {
                    Ok(fingerprint) => misfin::Response::MESSAGE_DELIVERED(fingerprint),
                    Err(err) => err.as_response().misfin,
                },
                Err(err) => err.as_response().misfin,
            },
            Some(msg),
        ),
        Err(err) => (err.as_response().misfin, None),
    };

    (Response::Misfin(out.0), out.1, None)
}
