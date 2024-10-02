mod config;
mod error;
mod request;
mod response;
mod tls;

use crate::error::EstampaError;
use config::Config;
use request::Request;
use response::{Response, Status};
use std::{
    fs::File,
    io::{self, BufReader},
    path::PathBuf,
    sync::Arc,
};
use tokio::{io::BufStream, net::TcpListener};
use tokio_rustls::{
    rustls::{pki_types::CertificateDer, server::ServerConfig},
    TlsAcceptor,
};
use tracing::{error, info, trace, warn};

static VERSION: &'static str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<(), EstampaError> {
    let conf = Config::open(PathBuf::from("./config.toml")).await?;

    let subscriber = tracing_subscriber::fmt()
        .compact()
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).map_err(|_| EstampaError::Logger)?;

    info!("📬 estampa v{VERSION}");

    let addr = &conf.base.bind;
    let listen = TcpListener::bind(&addr).await?;

    let mut certs_file = BufReader::new(File::open(&conf.tls.certificate)?);
    let mut key_file = BufReader::new(File::open(&conf.tls.private_key)?);

    let certs = rustls_pemfile::certs(&mut certs_file)
        .collect::<Result<Vec<CertificateDer>, io::Error>>()?;
    let key = if let Some(key) = rustls_pemfile::private_key(&mut key_file)? {
        key
    } else {
        return Err(EstampaError::KeyNotProvided);
    };

    // Connections will need a dummy verifier
    let config = Arc::new(
        ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(tls::EstampaClientAuth))
            .with_single_cert(certs, key)?,
    );
    let acceptor = TlsAcceptor::from(config);
    info!("listening on {addr}");

    let memory = Arc::new(conf);

    loop {
        let (mut socket, _) = listen.accept().await?;
        let acceptor = acceptor.clone();
        let inner_mem = memory.clone();

        tokio::spawn(async move {
            match acceptor.accept(&mut socket).await {
                Ok(stream) => {
                    let certs: Option<CertificateDer> =
                        if let Some(val) = stream.get_ref().1.peer_certificates() {
                            Some(val.get(0).unwrap().to_owned())
                        } else {
                            None
                        };
                    let mut buf = BufStream::new(stream);

                    let status = if let Some(val) = certs {
                        if let Err(err) = tls::verify(&val).await {
                            // TODO(otoayana): handle more error scenarios
                            error!(?err, "certificate invalid");
                            Status::CERTIFICATE_INVALID
                        } else {
                            match Request::parse(&mut buf).await {
                                Ok(request) => {
                                    trace!("request received ({request})");
                                    if request.hostname == inner_mem.base.host {
                                        if let Some(mbox) = inner_mem.mailbox.get(&request.mailbox)
                                        {
                                            Status::MESSAGE_DELIVERED(mbox.fingerprint.clone())
                                        } else {
                                            Status::MAILBOX_DOESNT_EXIST
                                        }
                                    } else {
                                        Status::DOMAIN_NOT_SERVICED
                                    }
                                }
                                Err(err) => {
                                    warn!("invalid request ({err})");
                                    Status::BAD_REQUEST
                                }
                            }
                        }
                    } else {
                        Status::CERTIFICATE_REQUIRED
                    };

                    match Response::from(status.clone()).write(&mut buf).await {
                        Ok(_) => trace!("response sent ({status})"),
                        Err(msg) => error!("response failed ({msg})"),
                    }
                }
                Err(err) => error!("connection error ({err})"),
            }
        });
    }
}
