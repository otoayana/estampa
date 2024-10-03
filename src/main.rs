mod config;
mod error;
mod request;
mod response;
mod tls;

use crate::error::EstampaError;
use config::Config;
use error::Responder;
use request::Message;
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
use tracing::{debug, error, info};

static VERSION: &'static str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<(), EstampaError> {
    let conf = Config::open(PathBuf::from("./config.toml")).await?;

    let subscriber = tracing_subscriber::fmt()
        .compact()
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

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
        return Err(EstampaError::Tls(
            tokio_rustls::rustls::Error::NoCertificatesPresented,
        ));
    };

    /*
        Client certificate verification is handled once the handshake has been
        completed, therefore we need the trick Rustls into completing it using
        the dummy verifier defined in tls::EstampaClientAuth
    */

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

                    let (status, message): (Status, Option<Message>) = if let Some(val) = certs {
                        match Message::from(val, &mut buf).await {
                            Ok(msg) => (
                                match msg.save(&inner_mem.mailbox, &inner_mem.base.host).await {
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
        });
    }
}
