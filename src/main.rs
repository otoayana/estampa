mod error;
mod request;
mod response;
mod tls;

use crate::error::EstampaError;
use request::Request;
use response::{Response, Status};
use rustls::{pki_types::CertificateDer, server::ServerConfig};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{BufReader, Read},
    sync::Arc,
};
use tokio::{io::BufStream, net::TcpListener};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

static VERSION: &'static str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<(), EstampaError> {
    let subscriber = tracing_subscriber::fmt()
        .compact()
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).map_err(|_| EstampaError::Logger)?;

    info!("📬 estampa v{}", VERSION);
    let addr = "localhost:1958";
    let listen = TcpListener::bind(addr).await?;

    let mut certs_file = BufReader::new(File::open("cert.pem")?);
    let mut key_file = BufReader::new(File::open("key.pem")?);

    let certs = rustls_pemfile::certs(&mut certs_file).collect::<Result<Vec<_>, _>>()?;
    let key = if let Some(key) = rustls_pemfile::private_key(&mut key_file)? {
        key
    } else {
        return Err(EstampaError::KeyNotProvided);
    };

    let config = Arc::new(
        ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(tls::EstampaClientAuth))
            .with_single_cert(certs, key)?,
    );
    let acceptor = TlsAcceptor::from(config);

    info!("listening on {}", addr);

    loop {
        let (mut socket, _) = listen.accept().await?;
        let acceptor = acceptor.clone();

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
                        let mut hash = Sha256::new();
                        let cert = val.bytes().map(|v| v.unwrap_or(0x20)).collect::<Vec<u8>>();
                        hash.update(cert);

                        let result = hash.finalize();
                        let mut fingerprint = String::new();

                        for (i, hex) in result.iter().enumerate() {
                            if i != 0 {
                                fingerprint.push_str(":")
                            }

                            if *hex <= 15 {
                                fingerprint.push_str("0")
                            }

                            fingerprint.push_str(&format!("{hex:x}"));
                        }

                        match Request::fetch(&mut buf).await {
                            Ok(request) => {
                                info!("request received ({})", request);
                                Status::MESSAGE_DELIVERED(fingerprint)
                            }
                            Err(err) => {
                                error!(?err, "invalid request");
                                Status::BAD_REQUEST
                            }
                        }
                    } else {
                        Status::CERTIFICATE_REQUIRED
                    };

                    match Response::from(status.clone()).write(&mut buf).await {
                        Ok(_) => info!("response sent ({})", status),
                        Err(msg) => error!("request failed ({})", msg),
                    }
                }
                Err(err) => error!("connection error ({})", err),
            }
        });
    }
}
