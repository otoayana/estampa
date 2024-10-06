mod config;
mod error;
mod request;
mod response;
mod tls;

use crate::error::EstampaError;
use config::Config;
use error::Responder;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use request::Message;
use response::{Response, Status};
use std::{
    fs::File,
    io::{self, BufReader, Read, Write},
    path::PathBuf,
    sync::Arc,
};
use tokio::{io::BufStream, net::TcpListener};
use tokio_rustls::{
    rustls::{pki_types::CertificateDer, server::ServerConfig},
    TlsAcceptor,
};
use tracing::{debug, error, info, warn};

pub const UID_OID: [u64; 7] = [0, 9, 2342, 19200300, 100, 1, 1];
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

    // Create server certificates if they don't exist
    if !conf.tls.certificate.exists() && !conf.tls.private_key.exists() {
        warn!("certificate and key not found. generating...");

        let keypair = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)?;
        let cert = CertificateParams::new(vec![conf.base.host.clone()])?.self_signed(&keypair)?;

        File::create(&conf.tls.certificate)?.write(&cert.pem().into_bytes())?;
        File::create(&conf.tls.private_key)?.write(&keypair.serialize_pem().into_bytes())?;

        info!("succesfully generated key for host {}", &conf.base.host);
    }

    if conf.tls.certificate.exists() ^ conf.tls.private_key.exists() {
        error!("incomplete x509 chain");

        return Err(EstampaError::IncompleteX509Chain);
    }

    let addr = &conf.base.bind;
    let listen = TcpListener::bind(&addr).await?;

    let certs_file = File::open(&conf.tls.certificate)?;
    let key_file = File::open(&conf.tls.private_key)?;

    let certs = rustls_pemfile::certs(&mut BufReader::new(certs_file))
        .collect::<Result<Vec<CertificateDer>, io::Error>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))?.ok_or(
        EstampaError::Tls(tokio_rustls::rustls::Error::NoCertificatesPresented),
    )?;

    // Create client certificates for each mailbox if not present
    for mbox in &conf.mailbox {
        if !mbox.1.certificate.exists() {
            warn!(
                "ceritificate not found for mailbox {}. generating...",
                mbox.0
            );

            let certs_file = File::open(&conf.tls.certificate)?;
            let key_file = File::open(&conf.tls.private_key)?;

            let mut cert_pem = String::new();
            certs_file.try_clone()?.read_to_string(&mut cert_pem)?;

            let mut key_pem = String::new();
            key_file.try_clone()?.read_to_string(&mut key_pem)?;

            let root_sig = KeyPair::from_pem(&key_pem)?;
            let parent_cert =
                CertificateParams::from_ca_cert_pem(&cert_pem)?.self_signed(&root_sig)?;

            let mut params = CertificateParams::new(vec![conf.base.host.clone()])?;
            let mut dn = DistinguishedName::new();

            dn.push(DnType::CustomDnType(UID_OID.to_vec()), mbox.0.clone());
            dn.push(DnType::CommonName, mbox.1.name.clone());

            params.distinguished_name = dn;

            let key = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)?;
            let cert = params.signed_by(&key, &parent_cert, &root_sig)?;

            File::create(&mbox.1.certificate)?.write_all(&cert.pem().into_bytes())?;
            File::create(
                // TODO(otoayana): Clean this up, maybe by adding a new error item
                &mbox
                    .1
                    .certificate
                    .parent()
                    .unwrap()
                    .to_path_buf()
                    .join(format!(
                        "{}.key",
                        &mbox
                            .1
                            .certificate
                            .file_name()
                            .unwrap()
                            .to_string_lossy()
                            .split_once(".")
                            .unwrap()
                            .0,
                    )),
            )?
            .write_all(&key.serialize_pem().into_bytes())?;

            info!(
                "generated certificate for mailbox {}. keep your private key safe!",
                mbox.0
            );
        }
    }

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
                        match Message::from(inner_mem.tls.trust_dir.clone(), val, &mut buf).await {
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
