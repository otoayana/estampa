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
    fs::{self, File},
    io::{self, BufReader, Write},
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{io::BufStream, net::TcpListener};
use tokio_rustls::{
    rustls::{pki_types::CertificateDer, server::ServerConfig},
    TlsAcceptor,
};
use tracing::{debug, error, info, warn};

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

                    let (mut sender, mut recipient): (String, String) =
                        ("".to_string(), "".to_string());

                    // TODO(otoayana): Split off expression into its own function
                    let status = if let Some(val) = certs {
                        match tls::verify(&val).await {
                            Ok(origin) => {
                                sender = format!("{}@{}", origin.0, origin.1);
                                match Request::parse(&mut buf).await {
                                    Ok(request) => {
                                        debug!("request received ({request})");
                                        recipient =
                                            format!("{}@{}", request.mailbox, request.hostname);
                                        if request.hostname == inner_mem.base.host {
                                            if let Some(mbox) =
                                                inner_mem.mailbox.get(&request.mailbox)
                                            {
                                                if mbox.enabled {
                                                    || -> Status {
                                                        if !mbox.path.exists() {
                                                            warn!("mailbox {} doesn't exist. making directory at requested path...", &request.mailbox);

                                                            if let Err(err) =
                                                                fs::create_dir_all(&mbox.path)
                                                            {
                                                                error!(
                                                                "could not create mailbox {}! ({err})",
                                                                &request.mailbox
                                                            );
                                                                return Status::PERMANENT_ERROR;
                                                            } else {
                                                                info!(
                                                                "mailbox {} created successfully",
                                                                &request.mailbox
                                                            )
                                                            }
                                                        }

                                                        let now = SystemTime::now();
                                                        let time = now
                                                            .duration_since(UNIX_EPOCH)
                                                            .unwrap_or(Duration::new(0, 0))
                                                            .as_millis();

                                                        let mpath =
                                                            mbox.path.clone().join(format!(
                                                                "{}-{}@{}.gmi",
                                                                time, origin.0, origin.1
                                                            ));

                                                        match File::create(mpath) {
                                                            Ok(mut file) => {
                                                                match file.write(
                                                                    request.message.as_bytes(),
                                                                ) {
                                                                    Ok(_) => {
                                                                        Status::MESSAGE_DELIVERED(
                                                                            mbox.fingerprint
                                                                                .clone(),
                                                                        )
                                                                    }
                                                                    Err(_) => {
                                                                        Status::PERMANENT_ERROR
                                                                    }
                                                                }
                                                            }
                                                            Err(_) => Status::PERMANENT_ERROR,
                                                        }
                                                    }(
                                                    )
                                                } else {
                                                    Status::MAILBOX_GONE
                                                }
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
                            Err(err) => {
                                // TODO(otoayana): handle more error scenarios
                                error!(?err, "certificate invalid");
                                Status::CERTIFICATE_INVALID
                            }
                        }
                    } else {
                        Status::CERTIFICATE_REQUIRED
                    };

                    match Response::from(status.clone()).write(&mut buf).await {
                        Ok(_) => {
                            debug!("response sent ({status})");
                            if matches!(status, Status::MESSAGE_DELIVERED(_)) {
                                info!("message received ({} -> {})", sender, recipient);
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
