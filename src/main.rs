mod config;
mod error;
mod handler;
mod request;
mod response;
mod tls;

#[cfg(test)]
mod test;

use crate::error::EstampaError;
use clap::Parser;
use config::Config;
use handler::handler;
use std::{
    fs::File,
    io::{self, BufReader},
    path::PathBuf,
    str::FromStr,
    sync::Arc,
};
use tls::Cert;
use tokio::net::TcpListener;
use tokio_rustls::{
    rustls::{pki_types::CertificateDer, server::ServerConfig},
    TlsAcceptor,
};
use tracing::{error, info, warn};

static VERSION: &'static str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    version,
    about = "Minimalist server for the Misfin protocol",
    long_about = None
)]
struct Cli {
    #[arg(
        short,
        long,
        value_name = "FILE",
        help = "Specifies a TOML file to use for configuration (default: ./config.toml)"
    )]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), EstampaError> {
    let args = Cli::parse();
    let conf = Config::open(
        args.config
            .unwrap_or(PathBuf::from_str("./config.toml").unwrap()),
    )
    .await?;

    let subscriber = tracing_subscriber::fmt()
        .compact()
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("📬 estampa v{VERSION}");

    conf.init().await?;

    // Create server certificates if they don't exist
    if !conf.tls.certificate.exists() && !conf.tls.private_key.exists() {
        warn!("certificate and key not found. generating...");

        Cert::generate_server(
            &conf.base.host,
            &conf.tls.certificate,
            &conf.tls.private_key,
        )
        .await?;

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
        if !conf
            .base
            .store
            .join(format!("certs/{}", mbox.0))
            .exists()
            .clone()
        {
            warn!(
                "ceritificate not found for mailbox {}. generating...",
                mbox.0
            );

            Cert::generate_client(
                &conf.base.store,
                mbox,
                &conf.base.host,
                &conf.tls.certificate,
                &conf.tls.private_key,
            )
            .await?;

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
            .with_client_cert_verifier(Arc::new(tls::auth::EstampaClientAuth))
            .with_single_cert(certs, key)?,
    );
    let acceptor = TlsAcceptor::from(config);
    info!("listening on {addr}");

    let memory = Arc::new(conf);

    loop {
        let (socket, _) = listen.accept().await?;
        let acceptor = acceptor.clone();
        let memory = memory.clone();

        tokio::spawn(handler(socket, acceptor, memory));
    }
}
