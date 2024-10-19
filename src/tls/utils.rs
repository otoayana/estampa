use crate::{
    config::Mailbox,
    error::{EstampaError, VerificationError},
    request::Identity,
    tls::auth::EstampaServerAuth,
};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use std::{io::Read, path::PathBuf, sync::Arc};
use time::OffsetDateTime;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{
    rustls::{
        pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer},
        server::ParsedCertificate,
        ClientConfig,
    },
    TlsConnector,
};
use tracing::debug;
use x509_parser::{
    der_parser::Oid,
    error::X509Error,
    prelude::{FromDer, GeneralName, X509Certificate},
    x509::SubjectPublicKeyInfo,
};

// Object identifier for the "UID" field. Not recognized by many x509 libraries
const X509_OID_UID: [u64; 7] = [0, 9, 2342, 19200300, 100, 1, 1];

pub struct Cert;

impl Cert {
    /// Generate a server certificate
    pub async fn generate_server<'a>(
        host: &'a str,
        certificate: &PathBuf,
        private_key: &PathBuf,
    ) -> Result<(), EstampaError> {
        let keypair = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)?;
        let mut cert_params = CertificateParams::new(vec![host.to_string()])?;
        let now = OffsetDateTime::now_utc();

        cert_params.not_after = now.replace_year(now.year() + 10)?;

        let cert = cert_params.self_signed(&keypair)?;

        File::create(certificate)
            .await?
            .write(&cert.pem().into_bytes())
            .await?;
        File::create(private_key)
            .await?
            .write(&keypair.serialize_pem().into_bytes())
            .await?;

        Ok(())
    }

    /// Generate a client certificate
    pub async fn generate_client<'a>(
        store: &PathBuf,
        mailbox: (&String, &Mailbox),
        host: &'a str,
        host_certificate: &PathBuf,
        host_private_key: &PathBuf,
    ) -> Result<(), EstampaError> {
        let mut cert_pem = String::new();
        File::open(host_certificate)
            .await?
            .read_to_string(&mut cert_pem)
            .await?;

        let mut key_pem = String::new();
        File::open(host_private_key)
            .await?
            .read_to_string(&mut key_pem)
            .await?;

        let root_sig = KeyPair::from_pem(&key_pem)?;
        let parent_cert = CertificateParams::from_ca_cert_pem(&cert_pem)?.self_signed(&root_sig)?;

        let mut params = CertificateParams::new(vec![host.to_string()])?;
        let mut dn = DistinguishedName::new();

        dn.push(
            DnType::CustomDnType(X509_OID_UID.to_vec()),
            mailbox.0.clone(),
        );
        dn.push(DnType::CommonName, mailbox.1.name.clone());

        params.distinguished_name = dn;

        let now = OffsetDateTime::now_utc();
        params.not_after = now.replace_year(now.year() + 5)?;

        let key = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256)?;
        let cert = params.signed_by(&key, &parent_cert, &root_sig)?;

        File::create(&store.join(format!("certs/{}.pem", &mailbox.0)))
            .await?
            .write_all(&cert.pem().into_bytes())
            .await?;

        File::create(&store.join(format!("certs/priv/{}.pem", &mailbox.0)))
            .await?
            .write_all(&key.serialize_pem().into_bytes())
            .await?;

        Ok(())
    }

    /// Parse a client certificate and validate its origin
    pub async fn verify<'a>(
        cert: &CertificateDer<'a>,
        trust_path: PathBuf,
    ) -> Result<Identity, VerificationError> {
        let parsed = X509Certificate::from_der(cert)
            .map_err(|_| VerificationError::InvalidCertificate)?
            .1;

        let san = parsed
            .subject_alternative_name()?
            .ok_or(VerificationError::InvalidCertificate)?
            .value
            .general_names
            .first();

        let hostname = if let Some(GeneralName::DNSName(value)) = san {
            value
        } else {
            return Err(VerificationError::InvalidCertificate);
        };

        let uid = parsed
            .tbs_certificate
            .subject
            .iter_by_oid(&Oid::from(&X509_OID_UID).unwrap())
            .next()
            .ok_or(VerificationError::InvalidCertificate)
            .map_err(|_| VerificationError::InvalidCertificate)?
            .as_str()?;

        debug!("sender certificate parsed ({}@{})", &uid, hostname);

        let local_cert_path = trust_path.join(format!("{}.spki", hostname));

        let spki = if local_cert_path.exists() {
            let mut raw: Vec<u8> = vec![];

            File::open(&local_cert_path)
                .await?
                .read_to_end(&mut raw)
                .await?;

            let out = SubjectPublicKeyInfoDer::try_from(raw).map_err(|_| X509Error::InvalidSPKI)?;

            out
        } else {
            // Fetch and verify the certificate from the client's SAN
            let address = format!("{}:1958", hostname);

            let config = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(EstampaServerAuth))
                .with_no_client_auth();
            let connector = TlsConnector::from(Arc::new(config));

            let raw_stream = TcpStream::connect(address).await?;

            let tls_hostname = ServerName::try_from(hostname.to_string())
                .map_err(|_| VerificationError::InvalidHostname)?;
            let stream = connector.connect(tls_hostname, raw_stream).await?;

            let server_cert = stream
                .get_ref()
                .1
                .peer_certificates()
                .ok_or(VerificationError::InvalidHostname)?
                .first()
                .ok_or(VerificationError::InvalidHostname)?
                .to_owned();

            let out = ParsedCertificate::try_from(&server_cert)
                .map_err(|_| VerificationError::InvalidHostname)?
                .subject_public_key_info();

            let buf: Vec<u8> = out.clone().to_vec();

            // Cache the SPKI for later usage
            File::create(&local_cert_path)
                .await?
                .write_all(&buf)
                .await?;

            out
        };

        parsed
            .verify_signature(Some(
                &SubjectPublicKeyInfo::from_der(
                    &spki
                        .bytes()
                        .filter(|b| b.is_ok())
                        .map(|b| b.unwrap())
                        .collect::<Vec<u8>>()
                        .as_slice(),
                )
                .unwrap()
                .1,
            ))
            .map_err(|_| VerificationError::InvalidSignature)?;

        debug!("sender certificate is valid");

        Ok(Identity {
            mailbox: uid.to_string(),
            hostname: hostname.to_string(),
        })
    }
}
