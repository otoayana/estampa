use std::{
    fs,
    path::PathBuf,
    sync::{Arc, LazyLock},
};

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use time::OffsetDateTime;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{
    rustls::{
        pki_types::{CertificateDer, ServerName},
        ClientConfig,
    },
    TlsConnector,
};
use tracing::{debug, warn};
use x509_cert::{
    der::{asn1::BitString, oid::AssociatedOid, Decode, Encode},
    ext::pkix::SubjectAltName,
    spki::ObjectIdentifier,
    Certificate,
};
use x509_verify::{Signature, VerifyInfo, VerifyingKey};

use crate::{
    config::Mailbox,
    error::{EstampaError, VerificationError},
    request::Identity,
    tls::auth::EstampaServerAuth,
};

const UID_OID: [u64; 7] = [0, 9, 2342, 19200300, 100, 1, 1];
static UID_OID_X509: LazyLock<ObjectIdentifier> = LazyLock::new(|| {
    ObjectIdentifier::from_arcs(UID_OID.clone().iter().map(|v| *v as u32)).unwrap()
});

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

        dn.push(DnType::CustomDnType(UID_OID.to_vec()), mailbox.0.clone());
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
        File::create(
            // TODO(otoayana): Clean this up, maybe by adding a new error item
            &store.join(format!("certs/priv/{}.pem", &mailbox.0)),
        )
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
        let parsed = Certificate::from_der(&cert)?;
        let tbs = parsed.tbs_certificate;

        let uid: String = tbs
            .subject
            .0
            .iter()
            .filter(|v| {
                v.0.iter()
                    .filter(|n| n.oid == *UID_OID_X509)
                    .next()
                    .is_some()
            })
            .map(|v| v.0.iter().next().clone())
            .filter(|v| v.is_some())
            .map(|v| v.unwrap())
            .next()
            .ok_or(VerificationError::InvalidCertificate)?
            .value
            .decode_as()?;

        // SANs need to be fetched through the certificates' extensions
        let extensions = tbs
            .clone()
            .extensions
            .ok_or(VerificationError::InvalidCertificate)?;

        let hostname = {
            let inner: String = {
                String::from_utf8_lossy(
                    extensions
                        .iter()
                        .filter(|x| x.extn_id == SubjectAltName::OID)
                        .next()
                        .ok_or(VerificationError::InvalidCertificate)?
                        .extn_value
                        .clone()
                        .as_bytes(),
                )
                .to_string()
                .chars()
                .filter(|c| c.is_ascii_alphabetic() || *c == '.')
                .collect()
            };

            inner
        };

        debug!("sender hostname parsed ({})", hostname);

        if !trust_path.exists() {
            warn!("trust path doesn't exist! creating...");
            fs::create_dir_all(&trust_path)?;
        }

        let local_cert_path = trust_path.join(format!("{}.spki", hostname));

        let spki: VerifyingKey = if local_cert_path.exists() {
            let mut raw: Vec<u8> = vec![];

            File::open(&local_cert_path)
                .await?
                .read_to_end(&mut raw)
                .await?;

            let out: x509_cert::spki::SubjectPublicKeyInfo<x509_cert::der::Any, BitString> =
                x509_cert::spki::SubjectPublicKeyInfo::try_from(raw.as_slice())
                    .map_err(|_| VerificationError::InvalidSignature)?;

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
                .ok_or(VerificationError::InvalidSignature)?
                .first()
                .unwrap()
                .to_owned();

            let out = Certificate::from_der(&server_cert)?
                .tbs_certificate
                .subject_public_key_info;
            let mut buf: Vec<u8> = vec![];

            out.clone().encode_to_vec(&mut buf)?;

            // Cache the SPKI for later usage
            File::create(&local_cert_path)
                .await?
                .write_all(&buf)
                .await?;

            out
        }
        .try_into()
        .map_err(|_| VerificationError::InvalidSignature)?;

        let verification_info = VerifyInfo::new(
            tbs.clone().to_der()?.into(),
            Signature::new(
                &parsed.signature_algorithm,
                parsed.signature.as_bytes().unwrap(),
            ),
        );

        spki.verify(verification_info)
            .map_err(|_| VerificationError::InvalidSignature)?;

        debug!("sender certificate is valid");

        Ok(Identity {
            mailbox: uid.to_string(),
            hostname: hostname.to_string(),
        })
    }
}
