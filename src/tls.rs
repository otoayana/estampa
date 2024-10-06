use crate::{error::VerificationError, request::Identity};
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, LazyLock},
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{
    rustls::{
        self,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
        server::danger::{ClientCertVerified, ClientCertVerifier},
        ClientConfig, DigitallySignedStruct, DistinguishedName, SignatureScheme,
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

static UID_OID_X509: LazyLock<ObjectIdentifier> = LazyLock::new(|| {
    ObjectIdentifier::from_arcs(crate::UID_OID.clone().iter().map(|v| *v as u32)).unwrap()
});

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

// Below are dummy verifiers used to get past CA validation in Rustls

#[derive(Debug)]
pub struct EstampaClientAuth;

impl ClientCertVerifier for EstampaClientAuth {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        // The server will send the corresponding response if its not present
        false
    }
}

#[derive(Debug)]
pub struct EstampaServerAuth;

impl ServerCertVerifier for EstampaServerAuth {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}
