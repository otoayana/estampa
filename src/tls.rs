use crate::{error::EstampaError, request::Identity};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{
    rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName},
        server::danger::{ClientCertVerified, ClientCertVerifier},
        ClientConfig, SignatureScheme,
    },
    TlsConnector,
};
use tracing::debug;
use x509_cert::{
    der::{oid::AssociatedOid, Decode, Encode},
    ext::pkix::SubjectAltName,
    Certificate,
};
use x509_verify::{Signature, VerifyInfo, VerifyingKey};

pub async fn verify<'a>(cert: &CertificateDer<'a>) -> Result<Identity, EstampaError> {
    let parsed = Certificate::from_der(&cert)?;
    let tbs = parsed.tbs_certificate;

    let uid: String = if let Some(v) = tbs.subject.0.iter().next() {
        v.0.iter().next().unwrap().value.decode_as()?
    } else {
        return Err(EstampaError::Verification);
    };

    let ext = if let Some(e) = tbs.extensions.clone() {
        e
    } else {
        return Err(EstampaError::Verification);
    };

    let hostname = {
        let inner: String = {
            String::from_utf8_lossy(
                if let Some(n) = ext
                    .iter()
                    .filter(|x| x.extn_id == SubjectAltName::OID)
                    .next()
                {
                    n
                } else {
                    return Err(EstampaError::Verification);
                }
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

    let address = format!("{}:1958", hostname);
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(EstampaServerAuth))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(address).await?;

    let tls_hostname =
        ServerName::try_from(hostname.to_string()).map_err(|_| EstampaError::Parse)?;
    let stream = connector.connect(tls_hostname, stream).await?;

    let server_cert = if let Some(inner) = stream.get_ref().1.peer_certificates() {
        inner.first().unwrap().to_owned()
    } else {
        return Err(EstampaError::InvalidSignature);
    };

    let vinfo = VerifyInfo::new(
        tbs.clone().to_der()?.into(),
        Signature::new(
            &parsed.signature_algorithm,
            parsed.signature.as_bytes().unwrap(),
        ),
    );

    let spki: VerifyingKey = Certificate::from_der(&server_cert)?
        .tbs_certificate
        .subject_public_key_info
        .try_into()
        .unwrap();

    spki.verify(vinfo).map_err(|_| EstampaError::Verification)?;
    debug!("sender certificate is valid");

    Ok(Identity {
        mailbox: uid.to_string(),
        hostname: hostname.to_string(),
    })
}

#[derive(Debug)]
pub struct EstampaClientAuth;

impl ClientCertVerifier for EstampaClientAuth {
    fn root_hint_subjects(&self) -> &[tokio_rustls::rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::server::danger::ClientCertVerified, tokio_rustls::rustls::Error>
    {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
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
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
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
