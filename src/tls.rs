use crate::error::EstampaError;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName},
    server::{
        danger::{ClientCertVerified, ClientCertVerifier},
        ParsedCertificate,
    },
    ClientConfig, SignatureScheme,
};
use std::{io::Read, sync::Arc};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::info;
use x509_parser::prelude::*;

pub async fn verify<'a>(cert: &CertificateDer<'a>) -> Result<(), EstampaError> {
    let parsed = X509Certificate::from_der(cert).unwrap().1;

    let san = if let Some(inner) = parsed.subject_alternative_name()? {
        inner.value.general_names.iter().next()
    } else {
        return Err(EstampaError::Certificate(X509Error::InvalidCertificate));
    };

    let hostname = if let Some(GeneralName::DNSName(inner)) = san {
        inner
    } else {
        return Err(EstampaError::Certificate(X509Error::InvalidCertificate));
    };

    info!("sender hostname parsed ({})", hostname);

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

    let spki = ParsedCertificate::try_from(&server_cert)?.subject_public_key_info();

    parsed.verify_signature(Some(
        &SubjectPublicKeyInfo::from_der(
            spki.bytes()
                .filter(|b| b.is_ok())
                .map(|b| b.unwrap())
                .collect::<Vec<u8>>()
                .as_slice(),
        )
        .unwrap()
        .1,
    ))?;

    info!("sender certificate is valid");

    Ok(())
}

#[derive(Debug)]
pub struct EstampaClientAuth;

impl ClientCertVerifier for EstampaClientAuth {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
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
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
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
