use crate::{error::VerificationError, request::Identity};
use std::sync::Arc;
use tokio::net::TcpStream;
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
use tracing::debug;
use x509_cert::{
    der::{oid::AssociatedOid, Decode, Encode},
    ext::pkix::SubjectAltName,
    Certificate,
};
use x509_verify::{Signature, VerifyInfo, VerifyingKey};

/// Parse a client certificate and validate its origin
pub async fn verify<'a>(cert: &CertificateDer<'a>) -> Result<Identity, VerificationError> {
    let parsed = Certificate::from_der(&cert)?;
    let tbs = parsed.tbs_certificate;

    let uid: String = if let Some(v) = tbs.subject.0.iter().next() {
        v.0.iter().next().unwrap().value.decode_as()?
    } else {
        return Err(VerificationError::InvalidCertificate);
    };

    // SANs need to be fetched through the certificates' extensions
    let extensions = if let Some(e) = tbs.extensions.clone() {
        e
    } else {
        return Err(VerificationError::InvalidCertificate);
    };

    let hostname = {
        let inner: String = {
            String::from_utf8_lossy(
                if let Some(n) = extensions
                    .iter()
                    .filter(|x| x.extn_id == SubjectAltName::OID)
                    .next()
                {
                    n
                } else {
                    return Err(VerificationError::InvalidCertificate);
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

    let server_cert = if let Some(c) = stream.get_ref().1.peer_certificates() {
        c.first().unwrap().to_owned()
    } else {
        return Err(VerificationError::InvalidSignature);
    };

    let verification_info = VerifyInfo::new(
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
        .map_err(|_| VerificationError::InvalidSignature)?;

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
