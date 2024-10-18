use crate::{
    config::{Base, Config, Mailbox, Tls},
    request::Message,
    tls::Cert,
};
use std::{collections::HashMap, fs, io::BufReader, path::PathBuf, str::FromStr, sync::Arc};
use tempfile::tempdir;
use tokio::{fs::File, io::AsyncReadExt, net::TcpListener};
use tokio_rustls::{
    rustls::{pki_types::CertificateDer, ServerConfig},
    TlsAcceptor,
};

const MESSAGE_BODY: &'static str = "misfin://skye@localhost Hi there!\r\n";

#[tokio::test]
async fn initialize_store() {
    let dir = tempdir().unwrap().into_path();

    let config = Config {
        base: Base {
            bind: String::new(),
            host: String::new(),
            store: dir.clone(),
        },
        tls: Tls {
            certificate: PathBuf::new(),
            private_key: PathBuf::new(),
        },
        mailbox: HashMap::new(),
    };

    let init = config.init().await;
    assert!(init.is_ok());

    for subdir in crate::config::STORE_TREE {
        assert!(dir.clone().join(subdir).exists())
    }
}

#[tokio::test]
async fn generate_server_certificate() {
    let dir = tempdir().unwrap().into_path();

    let cert_path = dir.clone().join("cert.pem");
    let key_path = dir.clone().join("key.pem");

    let generator = Cert::generate_server("example.com", &cert_path, &key_path).await;

    assert!(
        generator.is_ok(),
        "certificate generation failed: {generator:?}"
    );

    assert!(
        cert_path.exists(),
        "certificate was not written to the filesystem"
    );
    assert!(
        key_path.exists(),
        "private key was not written to the filesystem"
    );

    let mut cert: Vec<u8> = vec![];
    File::open(&cert_path)
        .await
        .unwrap()
        .read_to_end(&mut cert)
        .await
        .unwrap();
    assert!(!cert.is_empty(), "certificate is empty");

    let mut key: Vec<u8> = vec![];
    File::open(&key_path)
        .await
        .unwrap()
        .read_to_end(&mut key)
        .await
        .unwrap();
    assert!(!key.is_empty(), "private key is empty");
}

#[tokio::test]
async fn generate_client_certificate() {
    let dir = tempdir().unwrap().into_path();

    // Any errors that occur around these steps are already handled by
    // the generate_server_certificate() test.
    let server_cert_path = dir.clone().join("cert.pem");
    let server_key_path = dir.clone().join("key.pem");

    Cert::generate_server("example.com", &server_cert_path, &server_key_path)
        .await
        .unwrap();

    let certs_path = dir.join("certs/");
    let certs_dir = fs::create_dir_all(certs_path.clone().join("priv"));

    assert!(
        certs_dir.is_ok(),
        "certificate directory could not be created"
    );

    let mbox_name = "skye".to_string();
    let mbox_conf = Mailbox {
        enabled: true,
        name: "Skylar".to_string(),
    };

    let generate = Cert::generate_client(
        &dir,
        (&mbox_name, &mbox_conf),
        "example.com",
        &server_cert_path,
        &server_key_path,
    )
    .await;

    assert!(
        generate.is_ok(),
        "client certificate failed to generate: {generate:?}"
    );

    let client_cert_path = certs_path.clone().join("skye.pem");
    let mut client_cert: Vec<u8> = vec![];
    let client_cert_file = File::open(&client_cert_path).await;

    assert!(
        client_cert_file.is_ok(),
        "client certificate was not generated"
    );

    let reader = client_cert_file
        .unwrap()
        .read_to_end(&mut client_cert)
        .await;

    assert!(reader.is_ok(), "client certificate could not be read");
    assert!(!client_cert.is_empty());

    let client_key_path = certs_path.clone().join("priv/skye.pem");
    let mut client_key: Vec<u8> = vec![];
    let client_key_file = File::open(&client_key_path).await;

    assert!(client_key_file.is_ok(), "client private key is empty");

    let reader = client_key_file.unwrap().read_to_end(&mut client_key).await;

    assert!(reader.is_ok(), "client private key could not be read");
    assert!(!client_key.is_empty(), "client private key is empty")
}

#[tokio::test]
async fn verify_certificate() {
    let dir = tempdir().unwrap().into_path();

    // Any errors that occur around these steps are already handled by
    // both the generate_server_certificate(), and
    // generate_client_certificate() tests.

    let server_cert_path = dir.clone().join("cert.pem");
    let server_key_path = dir.clone().join("key.pem");

    Cert::generate_server("localhost", &server_cert_path, &server_key_path)
        .await
        .unwrap();

    let config = Config {
        base: Base {
            bind: "0.0.0.0:1958".to_string(),
            host: "localhost".to_string(),
            store: dir.clone().join("store/"),
        },
        tls: Tls {
            certificate: server_cert_path.to_path_buf(),
            private_key: server_key_path.to_path_buf(),
        },
        mailbox: HashMap::new(),
    };

    config.init().await.unwrap();

    Cert::generate_client(
        &config.base.store,
        (
            &String::from("skye"),
            &Mailbox {
                enabled: true,
                name: "Skylar".to_string(),
            },
        ),
        "localhost",
        &server_cert_path,
        &server_key_path,
    )
    .await
    .unwrap();

    // We need a dummy server for the certificate verifier to connect to
    let listen = TcpListener::bind("0.0.0.0:1958").await;

    assert!(listen.is_ok(), "couldn't bind server: {listen:?}");
    let listen = listen.unwrap();

    let certs_file = std::fs::File::open(&config.tls.certificate).unwrap();
    let key_file = std::fs::File::open(&config.tls.private_key).unwrap();

    let server_certs = rustls_pemfile::certs(&mut BufReader::new(certs_file))
        .collect::<Result<Vec<CertificateDer>, std::io::Error>>()
        .unwrap();
    let server_key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .unwrap()
        .unwrap();

    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(server_certs, server_key)
            .unwrap(),
    );

    let acceptor = TlsAcceptor::from(server_config);

    tokio::spawn(async move {
        // Only one request needs to be accepted. Don't loop.
        let (mut socket, _) = listen.accept().await.unwrap();
        acceptor.accept(&mut socket).await.unwrap();
    });

    let client_cert_path = config.base.store.clone().join("certs/skye.pem");
    let mut client_cert_raw: Vec<u8> = vec![];

    File::open(&client_cert_path)
        .await
        .unwrap()
        .read_to_end(&mut client_cert_raw)
        .await
        .unwrap();

    let mut reader = std::io::BufReader::new(&*client_cert_raw);
    let certificate_pem = rustls_pemfile::certs(&mut reader).next();

    assert!(
        certificate_pem.as_ref().is_some_and(|v| v.is_ok()),
        "unable to read client certificate"
    );

    let verify = Cert::verify(
        &certificate_pem.unwrap().unwrap(),
        config.base.store.clone().join("trust/"),
    )
    .await;

    assert!(
        verify.is_ok(),
        "certificate verification failed: {verify:?}"
    )
}

#[tokio::test]
async fn parse_b_request() {
    let message = Message::from_str(MESSAGE_BODY);

    assert!(
        message.is_ok(),
        "failed to parse misfin(b) request: {message:?}"
    );

    let message = message.unwrap();

    assert_eq!(
        message.recipient.mailbox, "skye",
        "unexpected value in mailbox field",
    );
    assert_eq!(
        message.recipient.hostname, "localhost",
        "unexpected value in hostname field",
    );
    assert_eq!(
        message.message, "Hi there!\n",
        "unexpected value in message field"
    );
}

#[tokio::test]
async fn store_b_request() {
    let dir = tempdir().unwrap().into_path();

    // Any errors that occur around these steps are already handled by
    // both the generate_server_certificate(), and
    // generate_client_certificate() tests.

    let server_cert_path = dir.clone().join("cert.pem");
    let server_key_path = dir.clone().join("key.pem");

    Cert::generate_server("localhost", &server_cert_path, &server_key_path)
        .await
        .unwrap();

    let mut config = Config {
        base: Base {
            bind: "0.0.0.0:1958".to_string(),
            host: "localhost".to_string(),
            store: dir.clone().join("store/"),
        },
        tls: Tls {
            certificate: server_cert_path.clone().to_path_buf(),
            private_key: server_key_path.clone().to_path_buf(),
        },
        mailbox: HashMap::new(),
    };

    config.mailbox.insert(
        "skye".to_string(),
        Mailbox {
            enabled: true,
            name: "Skye".to_string(),
        },
    );

    config.init().await.unwrap();

    Cert::generate_client(
        &config.base.store,
        (
            &String::from("skye"),
            &Mailbox {
                enabled: true,
                name: "Skylar".to_string(),
            },
        ),
        "localhost",
        &server_cert_path,
        &server_key_path,
    )
    .await
    .unwrap();

    // Spawn dummy server
    let listen = TcpListener::bind("0.0.0.0:1958").await;

    assert!(listen.is_ok(), "couldn't bind server: {listen:?}");
    let listen = listen.unwrap();

    let certs_file = std::fs::File::open(&config.tls.certificate).unwrap();
    let key_file = std::fs::File::open(&config.tls.private_key).unwrap();

    let server_certs = rustls_pemfile::certs(&mut BufReader::new(certs_file))
        .collect::<Result<Vec<CertificateDer>, std::io::Error>>()
        .unwrap();
    let server_key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .unwrap()
        .unwrap();

    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(server_certs.clone(), server_key)
            .unwrap(),
    );

    let acceptor = TlsAcceptor::from(server_config);

    tokio::spawn(async move {
        // Only one request needs to be accepted. Don't loop.
        let (mut socket, _) = listen.accept().await.unwrap();
        acceptor.accept(&mut socket).await.unwrap();
    });

    let message = Message::from_str(MESSAGE_BODY).unwrap();
    let save = message
        .save(&config.base.store, &config.mailbox, "localhost")
        .await;

    assert!(save.is_ok(), "message failed to save: ({save:#?})");

    let mut mailbox = config
        .base
        .store
        .clone()
        .join("mbox/skye")
        .read_dir()
        .unwrap();

    assert!(mailbox.next().is_some(), "no messages found in mailbox");
}
