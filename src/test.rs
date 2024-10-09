use crate::{
    config::{Base, Config, Mailbox, Tls},
    request::Message,
    tls::Cert,
};
use std::{collections::HashMap, fs, path::PathBuf, str::FromStr};
use tempfile::tempdir;
use tokio::{fs::File, io::AsyncReadExt};

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
    // the cert_gen_server() test.
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
async fn parse_b_request() {
    let message = Message::from_str("misfin://skye@example.com Hi there!\r\n");

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
        message.recipient.hostname, "example.com",
        "unexpected value in hostname field",
    );
    assert_eq!(
        message.message, "Hi there!\n",
        "unexpected value in message field"
    );
}
