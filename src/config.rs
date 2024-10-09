use crate::error::EstampaError;
use serde::Deserialize;
use std::{collections::HashMap, path::PathBuf};
use tokio::fs;
use tracing::info;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub base: Base,
    pub tls: Tls,
    pub mailbox: HashMap<String, Mailbox>,
}

#[derive(Debug, Deserialize)]
pub struct Base {
    pub bind: String,
    pub host: String,
    pub store: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct Tls {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct Mailbox {
    pub enabled: bool,
    pub name: String,
}

pub static STORE_TREE: [&'static str; 4] = ["certs/", "certs/priv/", "trust/", "mbox/"];

impl Config {
    /// Loads and parses an Estampa config file
    pub async fn open(path: PathBuf) -> Result<Self, EstampaError> {
        let file = fs::read(path).await?;
        let raw = String::from_utf8_lossy(&file);

        let config: Self = toml::from_str(&raw)?;

        Ok(config)
    }

    /// Initializes the store directories
    pub async fn init(&self) -> Result<(), EstampaError> {
        let mut dirs: Vec<String> = STORE_TREE
            .clone()
            .to_vec()
            .iter()
            .map(|v| v.to_string())
            .collect();

        // Controls log notification
        let mut created = false;

        // Include mailboxes in directory list
        self.mailbox
            .iter()
            .for_each(|mb| dirs.push(format!("mbox/{}", mb.0)));

        for dir in dirs.iter() {
            let joined = self.base.store.clone().join(&dir);

            if !joined.exists() {
                fs::create_dir_all(&joined).await?;

                if !created {
                    created = true
                }
            }
        }

        if created {
            info!("initialized store at {:?}", self.base.store);
        }

        Ok(())
    }
}
