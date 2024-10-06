use crate::error::EstampaError;
use serde::Deserialize;
use std::{collections::HashMap, path::PathBuf};
use tokio::fs;

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
}

#[derive(Debug, Deserialize)]
pub struct Tls {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub trust_dir: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct Mailbox {
    pub enabled: bool,
    pub name: String,
    pub path: PathBuf,
    pub certificate: PathBuf,
}

impl Config {
    pub async fn open(path: PathBuf) -> Result<Self, EstampaError> {
        let file = fs::read(path).await?;
        let raw = String::from_utf8_lossy(&file);

        let config: Self = toml::from_str(&raw)?;

        Ok(config)
    }
}
