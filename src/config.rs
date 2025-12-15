use serde::Deserialize;
use std::{
    fmt,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
};

use crate::{
    extractors::{self, Option82ExtractorFn},
    Duid, V4Subnet,
};

pub struct Config {
    pub v4_server_id: Ipv4Addr,
    pub dns_v4: Vec<Ipv4Addr>,
    pub subnets_v4: Vec<V4Subnet>,
    pub v6_server_id: Duid,
    pub option82_extractors: Vec<Option82ExtractorFn>,
    pub log_level: tracing::Level,
    pub events_address: Option<SocketAddr>,
}

/// Server wide configuration
#[derive(Deserialize)]
struct ServerConfig {
    dns_v4: Vec<Ipv4Addr>,
    subnets_v4: Vec<V4Subnet>,
    option82_extractors: Vec<String>,
    log_level: Option<String>,
    events_address: Option<SocketAddr>,
}

/// Server IDs stored in separate file that may be auto generated in the future
#[derive(Deserialize)]
struct ServerIds {
    v4: Ipv4Addr,
    v6: Duid,
}

#[derive(Debug)]
pub enum ConfigError {
    UnknownOption82Extractor(String),
    Parsing {
        err: serde_json::Error,
        path: PathBuf,
    },
    Io {
        err: std::io::Error,
        path: PathBuf,
    },
    LogLevel(String),
}

trait PathContext<T> {
    fn context<P: AsRef<Path>>(self, path: P) -> Result<T, ConfigError>;
}

impl<T> PathContext<T> for serde_json::Result<T> {
    fn context<P: AsRef<Path>>(self, path: P) -> Result<T, ConfigError> {
        self.map_err(|e| ConfigError::Parsing {
            err: e,
            path: path.as_ref().to_path_buf(),
        })
    }
}

impl<T> PathContext<T> for std::io::Result<T> {
    fn context<P: AsRef<Path>>(self, path: P) -> Result<T, ConfigError> {
        self.map_err(|e| ConfigError::Io {
            err: e,
            path: path.as_ref().to_path_buf(),
        })
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::UnknownOption82Extractor(ex) => {
                write!(f, "Unknown Option82 extractor function `{ex}`")
            }
            ConfigError::Parsing { err, path } => {
                write!(f, "Parsing `{}`: {err}", path.to_string_lossy())
            }
            ConfigError::Io { err, path } => write!(f, "`{}`: {err}", path.to_string_lossy()),
            ConfigError::LogLevel(value) => write!(
                f,
                r#"Unexpected log level {value}. Expected one of [trace, debug, info, warn, error]"#
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Load server config from `config.json` and `ids.json` in the current directory
    pub fn load_from_files<P: AsRef<Path>>(config_dir: P) -> Result<Config, ConfigError> {
        let server_config_path = config_dir.as_ref().join("config.json");
        let server_config: ServerConfig = serde_json::from_reader(
            std::fs::File::open(&server_config_path).context(&server_config_path)?,
        )
        .context(&server_config_path)?;

        let server_ids_path = config_dir.as_ref().join("ids.json");
        let server_ids: ServerIds = serde_json::from_reader(
            std::fs::File::open(&server_ids_path).context(&server_ids_path)?,
        )
        .context(&server_ids_path)?;

        let option82_extractors_map = extractors::get_all_extractors();

        let mut option82_extractors = Vec::with_capacity(server_config.option82_extractors.len());
        for extractor_str in server_config.option82_extractors {
            match option82_extractors_map.get(extractor_str.as_str()) {
                Some(extractor) => option82_extractors.push(extractor.to_owned()),
                None => return Err(ConfigError::UnknownOption82Extractor(extractor_str)),
            }
        }

        let log_level = match server_config.log_level {
            Some(s) if !s.is_empty() => {
                tracing::Level::from_str(&s).map_err(|_| ConfigError::LogLevel(s))?
            }
            _ => tracing::Level::INFO,
        };

        Ok(Config {
            dns_v4: server_config.dns_v4,
            v4_server_id: server_ids.v4,
            subnets_v4: server_config.subnets_v4,
            v6_server_id: server_ids.v6,
            option82_extractors,
            log_level,
            events_address: server_config.events_address,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deser_config() {
        Config::load_from_files(".").unwrap();
    }
}
