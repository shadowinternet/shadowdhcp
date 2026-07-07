use serde::Deserialize;
use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    path::{Path, PathBuf},
    str::FromStr,
};

use crate::types::{Duid, V4Subnet};
use crate::v4::extractors::{self as v4_extractors, NamedOption82Extractor};
use crate::v6::extractors::{self as v6_extractors, NamedOption1837Extractor};
use crate::v6::mac_extractors::MacExtractor;

/// Server wide configuration
pub struct Config {
    pub v4_server_id: Ipv4Addr,
    pub dns_v4: Vec<Ipv4Addr>,
    pub dns_v6: Vec<Ipv6Addr>,
    pub subnets_v4: Vec<V4Subnet>,
    pub v6_server_id: Duid,
    pub option82_extractors: Vec<NamedOption82Extractor>,
    pub option1837_extractors: Vec<NamedOption1837Extractor>,
    pub mac_extractors: Vec<MacExtractor>,
    pub lease_times: LeaseTimes,
    pub logging: LoggingConfig,
    pub events: EventsConfig,
    pub clickhouse: Option<ClickHouseConfig>,
    pub mgmt_address: Option<SocketAddr>,
    pub v4_bind_address: SocketAddrV4,
    pub v6_bind_address: SocketAddrV6,
}

/// Default DHCPv4 lease time (seconds). RFC 2131 §4.4.5 implicitly assumes
/// the lease is on the order of hours; 1 hour keeps the opt82→mac binding
/// cache refreshed frequently without churning clients.
const DEFAULT_V4_LEASE: u32 = 3600;
/// Default multiple applied to `v4_lease_time` when `v6_lease_time` is not
/// supplied. The v6 lease wants to be comfortably longer than v4 so that
/// after a server reboot, v4 has time to refresh the opt82→mac cache before
/// a v6 lease expires (since the cache is in-memory and lost on restart).
const DEFAULT_V6_MULTIPLE: u32 = 12;

/// Lease and renewal timers for both protocols. Derived once at config load
/// from the two user-supplied base values (v4 lease, v6 valid lifetime). All
/// downstream code reads from this struct rather than recomputing the
/// derivations.
///
/// Ratios follow the RFCs: v4 T1 = 0.5·lease, T2 = 7/8·lease (RFC 2131); v6
/// preferred = 0.5·valid, T1 = 0.5·preferred, T2 = 4/5·preferred (RFC 8415).
#[derive(Debug, Clone, Copy)]
pub struct LeaseTimes {
    pub v4_lease: u32,
    pub v4_renewal: u32,
    pub v4_rebinding: u32,
    pub v6_valid: u32,
    pub v6_preferred: u32,
    pub v6_renewal: u32,
    pub v6_rebinding: u32,
}

impl LeaseTimes {
    pub fn from_base(v4_lease: u32, v6_valid: u32) -> Self {
        let v6_preferred = v6_valid / 2;
        Self {
            v4_lease,
            v4_renewal: v4_lease / 2,
            v4_rebinding: v4_lease * 7 / 8,
            v6_valid,
            v6_preferred,
            v6_renewal: v6_preferred / 2,
            v6_rebinding: v6_preferred * 4 / 5,
        }
    }
}

impl Default for LeaseTimes {
    fn default() -> Self {
        Self::from_base(
            DEFAULT_V4_LEASE,
            DEFAULT_V4_LEASE.saturating_mul(DEFAULT_V6_MULTIPLE),
        )
    }
}

/// Server wide configuration, used to deserialize the config.json file before
/// transforming to `Config`
#[derive(Deserialize)]
struct ServerConfig {
    dns_v4: Vec<Ipv4Addr>,
    dns_v6: Vec<Ipv6Addr>,
    subnets_v4: Vec<V4Subnet>,
    #[serde(default)]
    option82_extractors: Vec<String>,
    #[serde(default)]
    option1837_extractors: Vec<String>,
    mac_extractors: Option<Vec<MacExtractor>>,
    v4_lease_time: Option<u32>,
    v6_lease_time: Option<u32>,
    logging: Option<ServerLoggingConfig>,
    #[serde(default)]
    events: EventsConfig,
    clickhouse: Option<ClickHouseConfig>,
    mgmt_address: Option<SocketAddr>,
    v4_bind_address: Option<SocketAddrV4>,
    v6_bind_address: Option<SocketAddrV6>,
}

/// Server IDs stored in separate file that may be auto generated in the future
#[derive(Deserialize)]
struct ServerIds {
    v4: Ipv4Addr,
    v6: Duid,
}

/// DHCP event sinks. Each sink is enabled by its presence (TCP) or by an
/// explicit toggle (ClickHouse, defaults to true when the top-level
/// `clickhouse` block is set). `queue_size` is applied independently to each
/// sink's bounded channel.
#[derive(Debug, Clone, Deserialize)]
pub struct EventsConfig {
    #[serde(default = "default_events_queue_size")]
    pub queue_size: usize,
    pub tcp: Option<SocketAddr>,
    /// Toggle: send events to ClickHouse. Defaults to true when the top-level
    /// `clickhouse` block is present. Set to false to disable.
    pub clickhouse: Option<bool>,
}

fn default_events_queue_size() -> usize {
    16384
}

impl Default for EventsConfig {
    fn default() -> Self {
        Self {
            queue_size: default_events_queue_size(),
            tcp: None,
            clickhouse: None,
        }
    }
}

/// Connection details for the self-hosted ClickHouse server
#[derive(Clone, Deserialize)]
pub struct ClickHouseConfig {
    /// Base URL (e.g. "https://clickhouse.example.com" or "https://host:8443")
    pub url: String,
    pub user: String,
    pub password: String,
    /// Database name, defaults to "dhcp"
    #[serde(default = "default_database")]
    pub database: String,
    /// Value used both for the `host_name` column on event rows and for the
    /// `host.name` resource attribute on log rows. If unset, reads from
    /// `/etc/hostname` at startup (empty string on platforms without one).
    #[serde(default)]
    pub hostname: Option<String>,
}

impl std::fmt::Debug for ClickHouseConfig {
    /// Debug print without password
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClickHouseConfig")
            .field("url", &self.url)
            .field("user", &self.user)
            .field("database", &self.database)
            .field("hostname", &self.hostname)
            .finish()
    }
}

fn default_database() -> String {
    "dhcp".to_string()
}

/// Top-level `logging` block from `config.json`.
#[derive(Deserialize)]
struct ServerLoggingConfig {
    /// Log verbosity. One of: `trace`, `debug`, `info`, `warn`, `error`.
    /// Resolved by the config loader; this field is here so it can sit
    /// alongside the sinks it controls. Default: `info`.
    pub level: Option<String>,
    pub stdout: Option<bool>,
    pub file: Option<FileLogConfig>,
    /// Toggle: send logs to ClickHouse via the top-level `clickhouse` block.
    /// Defaults to true when that block is present. Set to false to disable.
    pub clickhouse: Option<bool>,
    /// In-memory queue capacity for the ClickHouse log sink. Records over the
    /// limit are dropped instead of back-pressuring the request path. Default
    /// 16384.
    pub queue_size: Option<usize>,
}

pub struct LoggingConfig {
    pub level: tracing::Level,
    pub stdout: bool,
    pub file: Option<FileLogConfig>,
    pub clickhouse: bool,
    pub queue_size: usize,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: tracing::Level::INFO,
            stdout: true,
            file: None,
            clickhouse: true,
            queue_size: 16384,
        }
    }
}

impl TryFrom<ServerLoggingConfig> for LoggingConfig {
    type Error = ConfigError;

    fn try_from(c: ServerLoggingConfig) -> Result<Self, Self::Error> {
        let level = match c.level.as_deref().filter(|s| !s.is_empty()) {
            Some(s) => {
                tracing::Level::from_str(s).map_err(|_| ConfigError::LogLevel(s.to_string()))?
            }
            None => tracing::Level::INFO,
        };
        Ok(Self {
            level,
            stdout: c.stdout.unwrap_or(true),
            file: c.file,
            clickhouse: c.clickhouse.unwrap_or(true),
            queue_size: c.queue_size.unwrap_or(16384),
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileLogConfig {
    pub path: PathBuf,
    #[serde(default = "default_max_files")]
    pub max_files: usize,
}

fn default_max_files() -> usize {
    3
}

#[derive(Debug)]
pub enum ConfigError {
    UnknownOption82Extractor(String),
    UnknownOption1837Extractor(String),
    Parsing {
        err: serde_json::Error,
        path: PathBuf,
    },
    Io {
        err: std::io::Error,
        path: PathBuf,
    },
    LogLevel(String),
    InvalidSubnet {
        subnet: String,
        reason: &'static str,
    },
    EmptyDnsV4,
    EmptyDnsV6,
    MgmtNotLoopback(SocketAddr),
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
            ConfigError::UnknownOption82Extractor(name) => {
                writeln!(f, "Unknown Option82 extractor: `{name}`")?;
                write!(
                    f,
                    "Run `shadowdhcp --available-extractors` to see valid options"
                )
            }
            ConfigError::UnknownOption1837Extractor(name) => {
                writeln!(f, "Unknown Option18/37 extractor: `{name}`")?;
                write!(
                    f,
                    "Run `shadowdhcp --available-extractors` to see valid options"
                )
            }
            ConfigError::Parsing { err, path } => {
                writeln!(f, "Failed to parse `{}`:", path.to_string_lossy())?;
                writeln!(f, "  {err}")?;
                write!(
                    f,
                    "Run `shadowdhcp --help-config` for configuration file format"
                )
            }
            ConfigError::Io { err, path } => {
                writeln!(f, "Cannot read `{}`: {err}", path.to_string_lossy())?;
                write!(f, "Check the file exists, or run with --configdir to specify the directory containing config.json and ids.json")
            }
            ConfigError::LogLevel(value) => {
                writeln!(f, "Invalid logging.level: `{value}`")?;
                write!(f, "Expected one of: trace, debug, info, warn, error")
            }
            ConfigError::InvalidSubnet { subnet, reason } => {
                write!(f, "Invalid subnet `{subnet}`: {reason}")
            }
            ConfigError::EmptyDnsV4 => {
                write!(f, "`dns_v4` must contain at least one IPv4 address.")
            }
            ConfigError::EmptyDnsV6 => {
                write!(f, "`dns_v6` must contain at least one IPv6 address.")
            }
            ConfigError::MgmtNotLoopback(addr) => {
                writeln!(
                    f,
                    "mgmt_address `{addr}` must be a loopback address (e.g. 127.0.0.1 or [::1])."
                )?;
                write!(
                    f,
                    "The management interface has no authentication and full write access to reservations; management clients are expected to run on the same machine."
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl Default for Config {
    fn default() -> Self {
        Config {
            v4_server_id: Ipv4Addr::UNSPECIFIED,
            dns_v4: vec![],
            dns_v6: vec![],
            subnets_v4: vec![],
            v6_server_id: Duid::default(),
            option82_extractors: vec![],
            option1837_extractors: vec![],
            mac_extractors: vec![MacExtractor::ClientLinklayerAddress],
            lease_times: LeaseTimes::default(),
            logging: LoggingConfig::default(),
            events: EventsConfig::default(),
            clickhouse: None,
            mgmt_address: None,
            v4_bind_address: "0.0.0.0:67".parse().unwrap(),
            v6_bind_address: "[::]:547".parse().unwrap(),
        }
    }
}

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

        let option82_extractors_map = v4_extractors::get_all_extractors();
        let mut option82_extractors = Vec::with_capacity(server_config.option82_extractors.len());
        for extractor_str in server_config.option82_extractors {
            match option82_extractors_map.get_key_value(extractor_str.as_str()) {
                Some((&name, &extractor)) => option82_extractors.push((name, extractor)),
                None => return Err(ConfigError::UnknownOption82Extractor(extractor_str)),
            }
        }

        let option1837_extractors_map = v6_extractors::get_all_extractors();
        let mut option1837_extractors =
            Vec::with_capacity(server_config.option1837_extractors.len());
        for extractor_str in server_config.option1837_extractors {
            match option1837_extractors_map.get_key_value(extractor_str.as_str()) {
                Some((&name, &extractor)) => option1837_extractors.push((name, extractor)),
                None => return Err(ConfigError::UnknownOption1837Extractor(extractor_str)),
            }
        }

        // Validate subnet configurations
        for subnet in &server_config.subnets_v4 {
            subnet
                .validate()
                .map_err(|reason| ConfigError::InvalidSubnet {
                    subnet: subnet.net.to_string(),
                    reason,
                })?;
        }

        if server_config.dns_v4.is_empty() {
            return Err(ConfigError::EmptyDnsV4);
        }
        if server_config.dns_v6.is_empty() {
            return Err(ConfigError::EmptyDnsV6);
        }

        // The management interface has full write access to reservations and
        // no authentication, so exposing it beyond loopback is refused
        // outright.
        if let Some(addr) = server_config.mgmt_address {
            if !addr.ip().is_loopback() {
                return Err(ConfigError::MgmtNotLoopback(addr));
            }
        }

        // Default to ClientLinklayerAddress if no extractors configured
        let mac_extractors = server_config
            .mac_extractors
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| vec![MacExtractor::ClientLinklayerAddress]);

        // Warn if a subsystem explicitly requested ClickHouse but no top-level
        // clickhouse block is present
        if server_config.clickhouse.is_none() {
            if server_config.events.clickhouse == Some(true) {
                eprintln!(
                    "warning: events.clickhouse=true but no top-level `clickhouse` block; ignoring."
                );
            }
            if let Some(l) = server_config.logging.as_ref() {
                if l.clickhouse == Some(true) {
                    eprintln!(
                        "warning: logging.clickhouse=true but no top-level `clickhouse` block; ignoring."
                    );
                }
            }
        }

        let logging = server_config
            .logging
            .map(LoggingConfig::try_from)
            .transpose()?
            .unwrap_or_default();

        let v4_lease = server_config.v4_lease_time.unwrap_or(DEFAULT_V4_LEASE);
        let v6_valid = server_config
            .v6_lease_time
            .unwrap_or_else(|| v4_lease.saturating_mul(DEFAULT_V6_MULTIPLE));
        let lease_times = LeaseTimes::from_base(v4_lease, v6_valid);

        Ok(Config {
            dns_v4: server_config.dns_v4,
            dns_v6: server_config.dns_v6,
            v4_server_id: server_ids.v4,
            subnets_v4: server_config.subnets_v4,
            v6_server_id: server_ids.v6,
            option82_extractors,
            option1837_extractors,
            mac_extractors,
            lease_times,
            logging,
            events: server_config.events,
            clickhouse: server_config.clickhouse,
            mgmt_address: server_config.mgmt_address,
            v4_bind_address: server_config
                .v4_bind_address
                .unwrap_or_else(|| "0.0.0.0:67".parse().unwrap()),
            v6_bind_address: server_config
                .v6_bind_address
                .unwrap_or_else(|| "[::]:547".parse().unwrap()),
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

    fn write_test_config(cfg: &str) -> std::path::PathBuf {
        use std::io::Write;
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "shadowdhcp-cfg-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::File::create(dir.join("config.json"))
            .unwrap()
            .write_all(cfg.as_bytes())
            .unwrap();
        std::fs::File::create(dir.join("ids.json"))
            .unwrap()
            .write_all(br#"{"v4":"10.0.0.1","v6":"00:11:22:33"}"#)
            .unwrap();
        dir
    }

    #[test]
    fn empty_dns_v4_rejected() {
        let dir = write_test_config(r#"{"dns_v4":[],"dns_v6":["2001:db8::1"],"subnets_v4":[]}"#);
        let res = Config::load_from_files(&dir);
        std::fs::remove_dir_all(&dir).ok();
        assert!(matches!(res, Err(ConfigError::EmptyDnsV4)));
    }

    #[test]
    fn empty_dns_v6_rejected() {
        let dir = write_test_config(r#"{"dns_v4":["8.8.8.8"],"dns_v6":[],"subnets_v4":[]}"#);
        let res = Config::load_from_files(&dir);
        std::fs::remove_dir_all(&dir).ok();
        assert!(matches!(res, Err(ConfigError::EmptyDnsV6)));
    }

    #[test]
    fn non_loopback_mgmt_rejected() {
        for addr in ["0.0.0.0:8547", "192.0.2.10:8547", "[2001:db8::1]:8547"] {
            let dir = write_test_config(&format!(
                r#"{{"dns_v4":["8.8.8.8"],"dns_v6":["2001:db8::1"],"subnets_v4":[],"mgmt_address":"{addr}"}}"#,
            ));
            let res = Config::load_from_files(&dir);
            std::fs::remove_dir_all(&dir).ok();
            assert!(
                matches!(res, Err(ConfigError::MgmtNotLoopback(_))),
                "{addr} should be rejected"
            );
        }
    }

    #[test]
    fn loopback_mgmt_accepted() {
        for addr in ["127.0.0.1:8547", "127.0.0.53:8547", "[::1]:8547"] {
            let dir = write_test_config(&format!(
                r#"{{"dns_v4":["8.8.8.8"],"dns_v6":["2001:db8::1"],"subnets_v4":[],"mgmt_address":"{addr}"}}"#,
            ));
            let res = Config::load_from_files(&dir);
            std::fs::remove_dir_all(&dir).ok();
            assert!(res.is_ok(), "{addr} should be accepted");
        }
    }

    #[test]
    fn invalid_log_level_errors() {
        let json = r#"{"level": "inf"}"#;
        let config: ServerLoggingConfig = serde_json::from_str(json).unwrap();
        let config = LoggingConfig::try_from(config);

        assert!(matches!(config, Err(ConfigError::LogLevel(_))));
    }
}
