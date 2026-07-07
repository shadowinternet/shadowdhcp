use std::{
    io,
    net::{SocketAddr, TcpListener, UdpSocket},
    path::PathBuf,
    sync::{atomic::AtomicU64, mpsc, Arc},
    thread,
    time::Duration,
};

use arc_swap::ArcSwap;

use crate::analytics::EventSenders;
use crate::config::Config;
use crate::opt82_cache::Opt82Cache;
use crate::reservationdb::ReservationDb;
use crate::v4::extractors;
use crate::{analytics::events::DhcpEvent, types::Reservation};

mod analytics;
mod batch;
#[cfg(feature = "clickhouse")]
mod clickhouse_http;
mod config;
mod logging;
mod mgmt;
mod opt82_cache;
mod reservationdb;
mod shutdown;
#[cfg(unix)]
mod signal;
mod types;
mod v4;
mod v6;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const GITHUB_SHA: Option<&str> = option_env!("GITHUB_SHA");

fn main() {
    let mut args = pico_args::Arguments::from_env();
    if args.contains(["-h", "--help"]) {
        print!("{}", HELP);
        return;
    }
    if args.contains("--help-config") {
        print!("{}", HELP_CONFIG);
        return;
    }
    if args.contains("--help-reservations") {
        print!("{}", HELP_RESERVATIONS);
        return;
    }
    if args.contains("--available-extractors") {
        let mut extractors: Vec<_> = extractors::get_all_extractors().into_keys().collect();
        extractors.sort_unstable();
        println!("Option82 (DHCPv4): {}", extractors.join(", "));
        let mut extractors_v6: Vec<_> = v6::extractors::get_all_extractors().into_keys().collect();
        extractors_v6.sort_unstable();
        println!("Option18/37 (DHCPv6): {}", extractors_v6.join(", "));
        println!("MAC (DHCPv6): client_linklayer_address, peer_addr_eui64, duid");
        return;
    }
    if args.contains("--version") {
        let commit = match GITHUB_SHA {
            Some(sha) => &sha[0..7],
            None => "unknown",
        };
        println!("{VERSION} ({commit})");
        return;
    }

    let config_dir: PathBuf = args
        .opt_value_from_str("--configdir")
        .expect("Parsing option --configdir")
        .unwrap_or_else(|| PathBuf::from("."));

    // Check for any remaining unused arguments
    let remaining = args.finish();
    if !remaining.is_empty() {
        eprintln!(
            "Unexpected arguments: {:?}\n Run `shadowdhcp --help` for usage",
            remaining
        );
        std::process::exit(1);
    }

    let shutdown = shutdown::Shutdown::new();

    let config = match Config::load_from_files(&config_dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Unable to load config file: {e}");
            std::process::exit(1);
        }
    };
    // ClickHouse log writer (when enabled) returned here so we can spawn it
    // inside `thread::scope` and join on shutdown alongside the events writer.
    // The guards flush buffered file logs when they drop at the end of main.
    let (log_writer, _log_guards) = logging::init(
        &config.logging,
        config.clickhouse.as_ref(),
        shutdown.clone(),
    );
    let config = Arc::new(ArcSwap::from_pointee(config));

    let reservations_path = config_dir.join("reservations.json");
    let reservations: Vec<Reservation> = match std::fs::File::open(&reservations_path) {
        Ok(file) => match serde_json::from_reader(file) {
            Ok(res) => res,
            Err(e) => {
                eprintln!("Failed to parse {}: {e}", reservations_path.display());
                std::process::exit(1);
            }
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            tracing::warn!("No reservations.json found, starting with empty reservations");
            Vec::new()
        }
        Err(e) => {
            eprintln!("Failed to open {}: {e}", reservations_path.display());
            std::process::exit(1);
        }
    };
    tracing::info!("Loaded {} reservations", reservations.len());

    let db = ReservationDb::new();
    db.load_reservations(reservations);
    let db = Arc::new(ArcSwap::from_pointee(db));
    let leases = Arc::new(Opt82Cache::new());

    let loaded_config = config.load();
    let events_address = loaded_config.events.tcp;
    let mgmt_address = loaded_config.mgmt_address;
    let events_queue_size = loaded_config.events.queue_size;

    #[cfg(feature = "clickhouse")]
    let clickhouse_config = if loaded_config.events.clickhouse.unwrap_or(true) {
        loaded_config.clickhouse.clone()
    } else {
        None
    };
    drop(loaded_config);

    let mut senders = EventSenders::new();
    let tcp_rx: Option<(mpsc::Receiver<DhcpEvent>, Arc<AtomicU64>)> = events_address.map(|_| {
        let (tx, rx) = mpsc::sync_channel::<DhcpEvent>(events_queue_size);
        let dropped = Arc::new(AtomicU64::new(0));
        senders.push(tx, dropped.clone());
        (rx, dropped)
    });
    #[cfg(feature = "clickhouse")]
    let clickhouse_rx: Option<(mpsc::Receiver<DhcpEvent>, Arc<AtomicU64>)> =
        clickhouse_config.as_ref().map(|_| {
            let (tx, rx) = mpsc::sync_channel::<DhcpEvent>(events_queue_size);
            let dropped = Arc::new(AtomicU64::new(0));
            senders.push(tx, dropped.clone());
            (rx, dropped)
        });
    let senders = if senders.is_empty() {
        None
    } else {
        Some(senders)
    };

    // Bind sockets before spawning threads - fail fast if any fails
    let v4_socket = bind_udp_socket(config.load().v4_bind_address, "DHCPv4");
    let v6_socket = bind_udp_socket(config.load().v6_bind_address, "DHCPv6");
    let mgmt_listener = mgmt_address.map(|addr| bind_tcp_socket(addr, "management"));
    tracing::info!("Bound DHCPv4 to {}", config.load().v4_bind_address);
    tracing::info!("Bound DHCPv6 to {}", config.load().v6_bind_address);
    if let Some(addr) = mgmt_address {
        tracing::info!("Bound management to {}", addr);
    }

    // Spawn signal handler (Unix only, before thread::scope; it exits on its
    // own after signalling shutdown). SIGHUP reloads reservations,
    // SIGTERM/SIGINT drain and exit.
    #[cfg(unix)]
    let _signal_handler =
        signal::spawn_signal_handler(db.clone(), config_dir.clone(), shutdown.clone());

    // Management listener runs detached, not in the scope below: it blocks
    // in accept() with no wakeup mechanism and simply dies with the process
    // on shutdown. Safe even mid-request — reservation persistence is an
    // atomic write+rename — and keeps blocking accept, so management
    // clients see no polling latency.
    if let Some(listener) = mgmt_listener {
        let mgmt_db = db.clone();
        let mgmt_config_dir = config_dir.clone();
        thread::Builder::new()
            .name("mgmt".to_string())
            .spawn(move || mgmt::listener(listener, mgmt_db, mgmt_config_dir))
            .expect("mgmt spawn");
    }

    // `thread::scope` auto-joins every spawned thread when the closure
    // returns and re-raises any panic. Every thread watches `shutdown`
    // (directly or via its channel disconnecting), so on SIGTERM the scope
    // unwinds cleanly and main returns, flushing the log guards.
    thread::scope(|s| {
        let cleanup_leases = leases.clone();
        let cleanup_db = db.clone();
        let cleanup_shutdown = shutdown.clone();
        thread::Builder::new()
            .name("opt82-cleanup".to_string())
            .spawn_scoped(s, move || {
                while !cleanup_shutdown.wait_timeout(Duration::from_hours(1)) {
                    cleanup_leases.evict_expired(Duration::from_hours(24), &cleanup_db.load());
                }
            })
            .expect("opt82-cleanup spawn");

        let (v4db, v4leases, v4config, v4sinks, v4shutdown) = (
            db.clone(),
            leases.clone(),
            config.clone(),
            senders.clone(),
            shutdown.clone(),
        );
        thread::Builder::new()
            .name("v4worker".to_string())
            .spawn_scoped(s, move || {
                v4::v4_worker(v4_socket, v4db, v4leases, v4config, v4sinks, v4shutdown)
            })
            .expect("v4worker spawn");

        let (v6db, v6leases, v6config, v6sinks, v6shutdown) = (
            db.clone(),
            leases.clone(),
            config.clone(),
            senders.clone(),
            shutdown.clone(),
        );
        thread::Builder::new()
            .name("v6worker".to_string())
            .spawn_scoped(s, move || {
                v6::v6_worker(v6_socket, v6db, v6leases, v6config, v6sinks, v6shutdown)
            })
            .expect("v6worker spawn");

        // Only the workers hold event senders from here on, so once they
        // exit the writers see their channels disconnect and drain.
        drop(senders);

        if let Some((addr, (rx, dropped))) = events_address.zip(tcp_rx) {
            let writer_shutdown = shutdown.clone();
            thread::Builder::new()
                .name("events-tcp".to_string())
                .spawn_scoped(s, move || {
                    analytics::writer::tcp_writer(addr, rx, dropped, writer_shutdown)
                })
                .expect("events-tcp spawn");
        }

        #[cfg(feature = "clickhouse")]
        if let Some((cfg, (rx, dropped))) = clickhouse_config.zip(clickhouse_rx) {
            let writer_shutdown = shutdown.clone();
            thread::Builder::new()
                .name("events-ch".to_string())
                .spawn_scoped(s, move || {
                    analytics::clickhouse::clickhouse_writer(cfg, rx, dropped, writer_shutdown)
                })
                .expect("events-ch spawn");
        }

        if let Some(task) = log_writer {
            thread::Builder::new()
                .name("ch-logs".to_string())
                .spawn_scoped(s, task)
                .expect("ch-logs spawn");
        }
    });

    tracing::info!("shutdown complete");
}

const HELP: &str = "\
shadowdhcp

A reservation only DHCPv4 and DHCPv6 server designed for internet service providers.

USAGE:
  shadowdhcp [OPTIONS]

FLAGS:
  -h, --help                    Prints this help information
      --help-config             Configuration file help
      --help-reservations       Reservations file help
      --available-extractors    Print list of available extractors for Option82 and Option18/37

OPTIONS:
  --configdir PATH              Sets the directory to read config files from

RUNTIME UPDATES:
  Reservations can be reloaded at runtime via:
  - SIGHUP signal: Reloads reservations.json from disk
  - Management interface (if mgmt_address is set in config.json):
    echo '{\"command\":\"reload\"}' | nc localhost 8547
    echo '{\"command\":\"replace\",\"reservations\":[...]}' | nc localhost 8547
    echo '{\"command\":\"status\"}' | nc localhost 8547
";

const HELP_CONFIG: &str = r#"Config files are stored in a directory specified by --configdir (defaults to current directory):
  - ids.json contains the DHCPv4 and DHCPv6 server IDs
  - config.json server wide configuration
  - reservations.json IP reservations, can be hot reloaded. See --help-reservations

Extractors are run in order from the config file, put the most commonly used extractors first.

Option82 extractors parse DHCPv4 relay agent information (circuit, remote, subscriber fields).
Option18/37 extractors parse DHCPv6 interface-id (Option 18) and remote-id (Option 37) fields.
MAC extractors (DHCPv6) control how client MAC addresses are extracted from relay messages.

Run `shadowdhcp --available-extractors` to see all available extractors.

config.json:
{
    "dns_v4": [
        "8.8.8.8",
        "8.8.4.4"
    ],
    "dns_v6": [
        "2001:4860:4860::8888",
        "2001:4860:4860::8844"
    ],
    "subnets_v4": [
        {
            "net": "100.100.1.0/24",
            "gateway": "100.100.1.1"
        },
        {
            "net": "100.100.2.0/24",
            "gateway": "100.100.3.1"
        }
    ],
    "option82_extractors": [
        "remote_only",
        "subscriber_only",
        "circuit_and_remote",
        "remote_first_12"
    ],
    "option1837_extractors": [
        "interface_only",
        "remote_only",
        "interface_and_remote"
    ],
    "mac_extractors": [
        "client_linklayer_address"
    ],
    "logging": {
        "level": "info"
    },
    "clickhouse": {
        "url": "https://clickhouse.example.com",
        "user": "dhcp_writer",
        "password": "changeme"
    },
    "events": {
        "tcp": "127.0.0.1:9000"
    },
    "mgmt_address": "127.0.0.1:8547"
}

Optional fields:
  - option82_extractors: List of DHCPv4 Option82 extractor functions
  - option1837_extractors: List of DHCPv6 Option18/37 extractor functions
  - mac_extractors: List of DHCPv6 MAC extraction methods (default: ["client_linklayer_address"])
  - v4_lease_time: DHCPv4 lease time, seconds (default: 3600)
  - v6_lease_time: DHCPv6 valid lifetime, seconds (default: 12 * v4_lease_time)
  - logging: Logging block. Fields:
      level      - One of [trace, debug, info, warn, error] (default: info)
      stdout     - Write to stdout (default: true if logging block present)
      file       - { path, max_files } for in-process rotating file sink
      clickhouse - Toggle: ship logs to dhcp.otel_logs in ClickHouse via the
                   top-level `clickhouse` block (default: true when that block
                   is present)
  - clickhouse: ClickHouse connection (HTTPS). Required: url, user, password.
                Optional: database (default "dhcp"), hostname (default: read from /etc/hostname).
                Enabled by the "clickhouse" cargo feature (on by default). When
                present, both events and logs are shipped here unless their
                respective toggles are set to false.
  - events: Event sink block. Fields:
      queue_size - Per-sink in-memory queue capacity (default: 16384)
      tcp        - Address:port for analytics events over TCP (JSON lines)
      clickhouse - Toggle: insert events into dhcp.events_v4 / dhcp.events_v6
                   (default: true when the top-level clickhouse block is set)
  - mgmt_address: Address:port for management interface (reload/replace
                  reservations). Must be a loopback address; the interface
                  has no authentication, so any local process can use it.
                  Management clients are expected to run on this machine.
  - v4_bind_address: Address:port for DHCPv4 (default: 0.0.0.0:67)
  - v6_bind_address: Address:port for DHCPv6 (default: [::]:547)

ids.json:
{
    "v4": "192.168.1.1",
    "v6": "00:11:22:33:44:55:66:77:88:99:11:12:13:14:15:16"
}
"#;

const HELP_RESERVATIONS: &str = r#"Reservations must contain:
  - ipv4
  - ipv6_na
  - ipv6_pd
  - At least one source for IPv4 and IPv6. Some sources can be used for both
    - mac - can be used for both
    - option82 - can be used for both. Should be formatted in all caps dash format: AA-BB-CC-DD-EE-FF
    - duid - IPv6 only

Reservations with multiple sources will be evaluated in the following order:
IPv4: mac -> option82
IPv6: duid -> option18/37 -> mac -> option82

reservations.json:
[
    {
        "ipv4": "192.168.1.109",
        "ipv6_na": "2001:db8:1:2::1",
        "ipv6_pd": "2001:db8:1:3::/56",
        "mac": "00-11-22-33-44-55"
    },
    {
        "ipv4": "192.168.1.110",
        "ipv6_na": "2001:db8:1:4::1",
        "ipv6_pd": "2001:db8:1:5::/56",
        "mac": "00-11-22-33-44-57"
    },
    {
        "ipv4": "192.168.1.111",
        "ipv6_na": "2001:db8:1:6::1",
        "ipv6_pd": "2001:db8:1:7::/56",
        "option82": {"circuit": "99-11-22-33-44-55", "remote": "eth2:100"}
    },
    {
        "ipv4": "192.168.1.112",
        "ipv6_na": "2001:db8:1:8::1",
        "ipv6_pd": "2001:db8:1:9::/56",
        "duid": "29:30:31:32:33:34:35:36:37:38:39:40:41:42:43:44",
        "option82": {"subscriber": "subscriber:1020"}
    },
    {
        "ipv4": "100.110.1.2",
        "ipv6_na": "2001:db8:1::1",
        "ipv6_pd": "2001:db8:2::/56",
        "option82": {"remote": "AC-8B-A9-E2-17-F8"}
    }
]
"#;

fn bind_udp_socket(addr: impl Into<SocketAddr>, protocol: &str) -> UdpSocket {
    let addr = addr.into();
    match UdpSocket::bind(addr) {
        Ok(socket) => socket,
        Err(e) => {
            print_bind_error(addr, protocol, &e);
            std::process::exit(1);
        }
    }
}

fn bind_tcp_socket(addr: impl Into<SocketAddr>, protocol: &str) -> TcpListener {
    let addr = addr.into();
    match TcpListener::bind(addr) {
        Ok(listener) => listener,
        Err(e) => {
            print_bind_error(addr, protocol, &e);
            std::process::exit(1);
        }
    }
}

fn print_bind_error(addr: SocketAddr, protocol: &str, e: &io::Error) {
    eprintln!("Failed to bind {protocol} socket to {addr}: {e}");
    match e.kind() {
        io::ErrorKind::PermissionDenied => {
            eprintln!(
                "Hint: Binding to port {} requires elevated privileges.",
                addr.port()
            );
            #[cfg(unix)]
            {
                let exe_path = std::env::current_exe()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "./shadowdhcp".to_string());
                eprintln!("  - Run as root, or");
                eprintln!("  - Use setcap: sudo setcap 'cap_net_bind_service=+ep' {exe_path}");
            }
            #[cfg(windows)]
            {
                eprintln!("  - Run as Administrator");
            }
        }
        io::ErrorKind::AddrInUse => {
            eprintln!(
                "Hint: Port {} is already in use by another process.",
                addr.port()
            );
            #[cfg(unix)]
            eprintln!("  - Check with: ss -tlnp | grep {}", addr.port());
            #[cfg(windows)]
            eprintln!("  - Check with: netstat -ano | findstr :{}", addr.port());
        }
        io::ErrorKind::AddrNotAvailable => {
            eprintln!(
                "Hint: Address {} is not available on this system.",
                addr.ip()
            );
            #[cfg(unix)]
            eprintln!("  - Check available addresses with: ip addr");
            #[cfg(windows)]
            eprintln!("  - Check available addresses with: ipconfig");
        }
        _ => {}
    }
}
