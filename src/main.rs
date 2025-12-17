use std::{
    path::PathBuf,
    sync::{mpsc, Arc},
    thread,
};

use arc_swap::ArcSwap;
use shadow_dhcpv6::{
    config::Config, extractors, leasedb::LeaseDb, logging, reservationdb::ReservationDb,
    Reservation,
};

use crate::analytics::events::DhcpEvent;

mod analytics;
mod v4;
mod v6;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const GIT_HASH: Option<&str> = option_env!("GIT_HASH");

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
        println!("{}", extractors.join(", "));
        return;
    }
    if args.contains("--version") {
        println!("{} ({})", VERSION, GIT_HASH.unwrap_or("unknown"));
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
        return;
    }

    let config = match Config::load_from_files(&config_dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Unable to a load config file: {e}\nCheck the file exists, or set the `--configdir` parameter to the folder containing the `config.json` and `ids.json` files.");
            return;
        }
    };
    logging::init_stdout(config.log_level);
    let config = Arc::new(ArcSwap::from_pointee(config));

    let reservations: Vec<Reservation> =
        serde_json::from_reader(std::fs::File::open(config_dir.join("reservations.json")).unwrap())
            .unwrap();
    tracing::info!("Loaded {} reservations", reservations.len());

    let db = ReservationDb::new();
    db.load_reservations(reservations);
    let db = Arc::new(ArcSwap::from_pointee(db));
    let leases = Arc::new(LeaseDb::new());

    let events_address = config.load().events_address;
    let (tx, rx) = events_address
        .as_ref()
        .map(|_| mpsc::channel::<DhcpEvent>())
        .unzip();

    thread::scope(|s| {
        let (v4db, v4leases, v4config) = (db.clone(), leases.clone(), config.clone());
        let v4worker = thread::Builder::new()
            .name("v4worker".to_string())
            .spawn_scoped(s, move || v4::v4_worker(v4db, v4leases, v4config))
            .expect("v4worker spawn");

        let v6worker = thread::Builder::new()
            .name("v6worker".to_string())
            .spawn_scoped(s, move || v6::v6_worker(db, leases, config, tx))
            .expect("v6worker spawn");

        let events_worker = events_address.zip(rx).map(|(addr, rx)| {
            thread::Builder::new()
                .name("events".to_string())
                .spawn_scoped(s, move || analytics::writer::tcp_writer(addr, rx))
                .expect("events spawn")
        });

        v4worker.join().expect("v4worker join");
        v6worker.join().expect("v6worker join");
        if let Some(handle) = events_worker {
            handle.join().expect("events join");
        }
    });
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
      --available-extractors    Print list of available Option82 extractors

OPTIONS:
  --configdir PATH              Sets the directory to read config files from
";

const HELP_CONFIG: &str = r#"Option82 extractors are run in order from the config file, put the most commonly used extractors first.

config.json:
{
    "dns_v4": [
        "8.8.8.8",
        "8.8.4.4"
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
    ]
}

ids.json:
{
    "v4": "192.168.1.1",
    "v6": "00:11:22:33:44:55:66:77:88:99:11:12:13:14:15:16"
}
"#;

const HELP_RESERVATIONS: &str = r#"Reservations must contain:
 * ipv4
 * ipv6_na
 * ipv6_pd
 * At least one source for IPv4 and IPv6. Some sources can be used for both
   * mac - can be used for both
   * option82 - can be used for both. Should be formatted in all caps dash format: AA-BB-CC-DD-EE-FF
   * duid - IPv6 only

Reservations with multiple sources will be evaluated in the following order:
IPv4: mac -> option82
IPv6: duid -> mac -> option82

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
