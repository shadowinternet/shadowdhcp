use std::{net::Ipv4Addr, sync::Arc, thread};

use advmac::MacAddr6;
use arc_swap::ArcSwap;
use shadow_dhcpv6::{
    extractors, leasedb::LeaseDb, reservationdb::ReservationDb, Config, Reservation, V4Subnet,
};

mod v4;
mod v6;

fn main() {
    let subnets_v4 = vec![V4Subnet {
        net: "192.168.0.0/24".parse().unwrap(),
        gateway: "192.168.0.1".parse().unwrap(),
    }];
    let dns_v4 = vec![Ipv4Addr::from([8, 8, 8, 8]), Ipv4Addr::from([8, 8, 4, 4])];

    let config = Config {
        dns_v4,
        subnets_v4,
        option82_extractors: extractors::get_all_extractors().into_values().collect(),
    };
    let config = Arc::new(ArcSwap::from_pointee(config));

    let reservations: Vec<Reservation> =
        serde_json::from_reader(std::fs::File::open("reservations.json").unwrap()).unwrap();

    let db = ReservationDb::new();
    db.load_reservations(reservations);
    let db = Arc::new(ArcSwap::from_pointee(db));
    let leases = Arc::new(LeaseDb::new());

    {
        let mydb = db.load();
        if let Some(res) = mydb.by_mac(&MacAddr6::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])) {
            println!("ReservationDb reservation: {res:?}");
        }
    }

    thread::scope(|s| {
        let v4db = db.clone();
        let v4leases = leases.clone();
        let v4config = config.clone();
        let v6worker = s.spawn(|| v6::v6_worker(db, leases, config));
        let v4worker = s.spawn(|| v4::v4_worker(v4db, v4leases, v4config));

        let _ = v6worker.join();
        let _ = v4worker.join();
    })
}
