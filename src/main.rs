use std::net::Ipv4Addr;

use shadow_dhcpv6::{Reservation, Storage, V4Subnet};

mod v4;
mod v6;

fn main() {
    let subnets = [V4Subnet {
        net: "192.168.0.0/24".parse().unwrap(),
        gateway: "192.168.0.1".parse().unwrap(),
    }];
    let v4_dns = [Ipv4Addr::from([8, 8, 8, 8]), Ipv4Addr::from([8, 8, 4, 4])];

    let reservations: Vec<Reservation> =
        serde_json::from_reader(std::fs::File::open("reservations.json").unwrap()).unwrap();

    let mut storage = Storage::new(&reservations, &subnets, &v4_dns);
    v6::v6_worker(&mut storage);
    println!("hi");
}
