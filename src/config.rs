use std::net::Ipv4Addr;

use crate::{extractors::Option82ExtractorFn, Duid, V4Subnet};

pub struct Config {
    pub v4_server_id: Ipv4Addr,
    pub dns_v4: Vec<Ipv4Addr>,
    pub subnets_v4: Vec<V4Subnet>,
    pub v6_server_id: Duid,
    pub option82_extractors: Vec<Option82ExtractorFn>,
}
