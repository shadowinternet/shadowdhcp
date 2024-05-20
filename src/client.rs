use dhcproto::{v6, Encodable};

use std::net::{Ipv6Addr, UdpSocket};

fn main() {
    let msg = dhcpv6_test_request().to_vec().expect("encoding test msg");

    // send message to localhost udp
    let socket = UdpSocket::bind("[::1]:34254").expect("couldn't bind to address");
    socket
        .send_to(&msg, "[::1]:567")
        .expect("couldn't send data");
}

fn dhcpv6_test_request() -> v6::RelayMessage {
    let duid = vec![
        29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
    ];
    // construct a new Solicit Message with a random xid
    let mut msg = v6::Message::new(v6::MessageType::Solicit);
    // set an option
    msg.opts_mut().insert(v6::DhcpOption::ClientId(duid));

    // package this message into a RelayForw Message
    let mut relay_opts = v6::DhcpOptions::new();
    relay_opts.insert(v6::DhcpOption::RelayMsg(v6::RelayMessageData::Message(msg)));

    let mut relay_msg = v6::RelayMessage {
        msg_type: v6::MessageType::RelayForw,
        hop_count: 0,
        link_addr: Ipv6Addr::new(8, 8, 8, 8, 8, 8, 8, 8),
        peer_addr: Ipv6Addr::new(9, 9, 9, 9, 9, 9, 9, 9),
        opts: relay_opts,
    };

    relay_msg
}
