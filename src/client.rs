use dhcproto::{v6, Decodable, Encodable};

use std::net::{Ipv6Addr, UdpSocket};

fn main() {
    let msg = dhcpv6_test_request().to_vec().expect("encoding test msg");

    // send message to localhost udp
    let socket = UdpSocket::bind("[::1]:0").expect("couldn't bind to address");
    socket
        .send_to(&msg, "[::1]:547")
        .expect("couldn't send data");

    let mut recv_buf = vec![0u8; 1500];
    let recv_bytes = socket.recv(&mut recv_buf).expect("socket recv");
    println!("received {recv_bytes} bytes in response");

    let msg = v6::RelayMessage::from_bytes(&recv_buf[..recv_bytes]).expect("parsing response");
    println!("msg: {msg}");
}

fn dhcpv6_test_request() -> v6::RelayMessage {
    let duid = vec![
        0x29, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40, 0x41, 0x42, 0x43,
        0x44,
    ];
    // construct a new Solicit Message with a random xid
    let mut msg = v6::Message::new(v6::MessageType::Solicit);
    // set an option
    msg.opts_mut().insert(v6::DhcpOption::ClientId(duid));

    // package this message into a RelayForw Message
    let mut relay_opts = v6::DhcpOptions::new();
    relay_opts.insert(v6::DhcpOption::RelayMsg(v6::RelayMessageData::Message(msg)));

    v6::RelayMessage {
        msg_type: v6::MessageType::RelayForw,
        hop_count: 0,
        link_addr: Ipv6Addr::new(8, 8, 8, 8, 8, 8, 8, 8),
        peer_addr: Ipv6Addr::new(9, 9, 9, 9, 9, 9, 9, 9),
        opts: relay_opts,
    }
}
