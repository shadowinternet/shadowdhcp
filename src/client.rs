use dhcproto::{v6, Encodable};

use std::net::UdpSocket;

fn main() {
    let msg = dhcpv6_test_request().to_vec().expect("encoding test msg");

    // send message to localhost udp
    let socket = UdpSocket::bind("[::1]:34254").expect("couldn't bind to address");
    socket
        .send_to(&msg, "[::1]:567")
        .expect("couldn't send data");
}

#[allow(unused)]
fn dhcpv6_test_request() -> v6::Message {
    let duid = vec![
        29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
    ];
    // construct a new Message with a random xid
    let mut msg = v6::Message::new(v6::MessageType::Solicit);
    // set an option
    msg.opts_mut().insert(v6::DhcpOption::ClientId(duid));

    msg
}
