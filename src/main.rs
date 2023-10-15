use std::collections::hash_map::Entry;

mod tcp;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Quad {
    src: (std::net::Ipv4Addr, u16),
    dst: (std::net::Ipv4Addr, u16),
}

fn main() -> std::io::Result<()> {
    let mut connections: std::collections::HashMap<Quad, tcp::Connection> = Default::default();
    println!("try to crate a TUN device");
    let mut nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)
        .expect("Failed to create a TUN device");
    let mut buf = [0u8; 1504];
    println!("try to read bytes from {}", nic.name());
    loop {
        let bytes_n = nic.recv(&mut buf[..])?;
        // 2 bits to represent Flags
        // IFF_TUN   - TUN device (no Ethernet headers)
        // IFF_TAP   - TAP device
        // IFF_NO_PI - Do not provide packet information
        // IFF_MULTI_QUEUE - Create a queue of multiqueue device
        let eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
        println!("received raw eth frame(flags: {eth_flags:x?},proto: {eth_proto:x?}): {:x?}", &buf[..bytes_n]);
        if eth_proto != 0x0800 {
            // not ipv4
            continue;
        }
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..bytes_n]) {
            Ok(ip_header) => {
                let src = ip_header.source_addr();
                let dst = ip_header.destination_addr();
                if ip_header.protocol() != 0x06 {
                    // not tcp
                    continue;
                }
                let ip_header_size = ip_header.slice().len();
                match etherparse::TcpHeaderSlice::from_slice(&buf[4 + ip_header_size..bytes_n]) {
                    Ok(tcp_header) => {
                        // (srcip, srcport, dstip, dstport)
                        let tcp_header_size = tcp_header.slice().len();
                        let data_start_index = 4 + ip_header_size + tcp_header_size;
                        match connections.entry(Quad {
                            src: (src, tcp_header.source_port()),
                            dst: (dst, tcp_header.destination_port()),
                        }) {
                            Entry::Occupied(_) => {
                                unimplemented!()
                            }
                            Entry::Vacant(e) => {
                                if let Some(c) = tcp::Connection::accept(
                                    &mut nic,
                                    ip_header,
                                    tcp_header,
                                    &buf[data_start_index..bytes_n],
                                )? {
                                    e.insert(c);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("ignore weird tcp packet {e:?}");
                    }
                }
            }
            Err(e) => {
                eprintln!("ignoring weird packet {e:?}");
            }
        }
    }
}
