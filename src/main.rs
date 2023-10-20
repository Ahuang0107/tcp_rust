use std::collections::hash_map::Entry;

mod tcp;
mod util;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Quad {
    src: (std::net::Ipv4Addr, u16),
    dst: (std::net::Ipv4Addr, u16),
}

fn main() -> std::io::Result<()> {
    let mut connections: std::collections::HashMap<Quad, tcp::Connection> = Default::default();
    let listening_ports: std::collections::HashSet<u16> =
        std::collections::HashSet::from([80, 443]);
    println!("try to crate a TUN device");
    let mut nic =
        tun_tap::Iface::new("tun0", tun_tap::Mode::Tun).expect("Failed to create a TUN device");
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
        println!(
            "received raw eth frame(flags: {eth_flags:x?},proto: {eth_proto:x?}): {:x?}",
            &buf[..bytes_n]
        );
        if eth_proto != 0x0800 {
            // not ipv4
            continue;
        }
        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..bytes_n]) {
            Ok(iph) => {
                let src = iph.source_addr();
                let dst = iph.destination_addr();
                if iph.protocol() != 0x06 {
                    // not tcp
                    continue;
                }
                let ip_header_size = iph.slice().len();
                match etherparse::TcpHeaderSlice::from_slice(&buf[4 + ip_header_size..bytes_n]) {
                    Ok(seg) => {
                        // (srcip, srcport, dstip, dstport)
                        let tcp_header_size = seg.slice().len();
                        let data_start_index = 4 + ip_header_size + tcp_header_size;
                        match connections.entry(Quad {
                            src: (src, seg.source_port()),
                            dst: (dst, seg.destination_port()),
                        }) {
                            Entry::Occupied(_) => {
                                unimplemented!()
                            }
                            Entry::Vacant(e) => {
                                // rfc 793, page 64
                                if listening_ports.contains(&seg.destination_port()) {
                                    // If the state is LISTEN then
                                    if let Some(c) = tcp::Connection::accept(
                                        &mut nic,
                                        iph,
                                        seg,
                                        &buf[data_start_index..bytes_n],
                                    )? {
                                        e.insert(c);
                                    }
                                } else {
                                    // If the state is CLOSED (i.e., TCB does not exist) then
                                    if seg.rst() {
                                        // An incoming
                                        // segment containing a RST is discarded
                                    } else {
                                        // An incoming segment not
                                        // containing a RST causes a RST to be sent in response
                                        let mut tcp = etherparse::TcpHeader::new(
                                            seg.destination_port(),
                                            seg.source_port(),
                                            0,
                                            1024,
                                        );
                                        if !seg.ack() {
                                            // If the ACK bit is off, sequence number zero is used,
                                            // <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
                                            tcp.acknowledgment_number = seg.sequence_number();
                                            tcp.rst = true;
                                            tcp.ack = true;
                                        } else {
                                            // If the ACK bit is on
                                            // <SEQ=SEG.ACK><CTL=RST>
                                            tcp.sequence_number = seg.acknowledgment_number();
                                            tcp.rst = true;
                                        }
                                        let ip = etherparse::Ipv4Header::new(
                                            0,
                                            64,
                                            etherparse::IpTrafficClass::Tcp,
                                            iph.destination_addr().octets(),
                                            iph.source_addr().octets(),
                                        );
                                        util::response(&mut nic, &tcp, &ip)?;
                                    }
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
