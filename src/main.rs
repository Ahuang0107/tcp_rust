mod tcp;

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
struct Quad {
    src: (std::net::Ipv4Addr, u16),
    dst: (std::net::Ipv4Addr, u16),
}

fn main() -> std::io::Result<()> {
    let mut connections: std::collections::HashMap<Quad, tcp::State> = Default::default();
    println!("try to crate a TUN device");
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)
        .expect("Failed to create a TUN device");
    let mut buf = [0u8; 1504];
    println!("try to read bytes from {}", nic.name());
    loop {
        let bytes_n = nic.recv(&mut buf[..])?;
        let _eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
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
                        connections.entry(Quad {
                            src: (src, tcp_header.source_port()),
                            dst: (dst, tcp_header.destination_port()),
                        }).or_default().on_packet(ip_header, tcp_header, &buf[data_start_index..bytes_n]);
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
    Ok(())
}
