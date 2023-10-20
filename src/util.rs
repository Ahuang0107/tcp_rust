use std::io::Write;

pub fn response(
    nic: &mut tun_tap::Iface,
    tcp: &etherparse::TcpHeader,
    ip: &etherparse::Ipv4Header,
) -> std::io::Result<usize> {
    let mut buf = [0u8; 1500];
    let buf_len = buf.len();
    let mut unwritten = &mut buf[..];
    unwritten
        .write(&[0, 0, 8, 0])
        .expect("unable to write eth flags and proto");
    ip.write(&mut unwritten).expect("unable to write ip header");
    tcp.write(&mut unwritten)
        .expect("unable to write tcp header");
    let written_len = buf_len - unwritten.len();
    nic.send(&buf[..written_len])?;
    Ok(written_len)
}
