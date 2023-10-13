fn main() -> std::io::Result<()> {
    println!("try to crate a TUN device");
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun).expect("Failed to create a TUN device");
    let mut buf = [0u8; 1504];
    println!("try to read bytes from {}", nic.name());
    let bytes_n = nic.recv(&mut buf[..])?;
    println!("read {} bytes: {:x?}", bytes_n, &buf[..bytes_n]);
    Ok(())
}
