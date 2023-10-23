#[allow(dead_code)]
pub enum State {
    // Closed, 就是没有对应 TCB
    // Listen, 也是没有对应 TCB 但是有存储所有处于监听状态的 port
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

pub struct Connection {
    pub state: State,
    /// 存储最近一次send的数据的状态
    /// 主要是用来支持TCP的重传等机制
    pub send: SendSequenceSpace,
    /// 存储当前已接受的数据的状态
    pub recv: RecvSequenceSpace,
    pub tcp: etherparse::TcpHeader,
    pub ip: etherparse::Ipv4Header,
}

/// State of Send Sequence Space (RFC 793 S3.2 F4)
#[allow(dead_code)]
pub struct SendSequenceSpace {
    /// send unacknowledged
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    // /// send urgent pointer
    // up: bool,
    // /// segment sequence number used for last window update
    // wl1: u32,
    // /// segment acknowledgment number used for last window update
    // wl2: u32,
    /// initial send sequence number
    iss: u32,
}

/// State of Receive Sequence Space (RFC 793 S3.2 F5)
#[allow(dead_code)]
pub struct RecvSequenceSpace {
    /// initial receive sequence number
    /// 只在第一次建立连接时获取，之后不再更改
    irs: u32,
    /// receive next
    /// 表示下一个希望接收的seq
    nxt: u32,
    /// receive window
    wnd: u16,
    // /// receive urgent pointer
    // up: bool,
}

#[allow(dead_code)]
impl Connection {
    /// 接收到一个尝试连接的请求
    /// 具体需要进行的操作见
    /// rfc 793, page 65
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        seg: etherparse::TcpHeaderSlice<'a>,
        // _data: &'a [u8],
    ) -> std::io::Result<Option<Self>> {
        // first check for an RST
        if seg.rst() {
            // An incoming RST should be ignored.  Return.
            return Ok(None);
        }
        // second check for an ACK
        if seg.ack() {
            // Any acknowledgment is bad if it arrives on a connection still in
            // the LISTEN state.  An acceptable reset segment should be formed
            // for any arriving ACK-bearing segment.  The RST should be
            // formatted as follows:
            // <SEQ=SEG.ACK><CTL=RST>
            // Return.
            let mut tcp = etherparse::TcpHeader::new(
                seg.destination_port(),
                seg.source_port(),
                seg.acknowledgment_number(),
                1024,
            );
            tcp.rst = true;
            let ip = etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::IpTrafficClass::Tcp,
                iph.destination_addr().octets(),
                iph.source_addr().octets(),
            );
            super::util::response(nic, &tcp, &ip, &[])?;
            return Ok(None);
        }
        // third check for a SYN
        if seg.syn() {
            // TODO: If the SYN bit is set, check the security
            // <SEQ=ISS><ACK=RCV.NXT><CTL=SYN,ACK>
            // TODO: select a iss
            let iss = 0;
            let wnd = 1024;
            let mut c = Self {
                state: State::SynReceived,
                send: SendSequenceSpace {
                    una: iss,
                    nxt: iss,
                    wnd,
                    iss,
                },
                recv: RecvSequenceSpace {
                    // rfc 793, page 66, line 6
                    irs: seg.sequence_number(),
                    // rfc 793, page 66, line 6
                    nxt: seg.sequence_number().wrapping_add(1),
                    wnd: seg.window_size(),
                },
                tcp: etherparse::TcpHeader::new(
                    seg.destination_port(),
                    seg.source_port(),
                    iss,
                    wnd,
                ),
                ip: etherparse::Ipv4Header::new(
                    0,
                    64,
                    etherparse::IpTrafficClass::Tcp,
                    iph.destination_addr().octets(),
                    iph.source_addr().octets(),
                ),
            };
            // 接收到 SYN 需要用 SYN ACK 来响应
            c.tcp.syn = true;
            c.tcp.ack = true;
            c.write(nic, &[])?;
            c.send.nxt = iss + 1;
            // TODO: 应该还有一个补充默认socket的逻辑，所以创建 Connection 的逻辑也不应该在这里
            return Ok(Some(c));
        }
        // TODO: 剩下的应该进行 discard 或者交给 ack processing 处理？

        Ok(None)
    }
    fn write(&mut self, nic: &mut tun_tap::Iface, data: &[u8]) -> std::io::Result<usize> {
        let seq = self.send.nxt;
        self.tcp.sequence_number = seq;
        // 每次发送的响应的ack都是上一次接收到的请求的nxt
        self.tcp.acknowledgment_number = self.recv.nxt;
        // self.tcp
        //     .set_options(&[etherparse::TcpOptionElement::MaximumSegmentSize(u16::MAX)])
        //     .expect("TODO: panic message");
        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &[])
            .expect("unable to calc checksum");
        self.ip
            .set_payload_len(self.tcp.header_len() as usize + data.len())
            .expect("payload length is not too big");

        super::util::response(nic, &self.tcp, &self.ip, data)?;
        let mut len = data.len();
        if self.tcp.syn {
            len += 1;
        }
        if self.tcp.fin {
            len += 1;
        }
        Ok(len)
    }
    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        _iph: etherparse::Ipv4HeaderSlice<'a>,
        seg: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> std::io::Result<()> {
        // rfc 793, page 69
        // first check sequence number
        if let State::SynReceived | State::Established = self.state {
            if seg.window_size() == 0 {
                // If an incoming segment is not acceptable, an acknowledgment
                // should be sent in reply:
                // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                self.recv.nxt = seg.sequence_number().wrapping_add(1);
                super::util::response(nic, &self.tcp, &self.ip, data)?;
                return Ok(());
            }
        }

        // second check the RST bis
        if let State::SynReceived = self.state {
            if seg.rst() {
                // TODO: If the RST bit is set
            }
        }

        // TODO: third check security and precedence

        // TODO: fourth, check the SYN bit
        if seg.syn() {}

        // fifth check the ACK field
        if seg.ack() {
            // if the ACK bit is on
            if let State::SynReceived = self.state {
                // If SND.UNA =< SEG.ACK =< SND.NXT then enter ESTABLISHED state
                // and continue processing
                if is_between_wrapped(
                    self.send.una.wrapping_sub(1),
                    seg.acknowledgment_number(),
                    self.send.nxt.wrapping_add(1),
                ) {
                    self.state = State::Established;
                } else {
                    // If the segment acknowledgment is not acceptable, form a reset segment
                    // <SEQ=SEG.ACK><CTL=RST>
                }
            }
            if let State::Established = self.state {
                // If SND.UNA < SEG.ACK =< SND.NXT then, set SND.UNA <- SEG.ACK
                if is_between_wrapped(
                    self.send.una,
                    seg.acknowledgment_number(),
                    self.send.nxt.wrapping_add(1),
                ) {
                    self.send.una = seg.acknowledgment_number();
                    // TODO: update send window
                } else {
                    // TODO: handle SEG.ACK < SND.UNA and SEG.ACK > SND.NXT
                }
            }
        } else {
            // if the ACK bit is off drop the segment and return
            return Ok(());
        }

        // TODO: sixth, check the URG bit

        // seventh, process the segment text
        if let State::Established | State::FinWait1 | State::FinWait2 = self.state {
            // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
            self.recv.nxt = seg.sequence_number().wrapping_add(1);
            self.tcp = etherparse::TcpHeader::new(
                seg.destination_port(),
                seg.source_port(),
                self.send.nxt,
                self.send.wnd,
            );
            self.tcp.ack = true;
            self.send.nxt += self.write(nic, data)? as u32;
        }

        Ok(())
    }
}

/// 判断 lhs 是否在 rhs 的左边
fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // From RFC1323:
    //     TCP determines if a data segment is "old" or "new" by testing
    //     whether its sequence number is within 2**31 bytes of the left edge
    //     of the window, and if it is not, discarding the data as "old".  To
    //     insure that new data is never mistakenly considered old and vice-
    //     versa, the left edge of the sender's window has to be at most
    //     2**31 away from the right edge of the receiver's window.
    // wrapping_sub等说于如果 lhs < rhs，那么 lhs 会先加上 2^32+1 再计算
    lhs.wrapping_sub(rhs) > (1 << 31)
}

/// (start,end)
fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}

#[cfg(test)]
mod test {
    #[test]
    fn test_is_between_wrapped() {
        // ---------start---------------end-----------
        //            5                  10
        //        4
        assert!(!super::is_between_wrapped(5, 4, 10));
        // ---------start---------------end-----------
        //            5                  10
        //            5
        assert!(!super::is_between_wrapped(5, 5, 10));
        // ---------start---------------end-----------
        //            5                  10
        //                 6
        assert!(super::is_between_wrapped(5, 6, 10));
        // ---------start---------------end-----------
        //            5                  10
        //                             9
        assert!(super::is_between_wrapped(5, 9, 10));
        // ---------start---------------end-----------
        //            5                  10
        //                               10
        assert!(!super::is_between_wrapped(5, 10, 10));
        // ---------start---------------end-----------
        //            5                  10
        //                                  11
        assert!(!super::is_between_wrapped(5, 11, 10));
    }
}
