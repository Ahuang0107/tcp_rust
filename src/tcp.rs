use std::io::Write;

#[allow(dead_code)]
pub enum State {
    SynRcvd,
    Estab,
}

pub struct Connection {
    pub state: State,
    /// 存储最近一次send的数据的状态
    /// 主要是用来支持TCP的重传等机制
    pub send: SendSequenceSpace,
    /// 存储当前已接受的数据的状态
    pub recv: RecvSequenceSpace,
    // pub ip: etherparse::Ipv4Header,
}

/// State of Send Sequence Space (RFC 793 S3.2 F4)
///
/// ```
///      1         2          3          4
/// ----------|----------|----------|----------
///        SND.UNA    SND.NXT    SND.UNA
///                             +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
/// ```
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
///
/// ```
///      1          2          3
///  ----------|----------|----------
///         RCV.NXT    RCV.NXT
///                   +RCV.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
/// ```
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
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        _data: &'a [u8],
    ) -> std::io::Result<Option<Self>> {
        if !tcph.syn() {
            // only expected SYN packet
            return Ok(None);
        }

        // 接收到 SYN，需要初始化一个 seq
        let iss = 0;
        let wnd = 1024;
        let c = Self {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                una: iss,
                nxt: iss,
                wnd,
                iss,
            },
            recv: RecvSequenceSpace {
                irs: tcph.sequence_number(),
                nxt: tcph.sequence_number() + 1,
                wnd: tcph.window_size(),
            },
        };
        let mut syn_ack = etherparse::TcpHeader::new(
            tcph.destination_port(),
            tcph.source_port(),
            iss,
            wnd,
        );
        // 接收到的 SYN 会有一个 seq，响应时需要将 ack 置为 seq+1
        syn_ack.acknowledgment_number = c.recv.nxt;
        // 接收到 SYN 需要用 SYN ACK 来响应
        syn_ack.syn = true;
        syn_ack.ack = true;
        let ip = etherparse::Ipv4Header::new(
            syn_ack.header_len(),
            64,
            etherparse::IpTrafficClass::Tcp,
            iph.destination_addr().octets(),
            iph.source_addr().octets(),
        );
        // prepare a buf to write package data we need to response
        let mut buf = [0u8; 1500];
        let mut buf_writer = &mut buf[..];
        buf_writer.write(&[0, 0, 8, 0]).expect("");
        ip.write(&mut buf_writer).expect("");
        syn_ack.write(&mut buf_writer).expect("");
        let unwritten_len = buf_writer.len();
        let written_len = buf.len() - unwritten_len;
        nic.send(&buf[..written_len])?;
        Ok(Some(c))
    }
    pub fn on_packet<'a>(
        &mut self,
        _iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        _data: &'a [u8],
    ) -> std::io::Result<()> {
        // first, check that sequence numbers are valid (RFC 793 S3.3)
        let ackn = tcph.acknowledgment_number();
        if self.send.una < ackn {
            if ackn <= self.send.nxt {
                // not wrapping
                // 正常情况，seq 没有套圈
            } else if self.send.nxt < self.send.una {
                // 正常情况，nxt已经套圈了
            } else {
                // 非正常情况
                unimplemented!()
            }
        } else {
            if ackn <= self.send.nxt && self.send.nxt < self.send.una {
                // 正常情况，nxt已经套圈了，ackn也已经绕回去了
            } else {
                // 非正常情况
                unimplemented!()
            }
        }
        match self.state {
            State::SynRcvd => {
                // expect to get an ACK for our SYN
                unimplemented!()
            }
            State::Estab => {
                unimplemented!()
            }
        }
    }
}