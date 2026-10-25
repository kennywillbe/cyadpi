use std::net::{Ipv4Addr, Ipv6Addr};

pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

pub const IPV4_HDR_LEN: usize = 20;
pub const IPV6_HDR_LEN: usize = 40;
pub const TCP_HDR_LEN: usize = 20;
const IPPROTO_TCP: u8 = 6;

#[derive(Debug, Clone, Copy)]
pub struct TcpSegment<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    pub payload: &'a [u8],
}

fn sum_words(data: &[u8], mut acc: u32) -> u32 {
    let (words, rest) = data.as_chunks::<2>();
    for word in words {
        acc = acc.wrapping_add(u32::from(u16::from_be_bytes(*word)));
    }
    if let [last] = rest {
        acc = acc.wrapping_add(u32::from(*last) << 8);
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    // Truncation is the point: the loop above already brought it under 16 bits.
    #[allow(clippy::cast_possible_truncation)]
    let v = acc as u16;
    !v
}

pub fn internet_checksum(data: &[u8]) -> u16 {
    fold(sum_words(data, 0))
}

fn tcp_len_u32(seg_len: usize) -> u32 {
    u32::try_from(seg_len).expect("tcp segment fits u32")
}

pub fn tcp_checksum_v4(src: Ipv4Addr, dst: Ipv4Addr, tcp: &[u8]) -> u16 {
    let mut acc = sum_words(&src.octets(), 0);
    acc = sum_words(&dst.octets(), acc);
    acc = acc.wrapping_add(u32::from(IPPROTO_TCP));
    acc = acc.wrapping_add(tcp_len_u32(tcp.len()));
    fold(sum_words(tcp, acc))
}

pub fn tcp_checksum_v6(src: Ipv6Addr, dst: Ipv6Addr, tcp: &[u8]) -> u16 {
    let mut acc = sum_words(&src.octets(), 0);
    acc = sum_words(&dst.octets(), acc);
    let len = tcp_len_u32(tcp.len());
    acc = acc.wrapping_add(len >> 16).wrapping_add(len & 0xffff);
    acc = acc.wrapping_add(u32::from(IPPROTO_TCP));
    fold(sum_words(tcp, acc))
}

fn write_tcp_header(out: &mut Vec<u8>, seg: &TcpSegment<'_>) {
    out.extend_from_slice(&seg.src_port.to_be_bytes());
    out.extend_from_slice(&seg.dst_port.to_be_bytes());
    out.extend_from_slice(&seg.seq.to_be_bytes());
    out.extend_from_slice(&seg.ack.to_be_bytes());
    // No options: the fake dies before the server, and the DPI box only reads
    // the payload.
    out.push(5 << 4);
    out.push(seg.flags);
    out.extend_from_slice(&seg.window.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
}

/// TCP header + payload with the checksum over the IPv6 pseudo header.
pub fn build_tcp_v6(src: Ipv6Addr, dst: Ipv6Addr, seg: &TcpSegment<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(TCP_HDR_LEN + seg.payload.len());
    write_tcp_header(&mut out, seg);
    out.extend_from_slice(seg.payload);
    let ck = tcp_checksum_v6(src, dst, &out);
    out[16..18].copy_from_slice(&ck.to_be_bytes());
    out
}

/// Full IPv6 packet. `head` is the first word of the connection's own header
/// (version, traffic class, flow label): routers hash the flow label to pick a
/// link, and the fake has to take the same one as the real packets.
pub fn build_ipv6(
    head: [u8; 4],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    hop_limit: u8,
    seg: &TcpSegment<'_>,
) -> Vec<u8> {
    let tcp = build_tcp_v6(src, dst, seg);
    let len = u16::try_from(tcp.len()).expect("segment fits in u16");
    let mut out = Vec::with_capacity(IPV6_HDR_LEN + tcp.len());
    out.extend_from_slice(&head);
    out.extend_from_slice(&len.to_be_bytes());
    out.push(IPPROTO_TCP);
    out.push(hop_limit);
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    out.extend_from_slice(&tcp);
    out
}

/// Full IPv4 packet, in on-wire byte order.
pub fn build_ipv4(src: Ipv4Addr, dst: Ipv4Addr, ttl: u8, id: u16, seg: &TcpSegment<'_>) -> Vec<u8> {
    let total = IPV4_HDR_LEN + TCP_HDR_LEN + seg.payload.len();
    let total16 = u16::try_from(total).expect("packet fits in u16");
    let mut out = Vec::with_capacity(total);
    out.push(0x45);
    out.push(0);
    out.extend_from_slice(&total16.to_be_bytes());
    out.extend_from_slice(&id.to_be_bytes());
    // No DF: the fake is small, and a DF bit would invite ICMP replies from
    // the router where it expires.
    out.extend_from_slice(&[0, 0]);
    out.push(ttl);
    out.push(IPPROTO_TCP);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    let ck = internet_checksum(&out[..IPV4_HDR_LEN]);
    out[10..12].copy_from_slice(&ck.to_be_bytes());

    write_tcp_header(&mut out, seg);
    out.extend_from_slice(seg.payload);
    let tck = tcp_checksum_v4(src, dst, &out[IPV4_HDR_LEN..]);
    out[IPV4_HDR_LEN + 16..IPV4_HDR_LEN + 18].copy_from_slice(&tck.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(char::is_ascii_hexdigit).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn ipv4_header_checksum_textbook() {
        // RFC 1071 style worked example (Wikipedia "IPv4 header checksum").
        let mut h = hex("4500 0073 0000 4000 4011 0000 c0a8 0001 c0a8 00c7");
        assert_eq!(internet_checksum(&h), 0xb861);
        h[10] = 0xb8;
        h[11] = 0x61;
        assert_eq!(internet_checksum(&h), 0);
    }

    fn sample_seg(payload: &[u8]) -> TcpSegment<'_> {
        TcpSegment {
            src_port: 51000,
            dst_port: 443,
            seq: 0x1122_3344,
            ack: 0x5566_7788,
            flags: TCP_PSH | TCP_ACK,
            window: 2048,
            payload,
        }
    }

    // Reference bytes produced independently with scapy 2.6:
    // IP(src="192.168.1.10",dst="93.184.216.34",ttl=5,id=0x1234,flags=0)/
    // TCP(sport=51000,dport=443,seq=0x11223344,ack=0x55667788,flags="PA",
    //     window=2048)/b"\x16\x03\x01hello"
    const V4_REF: &str = "45000030123400000506ac07c0a8010a5db8d822c738\
                          01bb112233445566778850180800eca7000016030168656c6c6f";

    #[test]
    fn ipv4_tcp_packet_matches_reference() {
        let p = build_ipv4(
            Ipv4Addr::new(192, 168, 1, 10),
            Ipv4Addr::new(93, 184, 216, 34),
            5,
            0x1234,
            &sample_seg(b"\x16\x03\x01hello"),
        );
        assert_eq!(p, hex(V4_REF));
    }

    // scapy: IPv6(src="2001:db8::1",dst="2606:4700::6810:84e5",hlim=5)/
    // TCP(sport=51000,dport=443,seq=0x11223344,ack=0x55667788,flags="PA",
    //     window=2048)/b"\x16\x03\x01hello"  -> TCP part only
    const V6_TCP_REF: &str = "c73801bb1122334455667788501808005c7f000016030168656c6c6f";

    #[test]
    fn ipv6_tcp_segment_matches_reference() {
        let t = build_tcp_v6(
            "2001:db8::1".parse().unwrap(),
            "2606:4700::6810:84e5".parse().unwrap(),
            &sample_seg(b"\x16\x03\x01hello"),
        );
        assert_eq!(t, hex(V6_TCP_REF));
    }

    #[test]
    fn ipv6_packet_wraps_the_segment() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2606:4700::6810:84e5".parse().unwrap();
        let p = build_ipv6(
            [0x60, 0x0b, 0x02, 0x00],
            src,
            dst,
            3,
            &sample_seg(b"\x16\x03\x01hello"),
        );
        assert_eq!(&p[..8], &[0x60, 0x0b, 0x02, 0x00, 0, 28, 6, 3]);
        assert_eq!(&p[8..24], &src.octets());
        assert_eq!(&p[24..40], &dst.octets());
        assert_eq!(&p[40..], &hex(V6_TCP_REF)[..]);
    }

    #[test]
    fn checksum_verifies_to_zero_odd_payload() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let t = build_tcp_v6(src, dst, &sample_seg(b"abc"));
        assert_eq!(tcp_checksum_v6(src, dst, &t), 0);
    }
}
