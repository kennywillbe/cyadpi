use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::config;
use crate::fake;
use crate::logfile::log;
use crate::packet::{self, TCP_ACK, TCP_PSH, TcpSegment};
use crate::sys;

// The whole trick lives here. A bpf reader on each outgoing interface sees
// the handshake of every web connection: from our SYN it keeps the link
// header, the first word of the IP header and the window, and when the
// server's SYN-ACK comes in it writes one fake request with the sequence
// numbers the app's first segment will carry, straight to the interface. The
// app's connection itself is never touched. The in-kernel filter passes only
// SYN and SYN-ACK segments to or from port 80/443.

/// What our own SYN tells about the connection, kept until the SYN-ACK.
struct Entry {
    /// Link header as sent (our MAC, the gateway's): reused verbatim.
    link: Vec<u8>,
    /// First word of the IP header. For IPv6 it holds the flow label, which
    /// routers hash to pick a link; the fake has to take the same link as the
    /// real packets or the DPI box on it never sees the fake.
    head: [u8; 4],
    window: u16,
    seen: Instant,
}

/// Everything the fake for one connection is built from.
#[derive(Debug)]
struct Handshake {
    link: Vec<u8>,
    head: [u8; 4],
    window: u16,
    ours: SocketAddr,
    server: SocketAddr,
    /// The sequence number our first data segment will carry.
    seq: u32,
    /// The server's ISN + 1.
    ack: u32,
}

/// (our address, server address).
type Key = (SocketAddr, SocketAddr);

fn table() -> &'static Mutex<HashMap<Key, Entry>> {
    static TABLE: OnceLock<Mutex<HashMap<Key, Entry>>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Interface name -> `if_index` of the interface the reader is attached to. A
/// VPN `utun` or a USB Ethernet comes back under the same name but a new
/// index, and the old descriptor is bound to the interface that went away.
fn watched() -> &'static Mutex<HashMap<String, u32>> {
    static WATCHED: OnceLock<Mutex<HashMap<String, u32>>> = OnceLock::new();
    WATCHED.get_or_init(|| Mutex::new(HashMap::new()))
}

fn lock<T>(m: &'static Mutex<T>) -> std::sync::MutexGuard<'static, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Attach a reader to `ifname` unless one is already running.
pub fn watch(ifname: &str) -> io::Result<()> {
    let index = sys::if_index(ifname);
    let mut guard = lock(watched());
    if guard.get(ifname) == Some(&index) {
        return Ok(());
    }
    let fd = open_bpf()?;
    let raw = fd.as_raw_fd();
    configure(raw, ifname)?;
    let dlt = dlt_of(raw)?;
    let buflen = buflen_of(raw)?;
    let mut insns = program(dlt);
    set_filter(raw, &mut insns)?;
    set_int(raw, sys::BIOCIMMEDIATE, 1)?;
    // Locally generated packets must be visible or outgoing SYNs are lost.
    set_int(raw, sys::BIOCSSEESENT, 1)?;
    // The fake carries the source MAC copied from the connection's SYN.
    set_int(raw, sys::BIOCSHDRCMPLT, 1)?;
    set_timeout(raw, Duration::from_millis(250))?;

    let name = ifname.to_owned();
    std::thread::Builder::new()
        .name(format!("bpf:{name}"))
        .stack_size(64 * 1024)
        .spawn(move || {
            reader(&fd, dlt, buflen);
            // Forget this reader so the next round attaches a fresh one; a
            // newer reader for a re-created interface owns the entry now.
            let mut guard = lock(watched());
            if guard.get(&name) == Some(&index) {
                guard.remove(&name);
            }
        })
        .map_err(|e| io::Error::other(format!("cannot start bpf reader: {e}")))?;
    guard.insert(ifname.to_owned(), index);
    Ok(())
}

// Bounds on what traffic we do not control can make us do. A flood of SYNs
// (or SYNs whose SYN-ACK never comes) must not grow the table forever.
const MAX_ENTRIES: usize = 4096;
const PRUNE_EVERY: Duration = Duration::from_secs(1);
const ENTRY_TTL: Duration = Duration::from_secs(20);

fn prune(map: &mut HashMap<Key, Entry>, now: Instant) {
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    let mut last = LAST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if last.is_some_and(|t| now.duration_since(t) < PRUNE_EVERY) && map.len() < MAX_ENTRIES {
        return;
    }
    *last = Some(now);
    map.retain(|_, e| now.duration_since(e.seen) < ENTRY_TTL);
}

fn open_bpf() -> io::Result<OwnedFd> {
    let mut last = io::Error::other("no /dev/bpf device available");
    for i in 0..256 {
        let path = CString::new(format!("/dev/bpf{i}")).expect("path has no NUL");
        // SAFETY: we own the returned descriptor and wrap it immediately.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
        if fd >= 0 {
            // SAFETY: fd was just returned by open(2) and is not owned elsewhere.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        last = io::Error::last_os_error();
        if last.raw_os_error() != Some(libc::EBUSY) {
            break;
        }
    }
    Err(last)
}

fn configure(fd: libc::c_int, ifname: &str) -> io::Result<()> {
    // The buffer must be sized before the interface is attached.
    let mut blen: libc::c_uint = 1 << 20;
    // SAFETY: &blen is a live c_uint.
    unsafe { sys::ioctl_ptr(fd, sys::BIOCSBLEN, (&raw mut blen).cast()) }?;
    let mut req = sys::ifreq(ifname)?;
    // SAFETY: req is a live ifreq whose ifr_name names an interface.
    unsafe { sys::ioctl_ptr(fd, sys::BIOCSETIF, (&raw mut req).cast()) }
}

fn dlt_of(fd: libc::c_int) -> io::Result<u32> {
    let mut dlt: libc::c_uint = 0;
    // SAFETY: &dlt is a live c_uint.
    unsafe { sys::ioctl_ptr(fd, sys::BIOCGDLT, (&raw mut dlt).cast()) }?;
    Ok(dlt)
}

fn buflen_of(fd: libc::c_int) -> io::Result<usize> {
    let mut len: libc::c_uint = 0;
    // SAFETY: &len is a live c_uint.
    unsafe { sys::ioctl_ptr(fd, sys::BIOCGBLEN, (&raw mut len).cast()) }?;
    usize::try_from(len).map_err(|_| io::Error::other("bpf buffer too large"))
}

fn set_filter(fd: libc::c_int, insns: &mut [sys::BpfInsn]) -> io::Result<()> {
    let mut prog = sys::BpfProgram {
        len: u32::try_from(insns.len()).expect("bpf program fits u32"),
        insns: insns.as_mut_ptr(),
    };
    // SAFETY: prog points at the live insns slice and has its exact length.
    unsafe { sys::ioctl_ptr(fd, sys::BIOCSETF, (&raw mut prog).cast()) }
}

fn set_int(fd: libc::c_int, request: libc::c_ulong, value: libc::c_uint) -> io::Result<()> {
    let mut value = value;
    // SAFETY: &value is a live c_uint, matching the request's size.
    unsafe { sys::ioctl_ptr(fd, request, (&raw mut value).cast()) }
}

fn set_timeout(fd: libc::c_int, timeout: Duration) -> io::Result<()> {
    let mut tv = libc::timeval {
        tv_sec: i64::try_from(timeout.as_secs()).unwrap_or(i64::MAX),
        tv_usec: libc::suseconds_t::try_from(timeout.subsec_micros()).unwrap_or(0),
    };
    // SAFETY: &tv is a live timeval.
    unsafe { sys::ioctl_ptr(fd, sys::BIOCSRTIMEOUT, (&raw mut tv).cast()) }
}

fn reader(fd: &OwnedFd, dlt: u32, buflen: usize) {
    let mut buf = vec![0u8; buflen];
    let raw = fd.as_raw_fd();
    while !sys::stop_requested() {
        let mut pfd = libc::pollfd {
            fd: raw,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live pollfd; the timeout lets the stop flag be noticed.
        let rc = unsafe { libc::poll(&raw mut pfd, 1, 250) };
        if rc < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if rc == 0 {
            continue;
        }
        if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            break;
        }
        // SAFETY: buf is writable for buf.len() bytes and the fd is a readable bpf device.
        let n = unsafe { libc::read(raw, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        #[allow(clippy::cast_sign_loss)]
        parse_frames(&buf[..n as usize], dlt, Some(raw));
    }
}

fn parse_frames(buf: &[u8], dlt: u32, out: Option<RawFd>) {
    let mut off = 0usize;
    while off + 18 <= buf.len() {
        let Some((start, end)) = record(buf, off, dlt) else {
            break;
        };
        handle_frame(&buf[start..end], dlt, out);
        off = (end + 3) & !3;
    }
}

/// Locate one record. The kernel writes either an 18-byte header (32-bit
/// `timeval`, what macOS 27 returns) or the 32-byte `timeval` form, so the
/// layout is taken from whichever candidate produces a frame that matches the
/// link type instead of trusting a compile-time offset.
fn record(buf: &[u8], off: usize, dlt: u32) -> Option<(usize, usize)> {
    // (offset of caplen, offset of hdrlen)
    const LAYOUTS: [(usize, usize); 2] = [(8, 16), (16, 24)];
    for (cap_at, hdr_at) in LAYOUTS {
        let Some(cap) = buf.get(off + cap_at..off + cap_at + 4) else {
            continue;
        };
        let Some(len) = buf.get(off + hdr_at..off + hdr_at + 2) else {
            continue;
        };
        let caplen = usize::try_from(u32::from_ne_bytes(cap.try_into().ok()?)).ok()?;
        let datalen = usize::try_from(u32::from_ne_bytes(
            buf.get(off + cap_at + 4..off + cap_at + 8)?
                .try_into()
                .ok()?,
        ))
        .ok()?;
        let hdrlen = usize::from(u16::from_ne_bytes(len.try_into().ok()?));
        if caplen == 0 || caplen > datalen || !(18..=64).contains(&hdrlen) {
            continue;
        }
        let start = off + hdrlen;
        let end = start.checked_add(caplen)?;
        if end <= buf.len() && frame_matches(&buf[start..end], dlt) {
            return Some((start, end));
        }
    }
    None
}

fn frame_matches(frame: &[u8], dlt: u32) -> bool {
    match dlt {
        sys::DLT_EN10MB => {
            frame.len() >= 14
                && matches!(
                    u16::from_be_bytes([frame[12], frame[13]]),
                    0x0800 | 0x86dd | 0x0806 | 0x8035 | 0x8100
                )
        }
        sys::DLT_NULL => frame
            .first_chunk::<4>()
            .is_some_and(|b| matches!(u32::from_ne_bytes(*b), 2 | 30)),
        sys::DLT_LOOP => frame
            .first_chunk::<4>()
            .is_some_and(|b| matches!(u32::from_be_bytes(*b), 2 | 30)),
        sys::DLT_RAW => frame.first().is_some_and(|b| b >> 4 == 4 || b >> 4 == 6),
        _ => false,
    }
}

fn handle_frame(frame: &[u8], dlt: u32, out: Option<RawFd>) {
    let (offset, v4) = match dlt {
        sys::DLT_EN10MB => {
            let Some(t) = frame.get(12..14) else {
                return;
            };
            match u16::from_be_bytes([t[0], t[1]]) {
                0x0800 => (14, true),
                0x86dd => (14, false),
                _ => return,
            }
        }
        sys::DLT_NULL | sys::DLT_LOOP => {
            let Some(b) = frame.first_chunk::<4>() else {
                return;
            };
            let family = if dlt == sys::DLT_NULL {
                u32::from_ne_bytes(*b)
            } else {
                u32::from_be_bytes(*b)
            };
            match family {
                2 => (4, true),
                30 => (4, false),
                _ => return,
            }
        }
        sys::DLT_RAW => (0, frame.first().is_some_and(|b| b >> 4 == 4)),
        _ => return,
    };
    let hs = if v4 {
        parse_v4(frame, offset)
    } else {
        parse_v6(frame, offset)
    };
    // Only Ethernet-like links take a hand-built frame. On a VPN tunnel the
    // web traffic is inside the tunnel and the DPI sees none of it anyway.
    if let (Some(hs), Some(fd), sys::DLT_EN10MB) = (hs, out, dlt)
        && let Err(e) = write_frame(fd, &fake_frame(&hs))
    {
        log_send_failure(hs.server, &e);
    }
}

/// The fake request for one connection: `GoodbyeDPI`'s decoy with the sequence
/// numbers of the app's first segment and a TTL that runs out after the DPI
/// box, framed exactly like the connection's own packets.
fn fake_frame(hs: &Handshake) -> Vec<u8> {
    let payload = if hs.server.port() == 80 {
        fake::FAKE_HTTP
    } else {
        &fake::FAKE_HTTPS[..]
    };
    let seg = TcpSegment {
        src_port: hs.ours.port(),
        dst_port: hs.server.port(),
        seq: hs.seq,
        ack: hs.ack,
        flags: TCP_PSH | TCP_ACK,
        window: hs.window,
        payload,
    };
    let ip = match (hs.ours.ip(), hs.server.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            // Any id will do for a packet that is never fragmented.
            let id = hs.seq.to_be_bytes();
            packet::build_ipv4(
                s,
                d,
                config::FAKE_TTL,
                u16::from_be_bytes([id[2], id[3]]),
                &seg,
            )
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => packet::build_ipv6(hs.head, s, d, config::FAKE_TTL, &seg),
        _ => unreachable!("a TCP connection has one address family"),
    };
    let mut frame = Vec::with_capacity(hs.link.len() + ip.len());
    frame.extend_from_slice(&hs.link);
    frame.extend_from_slice(&ip);
    frame
}

/// Written to the bpf device, so it leaves through the interface the
/// connection uses.
fn write_frame(fd: RawFd, frame: &[u8]) -> io::Result<()> {
    // SAFETY: frame is a live buffer of frame.len() bytes.
    let n = unsafe { libc::write(fd, frame.as_ptr().cast(), frame.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// One line per minute at most: a broken interface would otherwise log once
/// per connection.
fn log_send_failure(server: SocketAddr, e: &io::Error) {
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    let mut last = LAST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if last.is_none_or(|t| t.elapsed() >= Duration::from_secs(60)) {
        *last = Some(Instant::now());
        log!("{server}: fake not sent: {e}");
    }
}

/// A server zero hops away (the router's admin page, a NAS, a VM, Tailscale)
/// would receive a TTL-3 fake as real data. There is no DPI in between anyway.
fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || (a == 100 && (64..128).contains(&b))
                || (a == 198 && (18..20).contains(&b))
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                || first & 0xfe00 == 0xfc00
                || first & 0xffc0 == 0xfe80
        }
    }
}

/// Link header and first IP word of a frame.
struct Origin<'a> {
    link: &'a [u8],
    head: [u8; 4],
}

/// Our SYN to a web port starts an entry; the SYN-ACK back completes it and
/// hands out the handshake to fake. Anything else is ignored.
fn record_tcp(src: IpAddr, dst: IpAddr, seg: &TcpFields, origin: &Origin<'_>) -> Option<Handshake> {
    let syn = seg.flags & 0x02 != 0;
    let ack_set = seg.flags & 0x10 != 0;
    let web = |port| port == 80 || port == 443;
    if !syn || (ack_set && !web(seg.src_port)) || (!ack_set && !web(seg.dst_port)) {
        return None;
    }
    let from = SocketAddr::new(src, seg.src_port);
    let to = SocketAddr::new(dst, seg.dst_port);
    // A SYN-ACK travels server -> us, so the key is the other way round.
    let key = if ack_set { (to, from) } else { (from, to) };
    if is_local(key.1.ip()) {
        return None;
    }
    let now = Instant::now();
    let mut map = lock(table());
    prune(&mut map, now);
    if ack_set {
        // Only a connection whose SYN we saw has a link header to reuse; one
        // that started before we were watching goes without.
        let entry = map.remove(&key)?;
        return Some(Handshake {
            link: entry.link,
            head: entry.head,
            window: entry.window,
            ours: key.0,
            server: key.1,
            seq: seg.ack,
            ack: seg.seq.wrapping_add(1),
        });
    }
    if map.len() < MAX_ENTRIES || map.contains_key(&key) {
        map.insert(
            key,
            Entry {
                link: origin.link.to_vec(),
                head: origin.head,
                window: seg.window,
                seen: now,
            },
        );
    }
    None
}

fn origin(frame: &[u8], base: usize) -> Origin<'_> {
    Origin {
        link: &frame[..base],
        head: [
            frame[base],
            frame[base + 1],
            frame[base + 2],
            frame[base + 3],
        ],
    }
}

fn parse_v4(frame: &[u8], base: usize) -> Option<Handshake> {
    if frame.len() < base + 20 || frame[base] >> 4 != 4 || frame[base + 9] != 6 {
        return None;
    }
    let ihl = usize::from(frame[base] & 0x0f) * 4;
    let tcp = base + ihl;
    if ihl < 20 || frame.len() < tcp + 20 {
        return None;
    }
    let ip = |at: usize| {
        IpAddr::from([
            frame[base + at],
            frame[base + at + 1],
            frame[base + at + 2],
            frame[base + at + 3],
        ])
    };
    let seg = TcpFields::parse(&frame[tcp..]);
    record_tcp(ip(12), ip(16), &seg, &origin(frame, base))
}

fn parse_v6(frame: &[u8], base: usize) -> Option<Handshake> {
    if frame.len() < base + 40 || frame[base] >> 4 != 6 || frame[base + 6] != 6 {
        return None;
    }
    let tcp = base + packet::IPV6_HDR_LEN;
    if frame.len() < tcp + 20 {
        return None;
    }
    let ip = |at: usize| {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&frame[base + at..base + at + 16]);
        IpAddr::from(octets)
    };
    let seg = TcpFields::parse(&frame[tcp..]);
    record_tcp(ip(8), ip(24), &seg, &origin(frame, base))
}

struct TcpFields {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
}

impl TcpFields {
    fn parse(b: &[u8]) -> Self {
        Self {
            src_port: u16::from_be_bytes([b[0], b[1]]),
            dst_port: u16::from_be_bytes([b[2], b[3]]),
            seq: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            ack: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
            flags: b[13],
            window: u16::from_be_bytes([b[14], b[15]]),
        }
    }
}

// ---- in-kernel filter ----

const LD: u16 = 0x00;
const LDX: u16 = 0x01;
const ALU: u16 = 0x04;
const JMP: u16 = 0x05;
const RET: u16 = 0x06;
const MISC: u16 = 0x07;
const W: u16 = 0x00;
const H: u16 = 0x08;
const B: u16 = 0x10;
const IMM: u16 = 0x00;
const ABS: u16 = 0x20;
const IND: u16 = 0x40;
const ADD: u16 = 0x00;
const AND: u16 = 0x50;
const LSH: u16 = 0x60;
const JEQ: u16 = 0x10;
const K: u16 = 0x00;
const TAX: u16 = 0x07;

enum Node {
    Insn { code: u16, k: u32 },
    Jump { k: u32, label: &'static str },
    Label(&'static str),
}

struct Asm {
    nodes: Vec<Node>,
}

impl Asm {
    fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    fn insn(&mut self, code: u16, k: u32) {
        self.nodes.push(Node::Insn { code, k });
    }

    fn jeq(&mut self, k: u32, label: &'static str) {
        self.nodes.push(Node::Jump { k, label });
    }

    fn label(&mut self, name: &'static str) {
        self.nodes.push(Node::Label(name));
    }

    fn ret(&mut self, k: u32) {
        self.insn(RET, k);
    }

    fn finish(self) -> Vec<sys::BpfInsn> {
        let mut insns = Vec::with_capacity(self.nodes.len());
        let mut labels: Vec<(&'static str, usize)> = Vec::new();
        for node in &self.nodes {
            match node {
                Node::Label(name) => labels.push((name, insns.len())),
                Node::Insn { code, k } => insns.push(sys::BpfInsn {
                    code: *code,
                    jt: 0,
                    jf: 0,
                    k: *k,
                }),
                Node::Jump { .. } => insns.push(sys::BpfInsn {
                    code: JMP | JEQ | K,
                    jt: 0,
                    jf: 0,
                    k: 0,
                }),
            }
        }
        let mut idx = 0;
        for node in &self.nodes {
            if let Node::Jump { k, label } = node {
                let target = labels
                    .iter()
                    .find(|(name, _)| name == label)
                    .map(|(_, at)| *at)
                    .expect("filter jumps target an existing label");
                let offset = target - (idx + 1);
                assert!(offset < 256, "bpf jump out of range");
                insns[idx].jt = u8::try_from(offset).expect("offset fits u8");
                insns[idx].k = *k;
                idx += 1;
            } else if matches!(node, Node::Insn { .. }) {
                idx += 1;
            }
        }
        insns
    }
}

fn accept_ports(asm: &mut Asm) {
    asm.insn(LD | H | IND, 0);
    asm.jeq(80, "syn");
    asm.jeq(443, "syn");
    asm.insn(LD | H | IND, 2);
    asm.jeq(80, "syn");
    asm.jeq(443, "syn");
    asm.ret(0);
}

fn program(dlt: u32) -> Vec<sys::BpfInsn> {
    let mut asm = Asm::new();
    let base4 = match dlt {
        sys::DLT_EN10MB => {
            asm.insn(LD | H | ABS, 12);
            asm.jeq(0x0800, "v4");
            asm.jeq(0x86dd, "v6");
            asm.ret(0);
            14
        }
        sys::DLT_NULL | sys::DLT_LOOP => {
            asm.insn(LD | W | ABS, 0);
            if dlt == sys::DLT_NULL {
                // bpf compares the word big-endian; DLT_NULL stores it in host order.
                asm.jeq(u32::from_be_bytes(2u32.to_ne_bytes()), "v4");
                asm.jeq(u32::from_be_bytes(30u32.to_ne_bytes()), "v6");
            } else {
                asm.jeq(2, "v4");
                asm.jeq(30, "v6");
            }
            asm.ret(0);
            4
        }
        _ => {
            asm.insn(LD | B | ABS, 0);
            asm.insn(ALU | AND | K, 0xf0);
            asm.jeq(0x40, "v4");
            asm.jeq(0x60, "v6");
            asm.ret(0);
            0
        }
    };

    asm.label("v4");
    asm.insn(LD | B | ABS, base4 + 9);
    asm.jeq(6, "tcp4");
    asm.ret(0);
    asm.label("tcp4");
    asm.insn(LD | B | ABS, base4);
    asm.insn(ALU | AND | K, 0x0f);
    asm.insn(ALU | LSH | K, 2);
    asm.insn(ALU | ADD | K, base4);
    asm.insn(MISC | TAX, 0);
    accept_ports(&mut asm);

    asm.label("v6");
    asm.insn(LD | B | ABS, base4 + 6);
    asm.jeq(6, "tcp6");
    asm.ret(0);
    asm.label("tcp6");
    asm.insn(LDX | IMM, base4 + 40);
    accept_ports(&mut asm);

    // Only handshake packets are useful, and copying whole streams would swamp
    // the buffer on a busy machine.
    asm.label("syn");
    asm.insn(LD | B | IND, 13);
    asm.insn(ALU | AND | K, 0x02);
    asm.jeq(0, "drop");
    asm.ret(u32::from(u16::MAX));
    asm.label("drop");
    asm.ret(0);
    asm.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests share the global table; serialise them.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        lock(table()).clear();
        guard
    }

    const OUR_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
    const GW_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0xfe];
    const ME: [u8; 4] = [192, 168, 1, 20];
    const SERVER: [u8; 4] = [203, 0, 113, 7];

    /// Ethernet + IPv4 + bare TCP header, from `src` to `dst`.
    fn v4_frame(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
    ) -> Vec<u8> {
        let (from_mac, to_mac) = if src == ME {
            (OUR_MAC, GW_MAC)
        } else {
            (GW_MAC, OUR_MAC)
        };
        let mut f = Vec::new();
        f.extend_from_slice(&to_mac);
        f.extend_from_slice(&from_mac);
        f.extend_from_slice(&[0x08, 0x00]);
        let mut ip = [0u8; 20];
        ip[0] = 0x45;
        ip[8] = 64;
        ip[9] = 6;
        ip[12..16].copy_from_slice(&src);
        ip[16..20].copy_from_slice(&dst);
        f.extend_from_slice(&ip);
        let mut tcp = [0u8; 20];
        tcp[0..2].copy_from_slice(&sport.to_be_bytes());
        tcp[2..4].copy_from_slice(&dport.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        f.extend_from_slice(&tcp);
        f
    }

    fn our_syn(server: [u8; 4], port: u16) -> Vec<u8> {
        v4_frame(ME, server, 51000, port, 0x1111_2222, 0, 0x02)
    }

    fn their_synack(server: [u8; 4], port: u16) -> Vec<u8> {
        v4_frame(server, ME, port, 51000, 0xaaaa_cccc, 0x1111_2223, 0x12)
    }

    #[test]
    fn synack_after_our_syn_hands_out_the_first_segment_numbers() {
        let _guard = serial();
        assert!(parse_v4(&our_syn(SERVER, 443), 14).is_none());
        let hs = parse_v4(&their_synack(SERVER, 443), 14).expect("handshake complete");
        assert_eq!(hs.seq, 0x1111_2223, "our ISN + 1");
        assert_eq!(hs.ack, 0xaaaa_cccd, "their ISN + 1");
        assert_eq!(hs.window, 65535);
        assert_eq!(hs.ours, "192.168.1.20:51000".parse().unwrap());
        assert_eq!(hs.server, "203.0.113.7:443".parse().unwrap());
        assert_eq!(&hs.link[..6], &GW_MAC, "to the gateway, as our SYN went");
        assert_eq!(&hs.link[6..12], &OUR_MAC);
        // A retransmitted SYN-ACK must not send a second fake.
        assert!(parse_v4(&their_synack(SERVER, 443), 14).is_none());
    }

    #[test]
    fn connections_we_did_not_see_start_get_nothing() {
        let _guard = serial();
        assert!(parse_v4(&their_synack(SERVER, 443), 14).is_none());
        // Same server, other port of ours: not this connection.
        parse_v4(&our_syn(SERVER, 443), 14);
        let other = v4_frame(SERVER, ME, 443, 51001, 1, 2, 0x12);
        assert!(parse_v4(&other, 14).is_none());
    }

    #[test]
    fn local_and_non_web_peers_are_left_alone() {
        let _guard = serial();
        parse_v4(&our_syn([192, 168, 1, 1], 443), 14);
        parse_v4(&our_syn([100, 100, 1, 1], 443), 14);
        parse_v4(&our_syn(SERVER, 22), 14);
        // Someone connecting to a web server on this machine.
        parse_v4(&v4_frame(SERVER, ME, 40000, 443, 1, 0, 0x02), 14);
        assert!(lock(table()).is_empty());
        assert!(is_local("fd00::1".parse().unwrap()));
        assert!(is_local("fe80::1".parse().unwrap()));
        assert!(!is_local("2606:4700::1".parse().unwrap()));
        assert!(!is_local("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn v4_fake_is_a_valid_low_ttl_copy_of_the_first_segment() {
        let _guard = serial();
        parse_v4(&our_syn(SERVER, 443), 14);
        let hs = parse_v4(&their_synack(SERVER, 443), 14).unwrap();
        let frame = fake_frame(&hs);
        assert_eq!(&frame[..14], &hs.link[..]);
        let ip = &frame[14..34];
        assert_eq!(ip[8], config::FAKE_TTL);
        assert_eq!(packet::internet_checksum(ip), 0, "header checksum holds");
        assert_eq!(
            usize::from(u16::from_be_bytes([ip[2], ip[3]])),
            frame.len() - 14,
            "on-wire byte order"
        );
        let tcp = &frame[34..];
        assert_eq!(&tcp[4..8], &0x1111_2223u32.to_be_bytes());
        assert_eq!(&tcp[8..12], &0xaaaa_cccdu32.to_be_bytes());
        assert_eq!(&tcp[20..], &fake::FAKE_HTTPS[..]);
        assert_eq!(packet::tcp_checksum_v4(ME.into(), SERVER.into(), tcp), 0);

        parse_v4(&our_syn(SERVER, 80), 14);
        let http = parse_v4(&their_synack(SERVER, 80), 14).unwrap();
        assert!(fake_frame(&http).ends_with(fake::FAKE_HTTP));
    }

    #[test]
    fn v6_fake_keeps_the_flow_label_of_the_connection() {
        let _guard = serial();
        let me: std::net::Ipv6Addr = "2001:db8::20".parse().unwrap();
        let server: std::net::Ipv6Addr = "2001:db8:1::7".parse().unwrap();
        let frame = |src: std::net::Ipv6Addr,
                     dst: std::net::Ipv6Addr,
                     sport,
                     dport,
                     seq: u32,
                     ack: u32,
                     flags| {
            let mut f = Vec::new();
            f.extend_from_slice(&GW_MAC);
            f.extend_from_slice(&OUR_MAC);
            f.extend_from_slice(&[0x86, 0xdd]);
            f.extend_from_slice(&[0x60, 0x0b, 0x02, 0x00, 0, 20, 6, 64]);
            f.extend_from_slice(&src.octets());
            f.extend_from_slice(&dst.octets());
            let mut tcp = [0u8; 20];
            tcp[0..2].copy_from_slice(&u16::to_be_bytes(sport));
            tcp[2..4].copy_from_slice(&u16::to_be_bytes(dport));
            tcp[4..8].copy_from_slice(&seq.to_be_bytes());
            tcp[8..12].copy_from_slice(&ack.to_be_bytes());
            tcp[12] = 5 << 4;
            tcp[13] = flags;
            f.extend_from_slice(&tcp);
            f
        };
        parse_v6(&frame(me, server, 52000, 443, 7, 0, 0x02), 14);
        let hs = parse_v6(&frame(server, me, 443, 52000, 100, 8, 0x12), 14).unwrap();
        let out = fake_frame(&hs);
        let ip = &out[14..54];
        assert_eq!(
            &ip[..4],
            &[0x60, 0x0b, 0x02, 0x00],
            "flow label 0xb0200 kept"
        );
        assert_eq!(ip[6], 6);
        assert_eq!(ip[7], config::FAKE_TTL);
        assert_eq!(
            usize::from(u16::from_be_bytes([ip[4], ip[5]])),
            out.len() - 54
        );
        assert_eq!(packet::tcp_checksum_v6(me, server, &out[54..]), 0);
    }

    #[test]
    fn bpf_record_header_layouts_are_detected() {
        let mut frame = [0u8; 60];
        frame[12] = 0x08;
        frame[13] = 0x00;

        // 18-byte header: 32-bit timeval, the layout macOS returns.
        let mut short = vec![0u8; 18];
        short[8..12].copy_from_slice(&60u32.to_ne_bytes());
        short[12..16].copy_from_slice(&60u32.to_ne_bytes());
        short[16..18].copy_from_slice(&18u16.to_ne_bytes());
        short.extend_from_slice(&frame);
        assert_eq!(record(&short, 0, sys::DLT_EN10MB), Some((18, 78)));

        // 32-byte header: 64-bit timeval.
        let mut long = vec![0u8; 32];
        long[16..20].copy_from_slice(&60u32.to_ne_bytes());
        long[20..24].copy_from_slice(&60u32.to_ne_bytes());
        long[24..26].copy_from_slice(&32u16.to_ne_bytes());
        long.extend_from_slice(&frame);
        assert_eq!(record(&long, 0, sys::DLT_EN10MB), Some((32, 92)));

        // Nonsense must not be mistaken for a record.
        assert_eq!(record(&[0u8; 40], 0, sys::DLT_EN10MB), None);
    }

    #[test]
    fn filter_has_forward_jumps_only() {
        for dlt in [sys::DLT_EN10MB, sys::DLT_NULL, sys::DLT_LOOP, sys::DLT_RAW] {
            let insns = program(dlt);
            assert!(insns.len() < 40, "program should stay small");
            for (i, insn) in insns.iter().enumerate() {
                if insn.code == JMP | JEQ | K {
                    assert!(insn.jt >= 1, "jumps must move forward");
                    assert!(i + 1 + usize::from(insn.jt) < insns.len());
                }
            }
            // The program ends in the non-SYN drop and still accepts handshakes.
            assert_eq!(insns.last().unwrap().code, RET | K);
            assert_eq!(insns.last().unwrap().k, 0);
            assert!(insns.iter().any(|i| i.code == RET | K && i.k == 0xffff));
        }
    }

    #[test]
    fn truncated_frames_are_rejected_not_indexed() {
        for dlt in [sys::DLT_NULL, sys::DLT_LOOP, sys::DLT_EN10MB, sys::DLT_RAW] {
            for len in 0..4 {
                assert!(!frame_matches(&[2u8; 3][..len.min(3)], dlt));
                handle_frame(&[2u8; 3][..len.min(3)], dlt, None);
            }
        }
    }
}
