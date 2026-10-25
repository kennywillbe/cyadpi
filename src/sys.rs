use std::ffi::CStr;
use std::io;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};

const IOCPARM_MASK: libc::c_ulong = 0x1fff;
#[cfg(test)]
const IOC_VOID: libc::c_ulong = 0x2000_0000;
const IOC_OUT: libc::c_ulong = 0x4000_0000;
const IOC_IN: libc::c_ulong = 0x8000_0000;

const fn ioc(inout: libc::c_ulong, group: u8, num: u8, len: usize) -> libc::c_ulong {
    inout
        | (((len as libc::c_ulong) & IOCPARM_MASK) << 16)
        | ((group as libc::c_ulong) << 8)
        | num as libc::c_ulong
}
#[cfg(test)]
pub const fn io(group: u8, num: u8) -> libc::c_ulong {
    ioc(IOC_VOID, group, num, 0)
}
pub const fn ior(group: u8, num: u8, len: usize) -> libc::c_ulong {
    ioc(IOC_OUT, group, num, len)
}
pub const fn iow(group: u8, num: u8, len: usize) -> libc::c_ulong {
    ioc(IOC_IN, group, num, len)
}
pub const fn iowr(group: u8, num: u8, len: usize) -> libc::c_ulong {
    ioc(IOC_IN | IOC_OUT, group, num, len)
}

// net/bpf.h is not in the macOS SDK any more, so the few structs and numbers we
// use are declared here. `cargo test` checks the ioctl numbers against the SDK
// values printed by a C compiler.

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[repr(C)]
pub struct BpfProgram {
    pub len: u32,
    pub insns: *mut BpfInsn,
}

pub const BIOCGBLEN: libc::c_ulong = ior(b'B', 102, 4);
pub const BIOCSBLEN: libc::c_ulong = iowr(b'B', 102, 4);
pub const BIOCSETF: libc::c_ulong = iow(b'B', 103, size_of::<BpfProgram>());
pub const BIOCGDLT: libc::c_ulong = ior(b'B', 106, 4);
pub const BIOCSETIF: libc::c_ulong = iow(b'B', 108, size_of::<libc::ifreq>());
pub const BIOCSRTIMEOUT: libc::c_ulong = iow(b'B', 109, size_of::<libc::timeval>());
pub const BIOCIMMEDIATE: libc::c_ulong = iow(b'B', 112, 4);
pub const BIOCSHDRCMPLT: libc::c_ulong = iow(b'B', 117, 4);
pub const BIOCSSEESENT: libc::c_ulong = iow(b'B', 119, 4);

pub const DLT_NULL: u32 = 0;
pub const DLT_EN10MB: u32 = 1;
pub const DLT_RAW: u32 = 12;
pub const DLT_LOOP: u32 = 108;

pub fn ifreq(name: &str) -> io::Result<libc::ifreq> {
    let bytes = name.as_bytes();
    if bytes.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }
    // SAFETY: ifreq is plain old data and an all-zero value is valid.
    let mut req: libc::ifreq = unsafe { zeroed() };
    for (slot, byte) in req.ifr_name.iter_mut().zip(bytes) {
        // IFNAMSIZ is 16 and the bytes are ASCII; the wide cast cannot trap.
        #[allow(clippy::cast_possible_wrap)]
        {
            *slot = *byte as libc::c_char;
        }
    }
    Ok(req)
}

/// # Safety
/// `arg` must point to a value of the size encoded in `request`.
pub unsafe fn ioctl_ptr(
    fd: RawFd,
    request: libc::c_ulong,
    arg: *mut libc::c_void,
) -> io::Result<()> {
    // SAFETY: the caller promises arg matches the request's size.
    cvt(unsafe { libc::ioctl(fd, request, arg) }).map(drop)
}

/// # Safety
/// `sa` must point to a readable sockaddr of at least its declared family's size.
unsafe fn from_sockaddr(sa: *const libc::sockaddr) -> Option<IpAddr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: caller guarantees sa is readable; family is the first common field.
    let family = i32::from(unsafe { (*sa).sa_family });
    match family {
        libc::AF_INET => {
            // SAFETY: family says this is a sockaddr_in.
            let sin = unsafe { &*sa.cast::<libc::sockaddr_in>() };
            Some(IpAddr::V4(Ipv4Addr::from(
                sin.sin_addr.s_addr.to_ne_bytes(),
            )))
        }
        libc::AF_INET6 => {
            // SAFETY: family says this is a sockaddr_in6.
            let sin6 = unsafe { &*sa.cast::<libc::sockaddr_in6>() };
            Some(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

pub fn cvt(rc: libc::c_int) -> io::Result<libc::c_int> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

/// The source address the kernel would pick towards `dst`. A connected UDP
/// socket asks the routing table without sending anything.
pub fn source_towards(dst: SocketAddr) -> io::Result<IpAddr> {
    let bind: SocketAddr = match dst {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let s = UdpSocket::bind(bind)?;
    s.connect(dst)?;
    Ok(s.local_addr()?.ip())
}

/// Name of the interface that holds `ip`, so BPF can watch the right one.
pub fn interface_with(ip: IpAddr) -> io::Result<Option<String>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills head with a list we free below.
    cvt(unsafe { libc::getifaddrs(&raw mut head) })?;
    let mut found = None;
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: cur walks the list getifaddrs returned and is non-null here.
        let ifa = unsafe { &*cur };
        // SAFETY: ifa_addr is either null or a valid sockaddr owned by the list.
        if let Some(sa) = unsafe { from_sockaddr(ifa.ifa_addr) }
            && sa == ip
        {
            // SAFETY: ifa_name is a NUL-terminated string owned by the list.
            found = Some(
                unsafe { CStr::from_ptr(ifa.ifa_name) }
                    .to_string_lossy()
                    .into_owned(),
            );
            break;
        }
        cur = ifa.ifa_next;
    }
    // SAFETY: head came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(head) };
    Ok(found)
}

pub fn if_index(name: &str) -> u32 {
    let Ok(c) = std::ffi::CString::new(name) else {
        return 0;
    };
    // SAFETY: c is a valid NUL-terminated string.
    unsafe { libc::if_nametoindex(c.as_ptr()) }
}

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: libc::c_int) {
    // Only async-signal-safe work: one atomic store.
    STOP_REQUESTED.store(true, Ordering::SeqCst);
}

/// SIGINT/SIGTERM/SIGHUP flip the stop flag, which every loop checks at least
/// every 250 ms. SIGPIPE is ignored: `sudo cyadpi run | tee` losing its
/// reader must not kill us before pf is cleaned up.
pub fn install_signal_handlers() -> io::Result<()> {
    unblock(&[libc::SIGINT, libc::SIGTERM, libc::SIGHUP])?;
    let handler = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    set_handler(libc::SIGINT, handler)?;
    set_handler(libc::SIGTERM, handler)?;
    set_handler(libc::SIGHUP, handler)?;
    set_handler(libc::SIGPIPE, libc::SIG_IGN)
}

/// A launcher that starts us with these signals blocked would make Ctrl-C a
/// no-op; a daemon must own its own mask.
fn unblock(signals: &[libc::c_int]) -> io::Result<()> {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    for &sig in signals {
        // SAFETY: set is a live sigset_t and sig is a valid signal number.
        if unsafe { libc::sigaddset(&raw mut set, sig) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: set lists only valid signals.
    if unsafe { libc::sigprocmask(libc::SIG_UNBLOCK, &raw const set, std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_handler(sig: libc::c_int, handler: libc::sighandler_t) -> io::Result<()> {
    // sa_flags stays 0: no SA_RESTART, so a blocking call wakes us immediately.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = handler;
    // SAFETY: action is a fully initialised sigaction for a valid signal number.
    if unsafe { libc::sigaction(sig, &raw const action, std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Rust starts every program with SIGPIPE ignored, which turns
/// `cyadpi status | head -1` into a panic on the next print. A CLI should just
/// end there; the daemon ignores it again in `install_signal_handlers`.
pub fn default_sigpipe() {
    // SAFETY: resetting a signal to its default disposition has no preconditions.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
}

pub fn stop_requested() -> bool {
    STOP_REQUESTED.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_encoding_matches_sdk() {
        // Values printed from the macOS 27 SDK headers with a C program.
        assert_eq!(iowr(b'B', 102, 4), 0xc004_4266); // BIOCSBLEN
        assert_eq!(iow(b'B', 103, 16), 0x8010_4267); // BIOCSETF
        assert_eq!(iow(b'B', 108, 32), 0x8020_426c); // BIOCSETIF
        assert_eq!(ior(b'B', 106, 4), 0x4004_426a); // BIOCGDLT
        assert_eq!(io(b'B', 104), 0x2000_4268); // BIOCFLUSH
        assert_eq!(BIOCSBLEN, 0xc004_4266);
        assert_eq!(BIOCSETF, 0x8010_4267);
        assert_eq!(BIOCSETIF, 0x8020_426c);
        assert_eq!(BIOCGDLT, 0x4004_426a);
        assert_eq!(BIOCIMMEDIATE, 0x8004_4270); // _IOW, not _IOWR
        assert_eq!(BIOCSSEESENT, 0x8004_4277);
        assert_eq!(size_of::<BpfInsn>(), 8);
        assert_eq!(size_of::<BpfProgram>(), 16);
    }

    #[test]
    fn ifreq_carries_the_name() {
        let req = ifreq("en0").unwrap();
        assert_eq!(req.ifr_name[0], b'e'.cast_signed());
        assert_eq!(req.ifr_name[2], b'0'.cast_signed());
        assert_eq!(req.ifr_name[3], 0);
        assert!(ifreq("a-very-long-interface-name").is_err());
    }

    #[test]
    fn interface_lookup_finds_loopback() {
        assert_eq!(
            interface_with("127.0.0.1".parse().unwrap())
                .unwrap()
                .as_deref(),
            Some("lo0")
        );
        assert_eq!(interface_with("192.0.2.1".parse().unwrap()).unwrap(), None);
        assert_ne!(if_index("lo0"), 0);
    }
}
