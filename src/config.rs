use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

// The fake has to die after the DPI box and before the server. DPI boxes sit
// a hop or two out, but CDN nodes inside an ISP can be as close as four or
// five hops, and a fake that reaches the server breaks the connection.
// GoodbyeDPI's usual 5 is too many for those; 3 leaves room on both sides.
pub const FAKE_TTL: u8 = 3;

/// How long the TCP stack sees a SYN-ACK after the bpf reader does. The app
/// can only send its first request once its stack has the SYN-ACK, so this is
/// the head start of our fake. Browsers write their `ClientHello` within
/// ~0.1 ms of `connect()` returning, so without it the race is lost now and
/// then; the fake itself goes out ~0.1 ms after the SYN-ACK arrives.
pub const SYNACK_DELAY_MS: u32 = 2;

/// dummynet pipe for that delay. Any number nobody else uses.
pub const DUMMYNET_PIPE: u32 = 7488;

pub const PF_ANCHOR: &str = "com.apple/cyadpi";
pub const STATE_FILE: &str = "/var/run/cyadpi.state";

/// Routes are looked up towards these to find the interfaces to watch. Nothing
/// is sent to them.
pub const ROUTE_PROBES: [&str; 2] = ["1.1.1.1:443", "[2606:4700:4700::1111]:443"];

/// The default route moves between Wi-Fi, Ethernet and VPNs, and a reader
/// dies with its interface, so the watch list is refreshed this often.
pub const WATCH_EVERY: Duration = Duration::from_secs(1);

pub fn state_file() -> &'static Path {
    Path::new(STATE_FILE)
}

pub fn route_probes() -> impl Iterator<Item = SocketAddr> {
    ROUTE_PROBES
        .iter()
        .map(|p| p.parse().expect("probe addresses are literals"))
}
