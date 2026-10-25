use std::fs;
use std::io;
use std::process::{Command, Stdio};

use crate::config;

const ANCHOR: &str = config::PF_ANCHOR;
pub const ANCHOR_FILE: &str = "/var/run/cyadpi.anchor";
const DNCTL: &str = "/usr/sbin/dnctl";

/// Two jobs, nothing is redirected:
///
/// The `dummynet` rule holds every SYN-ACK from port 80/443 for a moment on its
/// way into the TCP stack. bpf sees it on arrival, so the fake is out before
/// the app even learns it is connected (see `config::SYNACK_DELAY_MS`).
///
/// The `block return` rules refuse QUIC. DPI boxes tend to drop QUIC to
/// blocked names silently, and a fake cannot be slipped in front of it the way
/// it is for TCP. An immediate ICMP error makes the browser use TCP at once
/// instead of waiting on a dead handshake. Only user processes: VPN daemons on
/// UDP 443 run as root and must keep working. Local ranges are left alone.
pub fn ruleset() -> String {
    let pipe = config::DUMMYNET_PIPE;
    format!(
        "\
table <cyadpi_lnets> {{ 127.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 198.18.0.0/15, 224.0.0.0/4 }}
table <cyadpi_lnets6> {{ ::1, fc00::/7, fe80::/10, ff00::/8 }}

dummynet in quick proto tcp from any port {{ 80, 443 }} flags SA/SA pipe {pipe}

block return out quick inet proto udp from any to !<cyadpi_lnets> port 443 user {{ >root }}
block return out quick inet6 proto udp from any to !<cyadpi_lnets6> port 443 user {{ >root }}
"
    )
}

/// An enabled pf reference plus a loaded anchor. Dropping it (or a crash, via
/// the state file) releases both.
pub struct Pf {
    token: Option<String>,
}

impl Pf {
    pub fn enable() -> io::Result<Self> {
        let (_, err) = run(&["-E"])?;
        let token =
            parse_token(&err).ok_or_else(|| io::Error::other(format!("pfctl -E said: {err}")))?;
        // Owned before anything else can fail: an error below drops it, and
        // Drop gives the reference back. Otherwise every launchd retry of a
        // failing start would leak one more pf enable reference.
        let pf = Self { token: Some(token) };
        Self::ensure_main_ruleset()?;
        Ok(pf)
    }

    /// Our anchor is only reachable through the `com.apple/*` anchor point in
    /// `/etc/pf.conf`. If nothing is loaded at all, loading that file is safe.
    /// If someone else replaced the main ruleset (a VPN kill switch, say),
    /// reloading would silently drop their rules, so stop instead.
    fn ensure_main_ruleset() -> io::Result<()> {
        let (anchors, _) = run(&["-s", "Anchors"])?;
        if anchors.lines().any(|l| l.trim() == "com.apple") {
            return Ok(());
        }
        let (rules, _) = run(&["-s", "rules"])?;
        let (nat, _) = run(&["-s", "nat"])?;
        if anchors.trim().is_empty() && rules.trim().is_empty() && nat.trim().is_empty() {
            return run(&["-f", "/etc/pf.conf"]).map(drop);
        }
        Err(io::Error::other(
            "the pf main ruleset was replaced by another tool and has no com.apple anchor; not touching it",
        ))
    }

    pub fn load() -> io::Result<()> {
        // The pipe first: a dummynet rule pointing at a missing pipe drops
        // the packets it matches.
        let delay = config::SYNACK_DELAY_MS.to_string();
        dnctl(&[
            "pipe",
            &config::DUMMYNET_PIPE.to_string(),
            "config",
            "delay",
            &delay,
        ])?;
        fs::write(ANCHOR_FILE, ruleset())?;
        run(&["-a", ANCHOR, "-n", "-f", ANCHOR_FILE])?;
        run(&["-a", ANCHOR, "-f", ANCHOR_FILE])?;
        Ok(())
    }

    #[must_use]
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    /// Release a token left behind by an earlier run.
    pub fn release_token(token: &str) {
        let _ = run(&["-X", token]);
        let _ = Self::flush_anchor();
    }

    /// Rules before the pipe, for the same reason as in `load`.
    pub fn flush_anchor() -> io::Result<()> {
        run(&["-a", ANCHOR, "-F", "all"])?;
        let pipe = config::DUMMYNET_PIPE.to_string();
        // Fails when there is no such pipe, which is the state we want.
        let _ = dnctl(&["pipe", "delete", &pipe]);
        Ok(())
    }

    pub fn teardown(&self) {
        let _ = Self::flush_anchor();
        if let Some(token) = &self.token {
            let _ = run(&["-X", token]);
        }
        let _ = fs::remove_file(ANCHOR_FILE);
    }
}

impl Drop for Pf {
    fn drop(&mut self) {
        self.teardown();
    }
}

fn parse_token(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(|line| line.strip_prefix("Token : ").map(|t| t.trim().to_owned()))
}

fn dnctl(args: &[&str]) -> io::Result<()> {
    let out = Command::new(DNCTL)
        .arg("-q")
        .args(args)
        .stdin(Stdio::null())
        .output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "dnctl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

fn run(args: &[&str]) -> io::Result<(String, String)> {
    let out = Command::new("/sbin/pfctl")
        .args(args)
        .stdin(Stdio::null())
        .output()?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    if out.status.success() {
        Ok((stdout, stderr))
    } else {
        Err(io::Error::other(format!(
            "pfctl {} failed: {}",
            args.join(" "),
            stderr.trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_delays_synacks_and_refuses_quic() {
        let r = ruleset();
        assert!(r.contains(
            "dummynet in quick proto tcp from any port { 80, 443 } flags SA/SA pipe 7488"
        ));
        assert!(!r.contains("rdr"), "nothing is redirected any more");
        assert!(
            r.contains("block return out quick inet proto udp")
                && r.contains("block return out quick inet6 proto udp"),
            "QUIC must be refused"
        );
        assert!(r.contains("192.168.0.0/16"), "LAN must be excluded");
        assert!(r.contains("fe80::/10"), "link-local must be excluded");
        for line in r.lines().filter(|l| l.starts_with("block")) {
            assert!(
                line.ends_with("user { >root }"),
                "root VPNs keep UDP 443: {line}"
            );
        }
        // Every rule needs its terminating newline or pfctl sees a truncated file.
        assert!(r.ends_with('\n'));
    }

    #[test]
    fn token_parsing() {
        assert_eq!(
            parse_token("Token : 12345\npf enabled\n").as_deref(),
            Some("12345")
        );
        assert_eq!(parse_token("pf enabled\n"), None);
    }
}
