use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::logfile;

pub const LABEL: &str = "com.kennywillbe.cyadpi";
const PLIST: &str = "/Library/LaunchDaemons/com.kennywillbe.cyadpi.plist";
const LAUNCHCTL: &str = "/bin/launchctl";

/// launchd job: start at boot, come back 10 s after a crash. `off` only
/// boots the job out, the file stays, so the next boot starts it again.
#[must_use]
pub fn plist(exe: &Path) -> String {
    let exe = xml_escape(&exe.to_string_lossy());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{exe}</string>
		<string>run</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>10</integer>
</dict>
</plist>
"#
    )
}

/// The job runs this file as root at every boot. If the user (or anything
/// running as the user) could replace it, or rename a directory above it, that
/// is a root shell for them: a `cargo build` output under the home folder is
/// exactly that. Returns the first path that is not root-only.
fn writable_by_others(exe: &Path) -> io::Result<Option<std::path::PathBuf>> {
    for path in exe.ancestors() {
        let meta = fs::metadata(path)?;
        if !owned_by_root_only(meta.uid(), meta.mode()) {
            return Ok(Some(path.to_path_buf()));
        }
    }
    Ok(None)
}

fn owned_by_root_only(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & 0o022 == 0
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn on() -> io::Result<()> {
    let exe = std::env::current_exe()?.canonicalize()?;
    if let Some(weak) = writable_by_others(&exe)? {
        return Err(io::Error::other(format!(
            "refusing to install a root service from {}: {} can be changed by \
             a non-root user. Install it first:\n  sudo install -m 755 {} /usr/local/bin/cyadpi && sudo cyadpi",
            exe.display(),
            weak.display(),
            exe.display()
        )));
    }
    let text = plist(&exe);
    if fs::read_to_string(PLIST).ok().as_deref() != Some(text.as_str()) {
        fs::write(PLIST, &text)?;
        // launchd refuses a daemon plist that group or others can write.
        fs::set_permissions(PLIST, fs::Permissions::from_mode(0o644))?;
    }

    if let Some(job) = Job::query() {
        println!(
            "cyadpi: already on ({}). Restart with: sudo cyadpi off && sudo cyadpi",
            job.describe()
        );
        return Ok(());
    }
    // A job switched off with `launchctl disable` by hand would refuse to load.
    launchctl(&["enable", &target()])?;
    launchctl(&["bootstrap", "system", PLIST])?;

    // bootstrap returns before the process has set pf up; give it a moment so
    // a broken start is reported here and not discovered in the browser.
    std::thread::sleep(Duration::from_secs(2));
    match Job::query() {
        Some(job) if job.running() => {
            println!("cyadpi: on ({}), starts at every boot", job.describe());
            println!("cyadpi: stop with: sudo cyadpi off");
            Ok(())
        }
        _ => {
            eprintln!("cyadpi: the service did not stay up; last log lines:");
            print_log_tail(10);
            // Left loaded, launchd would retry every 10 s forever and the next
            // `sudo cyadpi` would claim it is already on.
            let _ = launchctl(&["bootout", &target()]);
            let _ = crate::clean_slate();
            Err(io::Error::other("service failed to start; it is off now"))
        }
    }
}

pub fn off() -> io::Result<()> {
    if Job::query().is_none() {
        println!("cyadpi: already off");
        return Ok(());
    }
    // bootout sends SIGTERM and waits for the exit. Normally the process has
    // torn pf down itself; if it died without that, clean up here.
    launchctl(&["bootout", &target()])?;
    crate::clean_slate()?;
    println!("cyadpi: off until the next boot (or: sudo cyadpi)");
    Ok(())
}

/// Everything `cyadpi` puts on the disk outside its own binary.
fn leftovers() -> Vec<String> {
    let mut paths = vec![PLIST.to_owned(), logfile::PATH.to_owned()];
    paths.extend((1..=logfile::KEEP).map(|n| format!("{}.{n}", logfile::PATH)));
    paths.extend(
        [
            crate::config::STATE_FILE,
            crate::state::LOCK_FILE,
            crate::pf::ANCHOR_FILE,
        ]
        .map(str::to_owned),
    );
    paths
}

/// Off, then gone: the launchd job, its plist, the logs and this binary. The
/// network is left exactly as it was before the first `sudo cyadpi`.
pub fn uninstall() -> io::Result<()> {
    if Job::query().is_some() {
        launchctl(&["bootout", &target()])?;
    }
    crate::clean_slate()?;
    for path in leftovers() {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(io::Error::other(format!("cannot remove {path}: {e}"))),
        }
    }
    let exe = std::env::current_exe()?;
    fs::remove_file(&exe)?;
    println!(
        "cyadpi: removed (service, pf rules, logs and {})",
        exe.display()
    );
    Ok(())
}

pub fn status() {
    match Job::query() {
        Some(job) => println!("cyadpi: on ({})", job.describe()),
        None => println!("cyadpi: off"),
    }
    println!("--- {}", logfile::PATH);
    print_log_tail(10);
}

fn print_log_tail(lines: usize) {
    match fs::read_to_string(logfile::PATH) {
        Ok(text) => {
            let all: Vec<&str> = text.lines().collect();
            for line in &all[all.len().saturating_sub(lines)..] {
                println!("{line}");
            }
        }
        Err(e) => println!("(no log: {e})"),
    }
}

fn target() -> String {
    format!("system/{LABEL}")
}

#[derive(Debug, PartialEq, Eq)]
struct Job {
    state: String,
    pid: Option<u32>,
}

impl Job {
    /// None when launchd does not have the job loaded at all.
    fn query() -> Option<Self> {
        let out = Command::new(LAUNCHCTL)
            .args(["print", &target()])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| Self::parse(&String::from_utf8_lossy(&out.stdout)))
    }

    // Only the job's own fields sit at one tab of indent; nested sections
    // (sockets, endpoints) repeat `state =` deeper down.
    fn parse(text: &str) -> Self {
        let field = |name: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix('\t')?.strip_prefix(name))
                .map(str::trim)
        };
        Self {
            state: field("state = ").unwrap_or("unknown").to_owned(),
            pid: field("pid = ").and_then(|p| p.parse().ok()),
        }
    }

    fn running(&self) -> bool {
        self.state == "running" && self.pid.is_some()
    }

    fn describe(&self) -> String {
        match self.pid {
            Some(pid) => format!("{}, pid {pid}", self.state),
            None => self.state.clone(),
        }
    }
}

fn launchctl(args: &[&str]) -> io::Result<()> {
    let out = Command::new(LAUNCHCTL)
        .args(args)
        .stdin(Stdio::null())
        .output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "launchctl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_runs_the_binary_in_the_foreground_mode() {
        let p = plist(Path::new("/usr/local/bin/cyadpi"));
        assert!(p.contains("<string>com.kennywillbe.cyadpi</string>"));
        assert!(p.contains("<string>/usr/local/bin/cyadpi</string>\n\t\t<string>run</string>"));
        assert!(p.contains("<key>RunAtLoad</key>\n\t<true/>"));
        assert!(p.contains("<key>KeepAlive</key>\n\t<true/>"));
        assert!(p.contains("<integer>10</integer>"));
        assert!(plist(Path::new("/a&b")).contains("/a&amp;b"));
    }

    #[test]
    fn only_root_owned_unwritable_paths_are_trusted() {
        assert!(owned_by_root_only(0, 0o100_755));
        assert!(!owned_by_root_only(501, 0o100_755), "user-owned binary");
        assert!(!owned_by_root_only(0, 0o040_775), "group-writable dir");
        assert!(!owned_by_root_only(0, 0o040_777), "world-writable dir");
        // The repo's own build output sits under the user's home folder.
        let me = std::env::current_exe().unwrap();
        assert!(writable_by_others(&me).unwrap().is_some());
    }

    #[test]
    fn uninstall_knows_every_file_we_write() {
        let paths = leftovers();
        for want in [
            PLIST,
            "/var/log/cyadpi.log",
            "/var/log/cyadpi.log.1",
            "/var/log/cyadpi.log.2",
            "/var/run/cyadpi.state",
            "/var/run/cyadpi.lock",
            "/var/run/cyadpi.anchor",
        ] {
            assert!(
                paths.iter().any(|p| p == want),
                "{want} would be left behind"
            );
        }
    }

    #[test]
    fn job_fields_come_from_the_top_level_only() {
        let text = "system/com.kennywillbe.cyadpi = {\n\
                    \tactive count = 1\n\
                    \tstate = running\n\
                    \tpid = 4242\n\
                    \tendpoints = {\n\
                    \t\t\"x\" = {\n\
                    \t\t\tstate = active\n";
        let job = Job::parse(text);
        assert_eq!(
            job,
            Job {
                state: "running".into(),
                pid: Some(4242)
            }
        );
        assert!(job.running());

        let stopped = Job::parse("x = {\n\tstate = not running\n");
        assert_eq!(stopped.pid, None);
        assert!(!stopped.running());
    }
}
