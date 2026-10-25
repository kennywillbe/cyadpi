use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::sys;

pub const PATH: &str = "/var/log/cyadpi.log";

/// The daemon's only way to write a line. `eprintln!` panics when stderr
/// cannot be written (a full disk under launchd, a dead tty under `run`), and
/// a panic in the wrong place takes a reader down and the fakes stop. A lost
/// log line is the better failure.
macro_rules! log {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(
            std::io::stderr().lock(),
            "{} cyadpi: {}",
            $crate::logfile::timestamp(),
            format_args!($($arg)*)
        );
    }};
}
pub(crate) use log;

/// Local time as `2024-05-01 13:45:02`. Hand-rolled to avoid a date crate for
/// one log prefix.
#[must_use]
pub fn timestamp() -> String {
    // SAFETY: time(NULL) has no preconditions; localtime_r writes into the
    // zeroed tm we own.
    let tm = unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&raw const now, &raw mut tm);
        tm
    };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}
const MAX_BYTES: u64 = 1 << 20;
pub const KEEP: usize = 2;
const CHECK_EVERY: Duration = Duration::from_secs(60);

/// Under launchd stdout/stderr are /dev/null, so the service writes its own
/// log. It also rotates it itself: launchd's `StandardErrorPath` keeps one
/// descriptor open forever, so newsyslog renaming the file would leave us
/// writing into the old one. In a terminal nothing changes.
pub fn redirect_if_detached(rotate: bool) -> io::Result<()> {
    // SAFETY: isatty only inspects the descriptor.
    if unsafe { libc::isatty(libc::STDERR_FILENO) } == 1 {
        return Ok(());
    }
    if rotate {
        rotate_if_big(Path::new(PATH))?;
    }
    point_stdio_at(&open(Path::new(PATH))?)?;
    if !rotate {
        return Ok(());
    }
    std::thread::Builder::new()
        .name("logrotate".into())
        .stack_size(64 * 1024)
        .spawn(|| {
            while !sys::stop_requested() {
                std::thread::sleep(CHECK_EVERY);
                match rotate_if_big(Path::new(PATH)) {
                    Ok(true) => {
                        if let Ok(f) = open(Path::new(PATH)) {
                            let _ = point_stdio_at(&f);
                        }
                    }
                    Ok(false) => {}
                    Err(e) => log!("log rotation failed: {e}"),
                }
            }
        })?;
    Ok(())
}

fn open(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn point_stdio_at(file: &File) -> io::Result<()> {
    for fd in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: both descriptors are valid; dup2 replaces fd atomically, so
        // a concurrent eprintln writes to either the old or the new file.
        sys::cvt(unsafe { libc::dup2(file.as_raw_fd(), fd) })?;
    }
    Ok(())
}

/// `cyadpi.log` -> `.1` -> `.2`, oldest dropped. Returns whether it rotated.
fn rotate_if_big(path: &Path) -> io::Result<bool> {
    match fs::metadata(path) {
        Ok(m) if m.len() > MAX_BYTES => {}
        Ok(_) => return Ok(false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    }
    for n in (1..KEEP).rev() {
        let from = numbered(path, n);
        if from.exists() {
            fs::rename(&from, numbered(path, n + 1))?;
        }
    }
    fs::rename(path, numbered(path, 1))?;
    Ok(true)
}

fn numbered(path: &Path, n: usize) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_keeps_two_old_files() {
        let dir = std::env::temp_dir().join(format!("cyadpi-log-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let log = dir.join("cyadpi.log");

        fs::write(&log, b"small").unwrap();
        assert!(!rotate_if_big(&log).unwrap(), "under the limit stays put");

        let big = vec![b'x'; usize::try_from(MAX_BYTES).unwrap() + 1];
        for round in 1..=3u8 {
            let mut data = big.clone();
            data.push(round);
            fs::write(&log, &data).unwrap();
            assert!(rotate_if_big(&log).unwrap());
        }
        assert!(!log.exists());
        assert_eq!(fs::read(numbered(&log, 1)).unwrap().last(), Some(&3));
        assert_eq!(fs::read(numbered(&log, 2)).unwrap().last(), Some(&2));
        assert!(!numbered(&log, 3).exists(), "round 1 was dropped");

        fs::remove_dir_all(&dir).unwrap();
    }
}
