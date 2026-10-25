use std::fs;
use std::io;
use std::os::fd::AsRawFd;

use crate::config;

/// What a killed run leaves behind and the next start (or `cyadpi restore`)
/// has to undo: the pf enable reference. Without it pf would stay enabled with
/// our reference held forever.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct State {
    pub pf_token: Option<String>,
}

impl State {
    pub fn save(&self) -> io::Result<()> {
        let path = config::state_file();
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, self.encode())?;
        // rename is atomic, so a crash mid-save never leaves a torn file.
        fs::rename(&tmp, path)
    }

    pub fn load() -> io::Result<Option<Self>> {
        match fs::read_to_string(config::state_file()) {
            Ok(text) => Ok(Some(Self::decode(&text))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn remove() {
        let _ = fs::remove_file(config::state_file());
    }

    fn encode(&self) -> String {
        match &self.pf_token {
            Some(token) => format!("pf\t{token}\n"),
            None => String::new(),
        }
    }

    // Unknown lines are skipped, so a later version can add fields and an
    // older state file still recovers the token.
    fn decode(text: &str) -> Self {
        let pf_token = text
            .lines()
            .find_map(|line| line.strip_prefix("pf\t"))
            .map(|t| t.trim().to_owned())
            .filter(|t| !t.is_empty());
        Self { pf_token }
    }
}

pub const LOCK_FILE: &str = "/var/run/cyadpi.lock";

/// Held for the whole life of a running instance. A second instance would start
/// by "recovering" the first one's state file and pull its pf rules away.
pub struct Lock {
    _file: fs::File,
}

impl Lock {
    /// `None` when another cyadpi already holds it.
    pub fn try_acquire() -> io::Result<Option<Self>> {
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(LOCK_FILE)?;
        // SAFETY: flock on a descriptor we own; the kernel drops the lock when
        // the process dies, so a crash never leaves it stuck.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(Some(Self { _file: file }));
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            Ok(None)
        } else {
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let s = State {
            pf_token: Some("12345".into()),
        };
        assert_eq!(State::decode(&s.encode()), s);
        assert_eq!(State::decode(&State::default().encode()), State::default());
    }

    #[test]
    fn unknown_lines_are_skipped() {
        assert_eq!(
            State::decode("x\ty\npf\t987\n").pf_token.as_deref(),
            Some("987")
        );
        assert_eq!(State::decode("x\ty\n").pf_token, None);
    }
}
