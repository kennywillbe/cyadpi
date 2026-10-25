mod config;
mod fake;
mod logfile;
mod packet;
mod pf;
mod service;
mod sniff;
mod state;
mod sys;

use std::io::{self, Write};

use logfile::log;
use state::{Lock, State};

const USAGE: &str = "\
usage:
  sudo cyadpi           turn on (background service, also starts at boot)
  sudo cyadpi off       turn off until the next boot
  cyadpi status         is it on, last log lines
  sudo cyadpi run       run in this terminal instead, Ctrl-C stops it
  sudo cyadpi restore   clean up pf after a crash (only when it is not running)
  sudo cyadpi uninstall turn off and remove everything, this binary included";

fn main() {
    sys::default_sigpipe();
    let arg = std::env::args().nth(1);
    let outcome = match arg.as_deref() {
        None => root("").and_then(|()| service::on()),
        Some("off") => root(" off").and_then(|()| service::off()),
        Some("status") => {
            service::status();
            Ok(())
        }
        Some("run") => root(" run").and_then(|()| foreground()),
        Some("restore") => root(" restore").and_then(|()| restore_command()),
        Some("uninstall") => root(" uninstall").and_then(|()| service::uninstall()),
        Some(_) => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    };
    if let Err(e) = outcome {
        // Not eprintln: under launchd a failed write must not turn into a panic.
        let _ = writeln!(io::stderr(), "cyadpi: {e}");
        std::process::exit(1);
    }
}

fn root(cmd: &str) -> io::Result<()> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "needs root. Run: sudo cyadpi{cmd}"
        )))
    }
}

/// What launchd runs, and what `sudo cyadpi run` runs in a terminal.
fn foreground() -> io::Result<()> {
    let lock = Lock::try_acquire()?;
    // Only the lock holder may rotate: a second instance rotating would move
    // the live service's log away under it.
    logfile::redirect_if_detached(lock.is_some())?;
    let Some(_lock) = lock else {
        return Err(io::Error::other(
            "already running (the service?). See: cyadpi status",
        ));
    };
    sys::install_signal_handlers()?;

    run()?;
    log!("stopped, system left as it was");
    Ok(())
}

fn restore_command() -> io::Result<()> {
    clean_slate()?;
    println!("cyadpi: pf rules removed, previous state restored");
    Ok(())
}

/// Removes whatever a dead instance left in pf. Shared by `restore` and the
/// service commands: a process killed without running Drop (SIGKILL, launchd's
/// exit timeout) leaves the SYN-ACK delay and the QUIC block loaded, and
/// `off` must not report success in that state.
fn clean_slate() -> io::Result<()> {
    // Under a live instance this would pull its pf rules away. `launchctl
    // bootout` can return while the process is still tearing down, so give
    // a stopping instance a few seconds to let go of the lock.
    let mut lock = Lock::try_acquire()?;
    for _ in 0..50 {
        if lock.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        lock = Lock::try_acquire()?;
    }
    let Some(_lock) = lock else {
        return Err(io::Error::other(
            "cyadpi is still running; stop it with: sudo cyadpi off",
        ));
    };
    restore_previous()?;
    // Also when no state file exists: rules can outlive it, and an empty
    // anchor costs nothing.
    pf::Pf::flush_anchor()
}

fn run() -> io::Result<()> {
    // A previous run that was killed leaves pf enabled with our reference;
    // undo that first so a crash never compounds.
    restore_previous()?;

    let pf = pf::Pf::enable()?;
    State {
        pf_token: pf.token().map(str::to_owned),
    }
    .save()?;
    let outcome = pf::Pf::load().map(|()| {
        log!("active");
        watch_routes();
    });
    drop(pf);
    State::remove();
    outcome
}

/// Keeps a reader on every interface a default route points at, until a
/// signal asks us to stop.
fn watch_routes() {
    let mut failing = std::collections::HashSet::new();
    while !sys::stop_requested() {
        for probe in config::route_probes() {
            let Ok(source) = sys::source_towards(probe) else {
                continue;
            };
            let Ok(Some(ifname)) = sys::interface_with(source) else {
                continue;
            };
            match sniff::watch(&ifname) {
                Ok(()) => {
                    failing.remove(&ifname);
                }
                // Once per failure, not once a second.
                Err(e) => {
                    if failing.insert(ifname.clone()) {
                        log!("cannot watch {ifname}: {e}");
                    }
                }
            }
        }
        std::thread::sleep(config::WATCH_EVERY);
    }
}

fn restore_previous() -> io::Result<()> {
    let Some(state) = State::load()? else {
        return Ok(());
    };
    if let Some(token) = &state.pf_token {
        pf::Pf::release_token(token);
    }
    State::remove();
    Ok(())
}
