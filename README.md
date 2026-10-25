# cyadpi

Gets a Mac past DPI boxes that block websites by reading the server name in
the first packet of a connection. One binary, runs as a launchd service, no
configuration.

```
sudo cyadpi          # on, and on again after every reboot
sudo cyadpi off      # off until the next reboot
cyadpi status
```

## How it works

When a TLS (or plain HTTP) connection starts, cyadpi sends one fake request
ahead of the real one: same addresses, same sequence numbers, but with an IP
TTL of 3. The DPI box sees the fake first, decides the connection is going to
`www.w3.org`, and lets it through. The fake runs out of hops before it reaches
the server, so the server only ever gets the real request. This is the trick
[GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) uses on Windows, and the
fake packets are byte for byte its own.

Nothing sits in the middle of your connections. A bpf reader watches the TCP
handshakes on the active interface, and when a server's SYN-ACK arrives it
writes the fake straight to the interface. pf holds each SYN-ACK back from the
TCP stack for 2 ms, so the app cannot send its real request before the fake is
out. That 2 ms is the only cost a connection pays.

pf also refuses QUIC (UDP 443) from user processes, so browsers fall back to TCP
right away instead of waiting on a QUIC handshake the DPI box drops.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/kennywillbe/cyadpi/main/install.sh | sudo sh
```

The script picks the build for your Mac, checks it against the release's
SHA-256, installs it and turns the service on. Run it again to update. From
source instead: `cargo build --release`, then
`sudo install -m 755 target/release/cyadpi /usr/local/bin/ && sudo cyadpi`.

The service runs the binary as root at every boot, so it is installed where only
root can write: `/usr/local/bin`, or `/usr/local/sbin` on Intel Macs where
Homebrew owns `/usr/local/bin`. For the same reason `sudo cyadpi` refuses to
start from a folder you can write to, like a `cargo build` output.

## Uninstall

```sh
sudo cyadpi uninstall
```

This turns it off and removes the service, the pf rules, the logs and the
binary. The script can do the same:
`curl -fsSL https://raw.githubusercontent.com/kennywillbe/cyadpi/main/install.sh | sudo sh -s uninstall`

## When something is off

- `cyadpi status` shows whether the service runs and the last lines of
  `/var/log/cyadpi.log`.
- `sudo cyadpi off` takes the pf rules and the 2 ms delay away. Your network
  is then exactly as it was.
- `sudo cyadpi run` runs it in the terminal instead of as a service; Ctrl-C
  stops it.
- `sudo cyadpi restore` cleans up pf if a crash ever left rules behind.

## What it needs

- macOS only, and it needs root: bpf, pf and launchd all do.
- Wi-Fi and Ethernet. Behind a VPN your traffic is inside the tunnel and the
  DPI box sees none of it, so cyadpi stays out of the way there.
- A TTL of 3 suits a DPI box two hops away. Servers inside your own network
  are skipped; a server fewer than three hops out would see the fake.

## License

Apache-2.0
