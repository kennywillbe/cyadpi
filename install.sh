#!/bin/sh
# Install, update or remove cyadpi.
#
#   curl -fsSL https://raw.githubusercontent.com/kennywillbe/cyadpi/main/install.sh | sudo sh
#   curl -fsSL https://raw.githubusercontent.com/kennywillbe/cyadpi/main/install.sh | sudo sh -s uninstall
set -eu

REPO=kennywillbe/cyadpi

fail() {
    echo "cyadpi: $*" >&2
    exit 1
}

[ "$(uname -s)" = Darwin ] || fail "macOS only"
[ "$(id -u)" = 0 ] || fail "run it with sudo"

# The service runs the binary as root at every boot, so it has to live where
# only root can write. /usr/local/bin is that on Apple silicon, but Homebrew
# owns it on Intel Macs; /usr/local/sbin is the fallback.
root_only() {
    [ -d "$1" ] && [ "$(stat -L -f %u "$1")" = 0 ] && [ -z "$(find -H "$1" -maxdepth 0 -perm +022)" ]
}

installed() {
    for d in /usr/local/bin /usr/local/sbin; do
        [ -x "$d/cyadpi" ] && { echo "$d/cyadpi"; return; }
    done
}

if [ "${1:-}" = uninstall ]; then
    exe=$(installed)
    [ -n "$exe" ] || fail "not installed"
    exec "$exe" uninstall
fi

case "$(uname -m)" in
    arm64) target=aarch64-apple-darwin ;;
    x86_64) target=x86_64-apple-darwin ;;
    *) fail "unsupported CPU: $(uname -m)" ;;
esac

# A fresh Mac may not have /usr/local/bin at all.
[ -e /usr/local/bin ] || install -d -o root -g wheel -m 755 /usr/local/bin
if root_only /usr/local/bin; then
    dir=/usr/local/bin
else
    dir=/usr/local/sbin
    install -d -o root -g wheel -m 755 "$dir"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
url=https://github.com/$REPO/releases/latest/download/cyadpi-$target.tar.gz
echo "cyadpi: downloading $url"
curl -fsSL -o "$tmp/cyadpi.tar.gz" "$url"
curl -fsSL -o "$tmp/cyadpi.tar.gz.sha256" "$url.sha256"
want=$(awk '{print $1}' "$tmp/cyadpi.tar.gz.sha256")
got=$(shasum -a 256 "$tmp/cyadpi.tar.gz" | awk '{print $1}')
[ "$want" = "$got" ] || fail "checksum mismatch, nothing installed"
tar -xzf "$tmp/cyadpi.tar.gz" -C "$tmp"

# An update replaces a binary the service is running from; stop it first so
# the new one is what starts.
old=$(installed || true)
[ -n "$old" ] && "$old" off >/dev/null 2>&1 || true
install -m 755 -o root -g wheel "$tmp/cyadpi" "$dir/cyadpi"
"$dir/cyadpi"
echo "cyadpi: installed to $dir/cyadpi. Remove with: sudo cyadpi uninstall"
