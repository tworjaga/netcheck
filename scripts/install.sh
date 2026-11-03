#!/bin/sh
# Installs netcheck on Linux or macOS:
#
#   curl -fsSL https://raw.githubusercontent.com/tworjaga/netcheck/main/scripts/install.sh | sh
#
# It downloads the binary for this system from the latest release, checks
# it against the release's SHA256SUMS, and puts it in ~/.local/bin (or
# /usr/local/bin as root). Settings, all optional:
#   NETCHECK_VERSION      a release tag, e.g. v0.9.0 (default: the latest)
#   NETCHECK_INSTALL_DIR  where to put it
#   NETCHECK_DOWNLOAD     where the release files are (a mirror)
set -eu

repo=tworjaga/netcheck
say() { printf '  %s\n' "$*"; }
fail() { printf '  netcheck install: %s\n' "$*" >&2; exit 1; }

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=macos ;;
  *) fail "this script is for Linux and macOS; on Windows use install.ps1" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) fail "no release for $(uname -m); build it from source (see the README)" ;;
esac
asset="netcheck-$os-$arch"

if [ -n "${NETCHECK_DOWNLOAD:-}" ]; then
  base=$NETCHECK_DOWNLOAD
elif [ -n "${NETCHECK_VERSION:-}" ]; then
  base="https://github.com/$repo/releases/download/$NETCHECK_VERSION"
else
  base="https://github.com/$repo/releases/latest/download"
fi

if [ -n "${NETCHECK_INSTALL_DIR:-}" ]; then
  dir=$NETCHECK_INSTALL_DIR
elif [ "$(id -u)" = 0 ]; then
  dir=/usr/local/bin
else
  dir="$HOME/.local/bin"
fi

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" "$1"
  else
    fail "needs curl or wget"
  fi
}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading $asset…"
fetch "$base/$asset" "$tmp/$asset" || fail "couldn't download $base/$asset"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || fail "couldn't download $base/SHA256SUMS"

want=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
[ -n "$want" ] || fail "SHA256SUMS doesn't list $asset"
if command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum "$tmp/$asset" | awk '{ print $1 }')
else
  got=$(shasum -a 256 "$tmp/$asset" | awk '{ print $1 }')
fi
[ "$got" = "$want" ] || fail "the download doesn't match SHA256SUMS; nothing was installed"
say "Checked against SHA256SUMS."

mkdir -p "$dir" || fail "can't create $dir"
chmod 755 "$tmp/$asset"
mv -f "$tmp/$asset" "$dir/netcheck" || fail "can't write to $dir (try NETCHECK_INSTALL_DIR, or sudo)"
say "Installed $("$dir/netcheck" --version) in $dir."

case ":$PATH:" in
  *":$dir:"*) say "Run netcheck to start." ;;
  *)
    say "$dir isn't on your PATH yet. Add this line to ~/.profile (or ~/.zshrc), then open a new terminal:"
    say "  export PATH=\"$dir:\$PATH\""
    ;;
esac
