#!/bin/sh
# Installs domicile from GitHub Releases.
#
#   On the VPS:          curl -fsSL https://raw.githubusercontent.com/avinash-1707/domicile/main/install.sh | sh
#   On the home device:  curl -fsSL https://raw.githubusercontent.com/avinash-1707/domicile/main/install.sh | sh -s -- join <code>
#
# It downloads the binary for this OS and CPU, checks it against the
# release's SHA256SUMS, and asks before every change to the system. Set
# DOMICILE_YES=1 to answer yes to everything (unattended installs).
set -eu

REPO=avinash-1707/domicile
BASE=${DOMICILE_RELEASE_URL:-https://github.com/$REPO/releases/latest/download}
BIN_DIR=${DOMICILE_BIN_DIR:-/usr/local/bin}
YES=${DOMICILE_YES:-}

say() { printf '%s\n' "$*" >&2; }
die() { say "domicile install: $*"; exit 1; }

# ask reads from the terminal, since stdin is this script when piped to sh.
ask() {
	[ -n "$YES" ] && return 0
	# /dev/tty can exist without a controlling terminal (cron, CI): treat
	# that as "no" rather than failing.
	(: </dev/tty) 2>/dev/null || return 1
	printf '%s [y/N] ' "$1" >/dev/tty
	read -r answer </dev/tty || return 1
	case $answer in y | Y | yes | YES) return 0 ;; esac
	return 1
}

as_root() {
	if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi
}

# Everything runs from main, so a download cut short by `curl | sh` runs
# nothing.
main() {
	case $(uname -s) in
	Linux) os=linux ;;
	Darwin) os=darwin ;;
	*) die "unsupported OS $(uname -s); Linux and macOS are supported" ;;
	esac
	case $(uname -m) in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) die "unsupported CPU $(uname -m); amd64 and arm64 are supported" ;;
	esac
	asset=domicile-$os-$arch

	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT
	say "Downloading $asset ..."
	curl -fsSL "$BASE/$asset" -o "$tmp/$asset" || die "download failed: $BASE/$asset"
	curl -fsSL "$BASE/SHA256SUMS" -o "$tmp/SHA256SUMS" || die "download failed: $BASE/SHA256SUMS"

	expected=$(awk -v f="$asset" '$2 == f { print $1 }' "$tmp/SHA256SUMS")
	[ -n "$expected" ] || die "$asset is not listed in SHA256SUMS"
	if command -v sha256sum >/dev/null 2>&1; then
		actual=$(sha256sum "$tmp/$asset" | awk '{ print $1 }')
	elif command -v shasum >/dev/null 2>&1; then
		actual=$(shasum -a 256 "$tmp/$asset" | awk '{ print $1 }')
	else
		die "need sha256sum or shasum to check the download"
	fi
	[ "$expected" = "$actual" ] || die "checksum mismatch for $asset; refusing to install"
	chmod 0755 "$tmp/$asset"

	if [ -w "$BIN_DIR" ] || { [ ! -e "$BIN_DIR" ] && mkdir -p "$BIN_DIR" 2>/dev/null; }; then
		mv "$tmp/$asset" "$BIN_DIR/domicile"
	elif ask "Install domicile to $BIN_DIR (needs sudo)?"; then
		as_root mkdir -p "$BIN_DIR"
		# install, not mv: mv keeps the downloading user as owner, and root
		# runs this binary later (sudo domicile service install).
		as_root install -m 0755 "$tmp/$asset" "$BIN_DIR/domicile"
	else
		mv "$tmp/$asset" ./domicile
		BIN_DIR=.
		say "Left the binary at ./domicile."
	fi
	domicile="$BIN_DIR/domicile"
	say "Installed $("$domicile" version)."

	# QUIC wants larger UDP buffers than most Linux defaults.
	if [ "$os" = linux ]; then
		current=$(cat /proc/sys/net/core/rmem_max 2>/dev/null || echo 0)
		if [ "$current" -lt 7500000 ]; then
			if ask "Raise the UDP buffer limit for QUIC (writes /etc/sysctl.d/90-domicile.conf)?"; then
				printf 'net.core.rmem_max=7500000\nnet.core.wmem_max=7500000\n' | as_root tee /etc/sysctl.d/90-domicile.conf >/dev/null
				as_root sysctl -q -p /etc/sysctl.d/90-domicile.conf
			else
				say "Skipped; the tunnel still works, with lower throughput on fast links."
			fi
		fi
	fi

	if [ "${1:-}" = join ]; then
		[ -n "${2:-}" ] || die "usage: install.sh join <code from 'domicile add'>"
		"$domicile" agent join -pair-only "$2"
		if ask "Run the exit as a service, so it starts at boot and reconnects on its own?"; then
			if [ "$os" = linux ]; then
				# sudo drops XDG_STATE_HOME, so name the directory join used.
			as_root "$domicile" service install agent -yes -user "$(id -un)" -state-dir "${XDG_STATE_HOME:-$HOME/.local/state}/domicile"
			else
				"$domicile" service install agent -yes
			fi
		else
			say "Start it yourself with: $domicile agent"
		fi
		return 0
	fi

	say ""
	say "Next, on this VPS:"
	say "  $domicile init -public-addr <this server's address>:443"
	say "  sudo $domicile service install server"
	say "  $domicile add home      # prints the join command for your home device"
}

main "$@"
