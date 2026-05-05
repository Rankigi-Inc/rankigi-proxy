#!/bin/sh
# RANKIGI proxy installer.
# Piped from `curl -sSf https://rankigi.com/install | sh`.
#
# Detects the platform, downloads the matching prebuilt binary from the
# rankigi-core GitHub Releases, generates a local root CA, adds it to the
# system trust store, and prints the env vars the agent needs to set.
#
# POSIX sh. No bashisms. Tested on Debian, Ubuntu, Raspberry Pi OS, macOS.

set -eu

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REPO="Rankigi-Inc/rankigi-proxy"
BIN_NAME="rankigi-proxy"
BIN_DEST="/usr/local/bin/${BIN_NAME}"

LINUX_ETC_DIR="/etc/rankigi"
DARWIN_ETC_DIR="/usr/local/etc/rankigi"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

err() { printf 'error: %s\n' "$*" >&2; }
info() { printf '%s\n' "$*"; }

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "required command not found: $1"
    exit 1
  fi
}

# Run cmd as root if we are not already root. macOS and Linux both have sudo.
sudo_run() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    sudo "$@"
  fi
}

# ---------------------------------------------------------------------------
# 1. Detect platform
# ---------------------------------------------------------------------------

uname_s=$(uname -s)
uname_m=$(uname -m)

case "$uname_s" in
  Linux)  os="linux";  etc_dir="$LINUX_ETC_DIR" ;;
  Darwin) os="darwin"; etc_dir="$DARWIN_ETC_DIR" ;;
  *)
    err "unsupported OS: $uname_s. Supported: Linux, Darwin (macOS)."
    exit 1
    ;;
esac

case "$uname_m" in
  x86_64|amd64)        arch="x86_64" ;;
  aarch64|arm64)       arch="aarch64" ;;
  *)
    err "unsupported architecture: $uname_m. Supported: x86_64, aarch64 (arm64)."
    exit 1
    ;;
esac

asset="${BIN_NAME}-${os}-${arch}"
download_url="https://github.com/${REPO}/releases/latest/download/${asset}"

info "RANKIGI proxy installer"
info "  Platform: ${os}/${arch}"
info "  Asset:    ${asset}"
info ""

need curl

# ---------------------------------------------------------------------------
# 2. Download binary
# ---------------------------------------------------------------------------

tmp_bin=$(mktemp /tmp/rankigi-proxy.XXXXXX)
trap 'rm -f "$tmp_bin"' EXIT INT TERM

info "Downloading ${asset}..."
if ! curl -fSL -o "$tmp_bin" "$download_url"; then
  err "download failed: $download_url"
  err "verify your network and that a release exists at:"
  err "  https://github.com/${REPO}/releases/latest"
  exit 1
fi

if [ ! -s "$tmp_bin" ]; then
  err "downloaded file is empty"
  exit 1
fi

info "Installing to ${BIN_DEST}..."
sudo_run install -m 0755 "$tmp_bin" "$BIN_DEST"

# Remove macOS quarantine flag so Gatekeeper does not block execution of
# the unsigned binary on first run.
if [ "$os" = "darwin" ]; then
  sudo_run xattr -d com.apple.quarantine "$BIN_DEST" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 3. Generate CA cert
# ---------------------------------------------------------------------------

ca_cert="${etc_dir}/rankigi-ca.crt"
ca_key="${etc_dir}/rankigi-ca.key"

info "Generating local root CA..."
sudo_run mkdir -p "$etc_dir"
sudo_run env CA_CERT_PATH="$ca_cert" CA_KEY_PATH="$ca_key" \
  "$BIN_DEST" --generate-ca-only

if [ ! -f "$ca_cert" ]; then
  err "expected CA cert not found at $ca_cert"
  exit 1
fi

# ---------------------------------------------------------------------------
# 4. Trust CA cert in system store
# ---------------------------------------------------------------------------

info "Adding CA to system trust store..."

if [ "$os" = "linux" ]; then
  if command -v update-ca-certificates >/dev/null 2>&1; then
    sudo_run cp "$ca_cert" /usr/local/share/ca-certificates/rankigi-proxy.crt
    sudo_run update-ca-certificates >/dev/null
    info "  Added to /usr/local/share/ca-certificates and refreshed."
  elif command -v update-ca-trust >/dev/null 2>&1; then
    # RHEL / Fedora / CentOS path.
    sudo_run cp "$ca_cert" /etc/pki/ca-trust/source/anchors/rankigi-proxy.crt
    sudo_run update-ca-trust extract >/dev/null
    info "  Added to /etc/pki/ca-trust/source/anchors and refreshed."
  else
    err "could not find update-ca-certificates or update-ca-trust."
    err "trust the CA manually: $ca_cert"
  fi
else
  # macOS
  sudo_run security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain "$ca_cert"
  info "  Added to /Library/Keychains/System.keychain (trustRoot)."
fi

# ---------------------------------------------------------------------------
# 6. Detect localhost IPv6 issue
# ---------------------------------------------------------------------------
# Done before the success box so the warning sits next to the env vars.

ipv6_warning=""
if command -v getent >/dev/null 2>&1; then
  if getent hosts localhost 2>/dev/null | grep -q "::1"; then
    ipv6_warning=1
  fi
elif grep -E '^[[:space:]]*::1[[:space:]].*localhost' /etc/hosts >/dev/null 2>&1; then
  ipv6_warning=1
fi

# ---------------------------------------------------------------------------
# 5. Print setup instructions
# ---------------------------------------------------------------------------

cat <<'BOX'

+------------------------------------------------+
|   RANKIGI PROXY INSTALLED                      |
+------------------------------------------------+
|                                                |
|  Set these env vars on your agent:             |
|                                                |
|  export HTTPS_PROXY=http://127.0.0.1:8080      |
|  export HTTP_PROXY=http://127.0.0.1:8080       |
|  export NO_PROXY=rankigi.com                   |
|                                                |
|  Start the proxy:                              |
|  rankigi-proxy                                 |
|                                                |
|  Required env vars for the proxy:              |
|  RANKIGI_INGEST_URL=https://rankigi.com        |
|  RANKIGI_API_KEY=your_key_here                 |
|  RANKIGI_AGENT_ID=your_agent_uuid              |
|  RANKIGI_ORG_ID=your_org_uuid                  |
|                                                |
|  Get your keys at:                             |
|  app.rankigi.com/dashboard/keys                |
|                                                |
+------------------------------------------------+
BOX

if [ "$os" = "darwin" ]; then
  cat <<'MACNOTE'

+------------------------------------------------+
|  macOS note: unsigned binaries can be blocked  |
|  by Gatekeeper. The installer ran:             |
|                                                |
|    xattr -d com.apple.quarantine \             |
|      /usr/local/bin/rankigi-proxy              |
|                                                |
|  If launching the proxy is still blocked, run  |
|  the command above manually.                   |
+------------------------------------------------+
MACNOTE
fi

if [ -n "$ipv6_warning" ]; then
  cat <<'WARN'

WARNING: localhost resolves to IPv6 (::1) on this system.
Use 127.0.0.1 not localhost in HTTPS_PROXY. The proxy listens
on IPv4 only; agents that connect to ::1:8080 will silently
miss the proxy.

WARN
fi

# ---------------------------------------------------------------------------
# 7. Optional systemd service (Linux only)
# ---------------------------------------------------------------------------

if [ "$os" = "linux" ] && command -v systemctl >/dev/null 2>&1; then
  # If installer is not running on a TTY (e.g. piped from curl into sh),
  # don't block on stdin. Skip the prompt and tell the user how to opt in.
  if [ -t 0 ]; then
    printf 'Install rankigi-proxy as a systemd service?\n'
    printf 'It will start automatically on boot. [y/N] '
    read -r answer || answer="n"
  else
    answer=""
    info ""
    info "Tip: re-run this script in an interactive shell to install the"
    info "    systemd service automatically, or install it manually:"
    info "    https://rankigi.com/docs/proxy#systemd"
  fi

  case "$answer" in
    y|Y|yes|YES)
      service_path="/etc/systemd/system/rankigi-proxy.service"
      env_file="${etc_dir}/proxy.env"

      info "Writing $env_file..."
      tmp_env=$(mktemp /tmp/rankigi-proxy.env.XXXXXX)
      cat >"$tmp_env" <<EOF
RANKIGI_INGEST_URL=https://rankigi.com
RANKIGI_API_KEY=your_key_here
RANKIGI_AGENT_ID=your_agent_uuid
RANKIGI_ORG_ID=your_org_uuid
NO_PROXY=rankigi.com
CA_CERT_PATH=$ca_cert
CA_KEY_PATH=$ca_key
EOF
      sudo_run install -m 0600 "$tmp_env" "$env_file"
      rm -f "$tmp_env"

      info "Writing $service_path..."
      tmp_unit=$(mktemp /tmp/rankigi-proxy.service.XXXXXX)
      cat >"$tmp_unit" <<EOF
[Unit]
Description=RANKIGI Proxy Interceptor
After=network.target

[Service]
Type=simple
EnvironmentFile=$env_file
ExecStart=$BIN_DEST
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
      sudo_run install -m 0644 "$tmp_unit" "$service_path"
      rm -f "$tmp_unit"

      sudo_run systemctl daemon-reload
      sudo_run systemctl enable rankigi-proxy >/dev/null

      info ""
      info "Service installed."
      info "  Edit $env_file with your real RANKIGI keys."
      info "  Then run: sudo systemctl start rankigi-proxy"
      ;;
    *)
      :
      ;;
  esac
fi

info ""
info "Done."
