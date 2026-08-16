#!/bin/bash
# Common functions for VPN setup scripts
# shellcheck disable=SC2034
# (vars like PROJECT_VERSION, color codes are consumed by sourcing scripts)

set -euo pipefail

# Project version (read from VERSION file in repo root)
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROJECT_VERSION=$(cat "$REPO_ROOT/VERSION" 2>/dev/null || echo "unknown")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

check_os() {
    if ! grep -qi "ubuntu" /etc/os-release 2>/dev/null; then
        log_error "This script requires Ubuntu"
        exit 1
    fi
    log_ok "OS: Ubuntu detected"
}

prompt_input() {
    local prompt="$1"
    local var_name="$2"
    local default="${3:-}"
    local input
    if [[ -n "$default" ]]; then
        read -rp "$prompt [$default]: " input
        printf -v "$var_name" '%s' "${input:-$default}"
    else
        read -rp "$prompt: " input
        printf -v "$var_name" '%s' "$input"
    fi
}

prompt_password() {
    local prompt="$1"
    local var_name="$2"
    local input
    while true; do
        read -srp "$prompt: " input
        echo
        if [[ ! "$input" =~ ^[[:print:]]+$ ]]; then
            log_warn "Password contains non-ASCII characters (wrong keyboard layout?)"
            log_warn "Please try again with English layout"
            continue
        fi
        if [[ -z "$input" ]]; then
            log_warn "Password cannot be empty"
            continue
        fi
        break
    done
    printf -v "$var_name" '%s' "$input"
}

validate_ip() {
    local ip="$1"
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

validate_uuid() {
    local uuid="$1"
    [[ "$uuid" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]
}

validate_not_empty() {
    local value="$1"
    local name="$2"
    if [[ -z "$value" ]]; then
        log_error "$name cannot be empty"
        return 1
    fi
}

generate_random_port() {
    local excluded_ports=("$@")
    local port
    while true; do
        port=$(shuf -i 10000-60000 -n 1)
        # Skip if port is already listening
        if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
            continue
        fi
        # Skip if in excluded list
        local collision=false
        for ep in "${excluded_ports[@]}"; do
            if [[ "$port" == "$ep" ]]; then
                collision=true
                break
            fi
        done
        if [[ "$collision" == false ]]; then
            echo "$port"
            return
        fi
    done
}

generate_random_path() {
    openssl rand -hex 8
}

generate_admin_pass() {
    # od reads exactly 12 bytes and exits — no SIGPIPE on the writer (unlike
    # `tr </dev/urandom | head -c N`, which exits 141 under pipefail).
    # od + tr are in coreutils on every base Ubuntu — no openssl dependency,
    # so this works even before install_dependencies runs. 24 hex = 96 bits.
    od -An -N12 -tx1 /dev/urandom | tr -d ' \n'
}

# Single source of truth for XHTTP extra params (padding + mux + flow control).
# Values track XTLS upstream recommendations (discussion #4113, PR #4163):
#   - scMinPostsIntervalMs as range "10-50" (randomized) — avoids timing fingerprint
#   - scMaxEachPostBytes 1000000 (1MB) — upstream default
#   - scMaxBufferedPosts 30 — upstream default
#   - xmux.hMaxRequestTimes "600-900" — prevents hitting Nginx/CDN 1000-req cap
# Used on BOTH sides:
#   - Client-side (relay→exit outbound, subscription VLESS URLs): full block applies;
#     xmux and scMinPostsIntervalMs drive client behavior.
#   - Server-side (relay inbound, exit inbound): xmux and scMinPostsIntervalMs are
#     ignored at runtime but travel in subscription URL as metadata. xPaddingBytes,
#     scMaxEachPostBytes, scMaxBufferedPosts are enforced by the server.
# NOTE: scMaxEachPostBytes MUST match between relay outbound (client perspective)
# and exit inbound (server cap) — otherwise large POSTs get rejected.
xhttp_extra_json() {
    jq -n -c '{
        xPaddingBytes: "100-1000",
        scMaxEachPostBytes: 1000000,
        scMaxBufferedPosts: 30,
        scMinPostsIntervalMs: "10-50",
        xmux: {
            maxConcurrency: "16-32",
            maxConnections: 0,
            cMaxReuseTimes: "64-128",
            hMaxRequestTimes: "600-900"
        }
    }'
}

# Single source of truth for Reality fallback rate limits (server-side).
# Throttles only fallback traffic — real VPN clients passing the Reality
# handshake are NOT affected. Probes/visitors hitting the masquerade site
# get a "cheap-VPS-like" speed profile: full 5 MB burst, then 256 KB/s.
# Values match autoXRAY community baseline (xVRVx/autoXRAY).
# Used in:
#   - exit Reality inbound (xray.sh::configure_xray_exit)
#   - relay Reality inbound (3xui.sh::create_3xui_relay_inbound)
#   - relay inbound create via 3X-UI v3 REST API (xui-api.sh::xui_api_add_inbound)
#   - update-relay.sh in-place merge into existing DB row
reality_limit_fallback_json() {
    jq -n -c '{
        limitFallbackUpload: {
            afterBytes: 0,
            bytesPerSec: 65536,
            burstBytesPerSec: 0
        },
        limitFallbackDownload: {
            afterBytes: 5242880,
            bytesPerSec: 262144,
            burstBytesPerSec: 2097152
        }
    }'
}

# Both tune functions must be called BEFORE any service restart in the script —
# raise_service_nofile applies on next service start, so existing restarts later
# in update-*.sh pick up the new limit naturally without a second restart.
enable_bbr() {
    local current
    current=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)
    if [[ "$current" == "bbr" ]]; then
        log_ok "BBR already active"
        return 0
    fi

    cat > /etc/sysctl.d/99-vpn-bbr.conf <<'SYSCTL'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
SYSCTL

    sysctl --system >/dev/null || true

    current=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)
    if [[ "$current" == "bbr" ]]; then
        log_ok "BBR enabled (TCP congestion control + fq qdisc)"
    else
        log_warn "BBR not applied (kernel module missing?) — current: ${current:-unknown}"
    fi
}

# Socket buffer / accept-queue tuning for a relay that holds many concurrent
# long-lived encrypted connections (Reality/XHTTP/Hysteria2/TUIC), separate
# from enable_bbr() since it has no single "already applied" signal as clean
# as tcp_congestion_control==bbr — sysctl --system is idempotent to re-run
# regardless, so this just always (re)writes its own file.
#
# Deliberately does NOT set net.ipv4.tcp_fastopen: TFO changes the SYN's own
# structure (a distinct option + optional data), and this project's whole
# point is that the TLS/TCP handshake looks like the masquerade site's real
# traffic (see lib/reality.sh) — if the camouflage site doesn't advertise
# TFO and this server suddenly does, that is a small but real point of
# difference an active prober could someday check for. The throughput gain
# (one saved round trip) isn't worth adding a fingerprintable inconsistency
# to a project this deliberate about not having one.
tune_network_buffers() {
    cat > /etc/sysctl.d/99-vpn-network.conf <<'SYSCTL'
# Socket buffers — stock Linux maxes are sized for general-purpose use, too
# small to let BBR reach its throughput ceiling on a typical VPS's real
# bandwidth-delay product.
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216

# Accept/SYN queues — many concurrent client connections landing on :443.
net.core.somaxconn=4096
net.core.netdev_max_backlog=4096
net.ipv4.tcp_max_syn_backlog=4096

# VPN/proxy traffic is bursty (idle between requests, then a burst) — don't
# reset cwnd back to slow-start after an idle gap, and keep probing PMTU
# rather than risk a silent blackhole on a path with a stale/wrong MTU
# (common on VPS providers layering overlay networking under the NIC).
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_mtu_probing=1
SYSCTL

    sysctl --system >/dev/null || true
    log_ok "Network buffer/queue tuning applied"
}

# Swap as an OOM safety net, not a working-set extension — this project
# regularly runs on 1-2GB VPS instances (selfcheck has repeatedly shown
# ~600MB available on a live relay under normal load) with zero swap
# configured anywhere. Sized off actual RAM rather than a fixed value so it
# scales sanely across the small-VPS range this project targets; skips
# entirely above 2GB since that's past where this project needs to guess for
# the operator.
#
# swappiness=10 (not the 60 default): a relay's whole memory footprint is
# live proxy connection state. We want the kernel treating swap as a last
# resort against OOM-killing xray/3x-ui, not proactively paging out warm
# pages under mild pressure — the latter shows up as real added latency on
# whichever connection got paged out.
enable_swap() {
    if swapon --show 2>/dev/null | grep -q .; then
        log_ok "Swap already active ($(swapon --show=size --noheadings | tr -d ' '))"
        return 0
    fi

    local ram_kb swap_mb
    ram_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
    if (( ram_kb > 2097152 )); then
        log_info "RAM > 2GB — skipping automatic swap (add one manually if you want it)"
        return 0
    fi

    swap_mb=$(( ram_kb / 1024 ))
    (( swap_mb > 2048 )) && swap_mb=2048
    (( swap_mb < 512 )) && swap_mb=512

    local swapfile=/swapfile
    if [[ -f "$swapfile" ]]; then
        log_warn "$swapfile exists but isn't active — leaving it alone, inspect manually"
        return 0
    fi

    if ! fallocate -l "${swap_mb}M" "$swapfile" 2>/dev/null; then
        dd if=/dev/zero of="$swapfile" bs=1M count="$swap_mb" status=none
    fi
    chmod 600 "$swapfile"
    mkswap "$swapfile" >/dev/null
    if ! swapon "$swapfile"; then
        log_warn "Created ${swap_mb}MB swapfile but swapon failed (container/kernel restriction?) — removing"
        rm -f "$swapfile"
        return 0
    fi
    grep -q "^${swapfile} " /etc/fstab 2>/dev/null || echo "${swapfile} none swap sw 0 0" >> /etc/fstab

    cat > /etc/sysctl.d/99-vpn-swap.conf <<'SYSCTL'
vm.swappiness=10
vm.vfs_cache_pressure=50
SYSCTL
    sysctl --system >/dev/null || true

    log_ok "Swap enabled: ${swap_mb}MB ($swapfile), swappiness=10"
}

raise_service_nofile() {
    local conf=/etc/systemd/system.conf.d/99-vpn-limits.conf
    if [[ -f "$conf" ]] && grep -q '^DefaultLimitNOFILE=65535$' "$conf"; then
        log_ok "systemd nofile limit already 65535"
        return 0
    fi

    mkdir -p /etc/systemd/system.conf.d
    cat > "$conf" <<'LIMITS'
[Manager]
DefaultLimitNOFILE=65535
LIMITS

    systemctl daemon-reexec
    log_ok "systemd nofile limit set to 65535 (applies on next service start)"
}

install_dependencies() {
    log_info "Installing dependencies..."
    apt-get update -qq
    apt-get install -y -qq curl wget unzip jq openssl cron socat git sqlite3 > /dev/null 2>&1
    log_ok "Dependencies installed"
}

update_system() {
    log_info "Updating system..."
    apt-get update -qq && apt-get upgrade -y -qq > /dev/null 2>&1
    log_ok "System updated"
}

# Wait for Caddy's ACME-issued cert for $domain to land on disk (Caddy issues
# it asynchronously after start, so a freshly-started Caddy may not have it
# yet). Shared by any SelfSteal-adjacent service that needs its own copy of
# the cert (Hysteria2, TUIC) — Caddy itself owns issuance/renewal, callers
# only ever read a copy.
wait_for_caddy_cert() {
    local domain="$1"
    local timeout="${2:-90}"
    local cert_path
    cert_path="$(caddy_cert_path "$domain")"

    [[ -f "$cert_path" ]] && return 0

    log_info "Waiting for Caddy ACME certificate for ${domain}..."
    local elapsed=0
    while [[ ! -f "$cert_path" ]]; do
        if [[ $elapsed -ge $timeout ]]; then
            log_error "Caddy cert not issued for ${domain} within ${timeout}s"
            log_error "Expected: $cert_path"
            log_error "ACME likely failed — check: journalctl -u caddy"
            return 1
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    log_ok "Caddy cert ready (waited ${elapsed}s)"
}

caddy_cert_dir_for() {
    echo "/root/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/${1}"
}

caddy_cert_path() {
    echo "$(caddy_cert_dir_for "$1")/${1}.crt"
}

# Copy Caddy's cert+key for $domain into $dest_dir/cert.crt + cert.key.
# $dest_group (optional): chown the private key root:$dest_group 0640 for a
# service that runs as a dedicated system user, instead of root-only 0600.
copy_caddy_cert() {
    local domain="$1" dest_dir="$2" dest_group="${3:-}"
    local src_dir
    src_dir="$(caddy_cert_dir_for "$domain")"

    mkdir -p "$dest_dir"
    cp "${src_dir}/${domain}.crt" "$dest_dir/cert.crt"
    cp "${src_dir}/${domain}.key" "$dest_dir/cert.key"
    chmod 644 "$dest_dir/cert.crt"
    if [[ -n "$dest_group" ]]; then
        chmod 640 "$dest_dir/cert.key"
        chown "root:${dest_group}" "$dest_dir/cert.key"
    else
        chmod 600 "$dest_dir/cert.key"
    fi
}

validate_domain() {
    local domain="$1"
    [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$ ]]
}

check_domain_dns() {
    local domain="$1"
    local server_ip
    server_ip=$(curl -s4 --max-time 5 ifconfig.me 2>/dev/null) || server_ip=""
    local domain_ip
    domain_ip=$(getent hosts "$domain" 2>/dev/null | awk '{print $1}' | head -1) || domain_ip=""

    if [[ -z "$domain_ip" ]]; then
        log_error "DNS for ${domain} does not resolve"
        log_error "Set A-record: ${domain} → ${server_ip}"
        return 1
    fi

    if [[ -n "$server_ip" && "$domain_ip" != "$server_ip" ]]; then
        log_error "DNS for ${domain} resolves to ${domain_ip}, but this server is ${server_ip}"
        return 1
    fi

    log_ok "DNS verified: ${domain} → ${domain_ip}"
}
