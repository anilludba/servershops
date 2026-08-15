#!/bin/bash
# TUIC v5 standalone server — second QUIC transport, alongside Hysteria2
#
# Why run this next to Hysteria2 instead of picking one: they sit on
# different points of the same trade-off rather than duplicating each
# other. Hysteria2 (Brutal congestion control) favors raw throughput on a
# lossy link; TUIC v5 favors steadier tail latency for many concurrent
# short-lived streams. They are also two separate QUIC implementations
# with different wire fingerprints — a detector tuned to one does not
# automatically catch the other.
#
# Upstream: https://github.com/EAimTY/tuic (tuic-server, Rust, MPL-2.0).
# Installed as a pinned release asset + published sha256sum, verified
# before use — unlike most installers in this repo (curl|bash from a
# moving branch), TUIC's releases ship real checksums, so we use them.

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

TUIC_BIN="/usr/local/bin/tuic-server"
TUIC_CONFIG_DIR="/etc/tuic"
TUIC_CONFIG="${TUIC_CONFIG_DIR}/config.json"
TUIC_CERT_DIR="${TUIC_CONFIG_DIR}/certs"
TUIC_RELEASE_TAG="tuic-server-1.0.0"

install_tuic() {
    log_info "Installing TUIC v5 (tuic-server ${TUIC_RELEASE_TAG})..."

    local arch target
    arch=$(uname -m)
    case "$arch" in
        x86_64)  target="x86_64-unknown-linux-musl" ;;
        aarch64) target="aarch64-unknown-linux-musl" ;;
        *)
            log_error "TUIC: unsupported architecture: $arch (need x86_64 or aarch64)"
            return 1
            ;;
    esac

    local asset="${TUIC_RELEASE_TAG}-${target}"
    local base_url="https://github.com/EAimTY/tuic/releases/download/${TUIC_RELEASE_TAG}"
    local tmp
    tmp=$(mktemp -d)

    if ! curl -fsSL -o "$tmp/tuic-server" "${base_url}/${asset}"; then
        log_error "TUIC: failed to download ${asset}"
        rm -rf "$tmp"
        return 1
    fi
    if ! curl -fsSL -o "$tmp/tuic-server.sha256sum" "${base_url}/${asset}.sha256sum"; then
        log_error "TUIC: failed to download checksum file for ${asset}"
        rm -rf "$tmp"
        return 1
    fi

    local expected actual
    expected=$(awk '{print $1}' "$tmp/tuic-server.sha256sum")
    actual=$(sha256sum "$tmp/tuic-server" | awk '{print $1}')
    if [[ -z "$expected" || "$expected" != "$actual" ]]; then
        log_error "TUIC: checksum mismatch for ${asset} (expected ${expected:-<empty>}, got $actual)"
        log_error "Not installing an unverified binary — aborting"
        rm -rf "$tmp"
        return 1
    fi

    install -m 0755 "$tmp/tuic-server" "$TUIC_BIN"
    rm -rf "$tmp"

    if ! id -u tuic &>/dev/null; then
        useradd --system --no-create-home --shell /usr/sbin/nologin tuic
    fi

    if "$TUIC_BIN" --version &>/dev/null; then
        log_ok "TUIC v5 installed: $("$TUIC_BIN" --version)"
    else
        log_error "TUIC v5 installation failed (binary present but doesn't run)"
        return 1
    fi
}

# Config field names/values verified against a live `tuic-server -c` run —
# see project notes. congestion_control=bbr matches the rest of this repo
# (XRAY/Hysteria2 also default to BBR); alpn=h3 is the only value that
# doesn't create an unusual ALPN fingerprint on the wire.
configure_tuic() {
    local port="$1"
    local selfsteal_domain="$2"
    local exit_uuid="$3"

    log_info "Configuring TUIC v5..."

    wait_for_caddy_cert "$selfsteal_domain" || return 1
    copy_caddy_cert "$selfsteal_domain" "$TUIC_CERT_DIR" tuic

    export TUIC_PASSWORD
    TUIC_PASSWORD=$(openssl rand -hex 16)

    mkdir -p "$TUIC_CONFIG_DIR"
    jq -n \
        --arg listen "0.0.0.0:${port}" \
        --arg uuid "$exit_uuid" \
        --arg password "$TUIC_PASSWORD" \
        --arg cert "${TUIC_CERT_DIR}/cert.crt" \
        --arg key "${TUIC_CERT_DIR}/cert.key" \
        '{
            server: $listen,
            users: { ($uuid): $password },
            certificate: $cert,
            private_key: $key,
            congestion_control: "bbr",
            alpn: ["h3"],
            udp_relay_ipv6: true,
            zero_rtt_handshake: false,
            auth_timeout: "3s",
            max_idle_time: "10s",
            max_external_packet_size: 1500,
            gc_interval: "3s",
            gc_lifetime: "15s",
            log_level: "warn"
        }' > "$TUIC_CONFIG"
    chmod 0640 "$TUIC_CONFIG"
    chown root:tuic "$TUIC_CONFIG"

    cat > /etc/systemd/system/tuic-server.service << SVCEOF
[Unit]
Description=TUIC v5 proxy server
Documentation=https://github.com/EAimTY/tuic
After=network.target

[Service]
Type=simple
User=tuic
Group=tuic
ExecStart=${TUIC_BIN} -c ${TUIC_CONFIG}
Restart=on-failure
RestartSec=3
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    log_ok "TUIC v5 config written to $TUIC_CONFIG"
}

restart_tuic() {
    systemctl restart tuic-server
    systemctl enable tuic-server

    if systemctl is-active --quiet tuic-server; then
        log_ok "TUIC v5 is running"
        return 0
    else
        log_error "TUIC v5 failed to start. Check: journalctl -u tuic-server"
        return 1
    fi
}

# update-exit.sh calls this on every run (Caddy may have auto-renewed the
# SelfSteal cert) — same pattern as update_hysteria_certs().
update_tuic_certs() {
    local selfsteal_domain="$1"

    if [[ ! -f "$(caddy_cert_path "$selfsteal_domain")" ]]; then
        log_warn "Caddy cert not found for ${selfsteal_domain}, skipping TUIC cert update"
        return 1
    fi

    copy_caddy_cert "$selfsteal_domain" "$TUIC_CERT_DIR" tuic
    log_ok "TUIC certs updated from Caddy"
}

uninstall_tuic() {
    log_info "Removing TUIC v5..."
    systemctl stop tuic-server 2>/dev/null || true
    systemctl disable tuic-server 2>/dev/null || true
    rm -f /etc/systemd/system/tuic-server.service 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    rm -f "$TUIC_BIN" 2>/dev/null || true
    rm -rf "$TUIC_CONFIG_DIR" 2>/dev/null || true
    userdel tuic 2>/dev/null || true
    log_ok "TUIC v5 removed"
}
