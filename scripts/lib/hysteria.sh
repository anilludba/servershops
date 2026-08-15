#!/bin/bash
# Hysteria 2 standalone server (UDP fallback channel)

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

HYSTERIA_CONFIG="/etc/hysteria/config.yaml"
HYSTERIA_CERT_DIR="/etc/hysteria/certs"

install_hysteria() {
    log_info "Installing Hysteria 2..."

    bash <(curl -fsSL https://get.hy2.sh/) < /dev/null

    if command -v hysteria &> /dev/null; then
        local version
        version=$(hysteria version 2>/dev/null | head -1 || true)
        log_ok "Hysteria 2 installed: $version"
    else
        log_error "Hysteria 2 installation failed"
        exit 1
    fi
}

configure_hysteria() {
    local listen_port="$1"
    local port_range_end="$2"
    local selfsteal_domain="$3"
    local exit_uuid="$4"
    local obfs_password="$5"

    log_info "Configuring Hysteria 2..."

    # Hysteria runs as 'hysteria' user, Caddy certs are root-owned — copy a
    # group-readable copy in. wait_for_caddy_cert/copy_caddy_cert live in
    # common.sh (shared with tuic.sh, which needs the exact same dance).
    wait_for_caddy_cert "$selfsteal_domain" || exit 1
    copy_caddy_cert "$selfsteal_domain" "$HYSTERIA_CERT_DIR" hysteria

    mkdir -p /etc/hysteria
    cat > "$HYSTERIA_CONFIG" << HYEOF
listen: :${listen_port}-${port_range_end}

tls:
  cert: ${HYSTERIA_CERT_DIR}/cert.crt
  key: ${HYSTERIA_CERT_DIR}/cert.key

auth:
  type: password
  password: "${exit_uuid}"

obfs:
  type: salamander
  salamander:
    password: "${obfs_password}"

masquerade:
  type: proxy
  proxy:
    url: https://${selfsteal_domain}/
    rewriteHost: true
HYEOF

    log_ok "Hysteria 2 config written to $HYSTERIA_CONFIG"
}

restart_hysteria() {
    systemctl restart hysteria-server
    systemctl enable hysteria-server

    if systemctl is-active --quiet hysteria-server; then
        log_ok "Hysteria 2 is running"
        return 0
    else
        log_error "Hysteria 2 failed to start. Check: journalctl -u hysteria-server"
        return 1
    fi
}

update_hysteria_certs() {
    local selfsteal_domain="$1"

    if [[ ! -f "$(caddy_cert_path "$selfsteal_domain")" ]]; then
        log_warn "Caddy cert not found for ${selfsteal_domain}, skipping cert update"
        return 1
    fi

    copy_caddy_cert "$selfsteal_domain" "$HYSTERIA_CERT_DIR" hysteria
    log_ok "Hysteria certs updated from Caddy"
}

uninstall_hysteria() {
    log_info "Removing Hysteria 2..."

    systemctl stop hysteria-server 2>/dev/null || true
    systemctl disable hysteria-server 2>/dev/null || true

    # Official uninstall
    if [[ -f /usr/local/bin/hysteria ]]; then
        bash <(curl -fsSL https://get.hy2.sh/) --remove < /dev/null 2>/dev/null || true
    fi

    rm -rf /etc/hysteria 2>/dev/null || true
    log_ok "Hysteria 2 removed"
}
