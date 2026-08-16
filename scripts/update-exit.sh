#!/bin/bash
# Update exit server configuration from latest codebase
# Run: ./setup.sh update-exit [--upgrade] [--enable-warp|--disable-warp] [--remove-3xui]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/common.sh"
source "$SCRIPT_DIR/lib/security.sh"
source "$SCRIPT_DIR/lib/xray.sh"
source "$SCRIPT_DIR/lib/3xui.sh"
source "$SCRIPT_DIR/lib/hysteria.sh"
source "$SCRIPT_DIR/lib/tuic.sh"
source "$SCRIPT_DIR/lib/amneziawg.sh"
source "$SCRIPT_DIR/lib/warp.sh"
source "$SCRIPT_DIR/lib/verify.sh"
source "$SCRIPT_DIR/lib/caddy.sh"

XRAY_CONFIG="/usr/local/etc/xray/config.json"
XUI_DB="/etc/x-ui/x-ui.db"

main() {
    local upgrade=false skip_ssh=false enable_warp=false disable_warp=false remove_3xui=false
    for arg in "$@"; do
        case "$arg" in
            --upgrade) upgrade=true ;;
            --skip-ssh) skip_ssh=true ;;
            --enable-warp) enable_warp=true ;;
            --disable-warp) disable_warp=true ;;
            --remove-3xui) remove_3xui=true ;;
        esac
    done

    if [[ "$enable_warp" == true && "$disable_warp" == true ]]; then
        log_error "--enable-warp and --disable-warp are mutually exclusive"
        exit 1
    fi

    echo "==========================================="
    echo "  VLESS Reality VPN — EXIT Server Update  v${PROJECT_VERSION}"
    echo "==========================================="
    echo ""

    check_root
    enable_bbr
    raise_service_nofile

    # --- Step 1: Validate existing installation ---
    log_info "=== Checking existing installation ==="

    if [[ ! -f "$XRAY_CONFIG" ]]; then
        log_error "XRAY config not found at $XRAY_CONFIG"
        log_error "Run './setup.sh exit' first to perform initial setup"
        exit 1
    fi

    if ! command -v xray &> /dev/null; then
        log_error "XRAY binary not found"
        log_error "Run './setup.sh exit' first to perform initial setup"
        exit 1
    fi

    # --- Step 2: Extract current values ---
    log_info "=== Reading current configuration ==="

    local uuid private_key short_id dest server_name listen_port public_key xver
    uuid=$(jq -r '.inbounds[0].settings.clients[0].id' "$XRAY_CONFIG")
    private_key=$(jq -r '.inbounds[0].streamSettings.realitySettings.privateKey' "$XRAY_CONFIG")
    short_id=$(jq -r '.inbounds[0].streamSettings.realitySettings.shortIds[0]' "$XRAY_CONFIG")
    dest=$(jq -r '.inbounds[0].streamSettings.realitySettings.dest' "$XRAY_CONFIG")
    xver=$(jq -r '.inbounds[0].streamSettings.realitySettings.xver' "$XRAY_CONFIG")

    local is_selfsteal=false
    if [[ "$dest" == *"caddy.sock"* ]]; then
        is_selfsteal=true
        log_info "SelfSteal mode detected"
    fi

    local is_cdn=false cdn_port="" cdn_path=""
    # Try new XHTTP tag first, fall back to old WS tag for migration
    cdn_port=$(jq -r '.inbounds[] | select(.tag=="vless-cdn-in") | .port // empty' "$XRAY_CONFIG" 2>/dev/null) || true
    cdn_path=$(jq -r '.inbounds[] | select(.tag=="vless-cdn-in") | .streamSettings.xhttpSettings.path // empty' "$XRAY_CONFIG" 2>/dev/null | sed 's|^/||') || true
    if [[ -z "$cdn_port" ]]; then
        # Migration: read from old WS inbound
        cdn_port=$(jq -r '.inbounds[] | select(.tag=="vless-ws-in") | .port // empty' "$XRAY_CONFIG" 2>/dev/null) || true
        cdn_path=$(jq -r '.inbounds[] | select(.tag=="vless-ws-in") | .streamSettings.wsSettings.path // empty' "$XRAY_CONFIG" 2>/dev/null | sed 's|^/||') || true
    fi
    if [[ -n "$cdn_port" && "$cdn_port" != "null" && -n "$cdn_path" && "$cdn_path" != "null" ]]; then
        is_cdn=true
        log_info "CDN mode detected (port: $cdn_port)"
    fi
    server_name=$(jq -r '.inbounds[0].streamSettings.realitySettings.serverNames[0]' "$XRAY_CONFIG")
    listen_port=$(jq -r '.inbounds[0].port' "$XRAY_CONFIG")
    public_key=$(xray x25519 -i "$private_key" 2>/dev/null | grep -iE "public|password" | awk '{print $NF}')

    if [[ -z "$uuid" || "$uuid" == "null" ]]; then
        log_error "Failed to extract UUID from config"
        exit 1
    fi

    local dns_mode="default"
    if jq -e '.dns.servers[] | select(. == "94.140.14.14")' "$XRAY_CONFIG" > /dev/null 2>&1; then
        dns_mode="adguard"
    fi

    # Detect existing WARP outbound (issue #35) — preserve unless flag overrides
    local warp_enabled="N"
    if jq -e '.outbounds[] | select(.tag=="warp")' "$XRAY_CONFIG" > /dev/null 2>&1; then
        warp_enabled="Y"
    fi

    # warp_pending_disable=true means warp-cli/warp-svc must be stopped AFTER
    # successful xray restart (prevents broken state if restart_xray rolls back
    # to a backup that still references the warp outbound).
    local warp_pending_disable=false

    if [[ "$enable_warp" == true ]]; then
        log_info "Enabling WARP outbound (--enable-warp)..."
        install_warp
        # Always ensure warp-svc + socks5 listener are healthy on --enable-warp
        # (idempotent — handles case where flag was set before but daemon died).
        if ! is_warp_running; then
            configure_warp
        else
            log_info "WARP already running, skipping reconfigure"
        fi
        warp_enabled="Y"
    elif [[ "$disable_warp" == true ]]; then
        if [[ "$warp_enabled" == "N" ]]; then
            log_info "WARP not enabled, --disable-warp is no-op"
        else
            log_info "Disabling WARP outbound (--disable-warp) — warp-svc will stop after xray restart"
            warp_pending_disable=true
            warp_enabled="N"
        fi
    elif [[ "$warp_enabled" == "Y" ]]; then
        if ! is_warp_running; then
            log_warn "WARP outbound configured but warp-svc not running, restarting..."
            restart_warp || log_warn "WARP restart failed (config preserved as Y, manual fix needed)"
        fi
    fi

    log_ok "Current config read successfully"
    log_info "  UUID:     $uuid"
    log_info "  Port:     $listen_port"
    log_info "  SNI:      $server_name"
    log_info "  DNS mode: $dns_mode"
    log_info "  WARP:     $warp_enabled"

    # Read panel port from 3X-UI DB (for UFW and verification) — only
    # relevant for exit servers that still carry a pre-removal legacy
    # install (fresh installs since the removal never have this file).
    local panel_port=""
    if [[ -f "$XUI_DB" ]]; then
        panel_port=$(sqlite3 "$XUI_DB" "SELECT value FROM settings WHERE key='webPort';" 2>/dev/null) || true
    fi

    # --- Step 2a: One-time legacy cleanup (--remove-3xui) ---
    # 3X-UI on exit never controlled the actual xray process/config (exit's
    # xray always ran as its own systemd service with a static config) —
    # it was fully inert here. Servers set up before that was fixed still
    # have it installed and running for no operational reason; this flag
    # is the opt-in one-time removal for them. Fresh installs never had it,
    # so this is a no-op there.
    if [[ "$remove_3xui" == true ]]; then
        if [[ -f "$XUI_DB" ]]; then
            log_info "=== Removing legacy 3X-UI from exit (--remove-3xui) ==="
            if command -v x-ui &>/dev/null; then
                x-ui stop 2>/dev/null || true
                echo "y" | x-ui uninstall 2>/dev/null || true
            fi
            rm -rf /etc/x-ui/ 2>/dev/null || true
            log_ok "3X-UI removed from exit"
            if [[ -n "$panel_port" ]]; then
                log_info "Its UFW rule for port ${panel_port} was NOT auto-removed —"
                log_info "revoke manually if desired: ufw delete allow ${panel_port}/tcp"
            fi
            panel_port=""
        else
            log_info "--remove-3xui: no 3X-UI install found on this exit, nothing to do"
        fi
    fi

    # --- Step 2b: Heal Caddy socket perms (issue #42) ---
    # Install/refresh systemd override BEFORE apt upgrade — if apt-postinst
    # restarts Caddy in this run, ExecStartPost will already be in place.
    if [[ "$is_selfsteal" == true ]]; then
        install_caddy_systemd_override
        if [[ -S "/dev/shm/caddy.sock" ]] && [[ "$(stat -c '%a' /dev/shm/caddy.sock 2>/dev/null)" != "666" ]]; then
            log_info "Restarting Caddy to apply socket perms fix..."
            systemctl restart caddy
        fi
    fi

    # --- Step 3: System update ---
    log_info "=== System Update ==="
    update_system

    # --- Step 4: Upgrade binaries (optional) ---
    if [[ "$upgrade" == true ]]; then
        log_info "=== Upgrading Binaries ==="

        log_info "Upgrading XRAY..."
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install < /dev/null
        local version
        version=$(xray version 2>/dev/null | head -1 || true)
        log_ok "XRAY upgraded: $version"

        if command -v x-ui &> /dev/null; then
            log_info "Upgrading 3X-UI..."
            # Pinned to v3.6.0 (bumped from v3.3.1) — see scripts/lib/3xui.sh for
            # the full rationale. Exit panel is decorative (real exit xray is
            # standalone) — no API migration needed here even though this bump
            # is not itself security-motivated.
            #
            # NONINTERACTIVE=1 (explicit) + XUI_SSL_MODE=none: v3.6.0's install.sh
            # replaces every prompt with an env-var-or-default lookup once stdin
            # isn't a TTY (which our `< /dev/null` guarantees) — verified by
            # tracing the installer source that these two vars reproduce "Skip
            # SSL, don't bind 127.0.0.1" exactly, without relying on printf'd
            # answers to prompts that mode no longer actually reads.
            XUI_NONINTERACTIVE=1 XUI_SSL_MODE=none \
                bash <(curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/v3.6.0/install.sh) v3.6.0 < /dev/null
            log_ok "3X-UI upgraded to v3.6.0"
        fi

        if [[ "$is_selfsteal" == true ]]; then
            log_info "Upgrading Caddy..."
            apt-get update -qq && apt-get install -y -qq caddy > /dev/null 2>&1
            log_ok "Caddy upgraded"
        fi

        if [[ -f /etc/tuic/config.json ]]; then
            log_info "Reinstalling TUIC v5 (pinned release — re-verifies checksum, repairs a partial install)..."
            # install_tuic() is pinned to a fixed tag (see lib/tuic.sh) — same
            # reasoning as the 3X-UI pin above: a moving 'latest' target here
            # would mean re-verifying against a checksum that also moved,
            # which is a real difference from "curl|bash off a branch" only
            # in that we'd still be checking SOMETHING, not nothing. Kept
            # pinned for now rather than resolving GitHub's 'latest' release
            # dynamically on every run of a script that may execute across
            # many servers — avoids depending on unauthenticated GitHub API
            # rate limits for something that isn't security-critical to
            # chase immediately.
            if install_tuic; then
                log_ok "TUIC v5 reinstalled"
            else
                log_warn "TUIC v5 reinstall failed — previous binary/config untouched"
            fi
        fi

        if [[ -f /etc/amnezia/amneziawg/awg0.conf ]] && command -v awg &>/dev/null; then
            log_info "Upgrading AmneziaWG package..."
            if apt-get update -qq && apt-get install -y -qq --only-upgrade amneziawg > /dev/null 2>&1; then
                systemctl restart "awg-quick@awg0" 2>/dev/null || true
                if systemctl is-active --quiet "awg-quick@awg0"; then
                    log_ok "AmneziaWG upgraded and interface restarted"
                else
                    log_warn "AmneziaWG package upgraded but awg-quick@awg0 didn't come back — check: journalctl -u awg-quick@awg0"
                fi
                log_info "If the kernel module itself changed, a full reboot may still be needed for it to take effect"
            else
                log_warn "AmneziaWG upgrade check found nothing newer, or failed — see apt output above"
            fi
        fi
    fi

    # --- Step 5: Update XRAY config ---
    log_info "=== Updating XRAY Config ==="
    local backup_path
    backup_path="${XRAY_CONFIG}.bak.$(date +%Y%m%d-%H%M%S)"
    cp "$XRAY_CONFIG" "$backup_path"
    log_ok "Backup saved: $backup_path"

    if jq -e '.inbounds[0].streamSettings.xhttpSettings' "$XRAY_CONFIG" > /dev/null 2>&1; then
        log_info "Migrating XHTTP → RAW + xtls-rprx-vision (issue #33)"
    else
        log_info "Already on RAW + Vision, regenerating config"
    fi

    configure_xray_exit "$listen_port" "$uuid" "$private_key" \
        "$short_id" "$dest" "$server_name" "$xver" \
        "$cdn_port" "$cdn_path" "$dns_mode" "$warp_enabled"

    if ! restart_xray; then
        log_warn "Restoring previous config..."
        cp "$backup_path" "$XRAY_CONFIG"
        restart_xray || { log_error "Rollback also failed"; exit 1; }
        log_ok "Previous config restored, XRAY is running"
        exit 1
    fi

    # Stop WARP only AFTER successful xray restart — otherwise a config rollback
    # leaves xray referencing a disconnected WARP socks5 listener.
    if [[ "$warp_pending_disable" == true ]]; then
        log_info "Stopping warp-svc and disconnecting WARP..."
        warp-cli --accept-tos disconnect 2>/dev/null || true
        systemctl stop warp-svc 2>/dev/null || true
        log_ok "WARP daemon stopped (package preserved — use uninstall --purge-warp to remove)"
    fi

    # 3X-UI installer leaves an acme.sh cron behind that conflicts with Caddy on :80
    if [[ "$is_selfsteal" == true ]]; then
        disable_acme_cron
    fi

    # Regenerate Caddyfile if SelfSteal + CDN (routing changed from WS to XHTTP)
    if [[ "$is_selfsteal" == true && "$is_cdn" == true ]]; then
        local cdn_domain
        cdn_domain=$(grep -oP '(?<=https://)\S+(?= \{)' /etc/caddy/Caddyfile 2>/dev/null | grep -v "$server_name" | head -1) || true
        if [[ -n "$cdn_domain" ]]; then
            generate_caddyfile "$server_name" "" "" "" "" "$cdn_domain" "$cdn_path" "$cdn_port"
            start_caddy
            log_ok "Caddyfile regenerated (CDN XHTTP routing)"
        fi
    fi

    # --- Step 5b: Update Hysteria 2 if installed ---
    local is_hysteria=false
    if [[ -f "$HYSTERIA_CONFIG" ]]; then
        is_hysteria=true
        log_info "Hysteria 2 detected"

        if [[ "$upgrade" == true ]]; then
            log_info "Upgrading Hysteria 2..."
            bash <(curl -fsSL https://get.hy2.sh/) < /dev/null 2>/dev/null || true
            log_ok "Hysteria 2 upgraded"
        fi

        # Update certs from Caddy (may have been renewed)
        if [[ "$is_selfsteal" == true ]]; then
            update_hysteria_certs "$server_name"
        fi

        systemctl restart hysteria-server
        if systemctl is-active --quiet hysteria-server; then
            log_ok "Hysteria 2 restarted"
        else
            log_warn "Hysteria 2 failed to restart. Check: journalctl -u hysteria-server"
        fi
    fi

    # --- Step 5c: Update TUIC v5 certs if installed ---
    # Binary upgrade / port changes for TUIC are not wired into --upgrade
    # yet (tracked as follow-up) — this block only keeps the cert current,
    # which is the one thing that silently breaks TUIC on its own schedule
    # (Caddy renews the SelfSteal cert roughly every 60 days; without this,
    # tuic-server keeps serving the old one until it expires).
    local is_tuic=false
    if [[ -f /etc/tuic/config.json ]]; then
        is_tuic=true
        log_info "TUIC v5 detected"
        if [[ "$is_selfsteal" == true ]]; then
            update_tuic_certs "$server_name"
            systemctl restart tuic-server
            if systemctl is-active --quiet tuic-server; then
                log_ok "TUIC v5 restarted"
            else
                log_warn "TUIC v5 failed to restart. Check: journalctl -u tuic-server"
            fi
        fi
    fi

    # --- Step 6: Security ---
    log_info "=== Security ==="
    local ssh_port
    ssh_port=$(grep -E '^Port ' /etc/ssh/sshd_config 2>/dev/null | head -1 | awk '{print $2}') || true
    ssh_port="${ssh_port:-22}"
    log_info "Current SSH port: $ssh_port"

    local security_args=()
    [[ "$skip_ssh" == true ]] && security_args+=("--skip-ssh")
    security_args+=(--ssh-port "$ssh_port" "$ssh_port":SSH 443:XRAY)
    if [[ -n "$panel_port" ]]; then
        security_args+=("$panel_port:3X-UI Panel")
    fi
    if [[ "$is_selfsteal" == true ]]; then
        security_args+=(80:Caddy-ACME)
    fi
    setup_security "${security_args[@]}"
    if [[ "$is_hysteria" == true ]]; then
        local hy_port hy_port_end
        hy_port=$(grep -oP '(?<=^listen: :)\d+' "$HYSTERIA_CONFIG") || true
        hy_port_end=$(grep '^listen:' "$HYSTERIA_CONFIG" | grep -oP '(?<=-)\d+$') || true
        if [[ -n "$hy_port" && -n "$hy_port_end" ]]; then
            ufw allow "${hy_port}:${hy_port_end}/udp" comment "Hysteria2" > /dev/null 2>&1 || true
        fi
    fi
    if [[ "$is_tuic" == true ]]; then
        local tuic_port
        tuic_port=$(jq -r '.server' /etc/tuic/config.json 2>/dev/null | cut -d: -f2) || true
        if [[ -n "$tuic_port" ]]; then
            ufw allow "${tuic_port}/udp" comment "TUIC" > /dev/null 2>&1 || true
        fi
    fi

    # --- Step 7: Update exit-server-info.txt ---
    local server_ip
    server_ip=$(curl -s4 --max-time 5 ifconfig.me 2>/dev/null) || server_ip="<not detected>"

    install -m 0600 /dev/null /root/exit-server-info.txt
    cat > /root/exit-server-info.txt << EOF
EXIT_IP=$server_ip
EXIT_PORT=$listen_port
EXIT_UUID=$uuid
EXIT_PUBLIC_KEY=$public_key
EXIT_SHORT_ID=$short_id
EXIT_SERVER_NAME=$server_name
EOF
    if [[ "$warp_enabled" == "Y" ]]; then
        echo "WARP_ENABLED=Y" >> /root/exit-server-info.txt
    fi

    if [[ "$is_cdn" == true ]]; then
        # Read CDN domain from Caddyfile
        local cdn_domain=""
        cdn_domain=$(grep -oP '(?<=https://)\S+(?= \{)' /etc/caddy/Caddyfile 2>/dev/null | grep -v "$server_name" | head -1) || true
        if [[ -n "$cdn_domain" ]]; then
            cat >> /root/exit-server-info.txt << EOF
CDN_DOMAIN=$cdn_domain
CDN_PATH=$cdn_path
CDN_PORT=$cdn_port
EOF
        fi
    fi

    if [[ "$is_hysteria" == true ]]; then
        local hy_port hy_port_end hy_obfs
        hy_port=$(grep -oP '(?<=^listen: :)\d+' "$HYSTERIA_CONFIG") || true
        hy_port_end=$(grep '^listen:' "$HYSTERIA_CONFIG" | grep -oP '(?<=-)\d+$') || true
        hy_obfs=$(grep -A2 'salamander:' "$HYSTERIA_CONFIG" | grep 'password:' | sed 's/.*password: *"\?\([^"]*\)"\?/\1/') || true
        if [[ -n "$hy_port" ]]; then
            cat >> /root/exit-server-info.txt << EOF
HYSTERIA_PORT=$hy_port
HYSTERIA_PORT_END=$hy_port_end
HYSTERIA_OBFS=$hy_obfs
EOF
        fi
    fi

    # --- Step 8: Verify ---
    # selfcheck может вернуть 1 при FAIL — не abort'им апдейт, "Done" банер должен напечататься
    "$SCRIPT_DIR/selfcheck.sh" || true

    # --- Done ---
    echo ""
    echo "==========================================="
    log_ok "EXIT server update complete!"
    echo "==========================================="
    echo ""
    echo "  Config updated from latest codebase"
    if [[ "$upgrade" == true ]]; then
        echo "  Binaries upgraded (XRAY/Caddy to latest; 3X-UI/TUIC pinned versions re-verified; AmneziaWG via apt)"
    fi
    echo "  Security re-applied"
    if [[ "$warp_enabled" == "Y" ]]; then
        echo "  WARP outbound:        enabled (AI services)"
    fi
    echo ""
    echo "  Next: run 'update-relay' on every relay within ~30s to minimise"
    echo "        outage for relay-routed clients (see issue #33)."
    echo ""
}

LOG_FILE="/var/log/vpn-setup-$(basename "$0" .sh)-$(date +%Y%m%d-%H%M%S).log"
main "$@" 2>&1 | tee "$LOG_FILE"
exit "${PIPESTATUS[0]}"
