#!/bin/bash
# AmneziaWG — obfuscated WireGuard (kernel module + awg/awg-quick CLI).
#
# Why this is worth having alongside the TLS-based channels (Reality,
# CDN, Hysteria2, TUIC): it is a *different protocol family*, not another
# TLS handshake wrapper. Every other channel in this repo does a real or
# faked TLS handshake somewhere on the wire; a censor that fingerprints
# TLS ClientHello shapes specifically (including uTLS/fingerprint=chrome
# emulation) has nothing to key on here, because there is no TLS at all —
# obfuscation happens at the UDP-packet level via junk packets and header
# permutation (Jc/Jmin/Jmax, H1-H4, S1/S2 parameters).
#
# Deliberately NOT wired into 3X-UI: 3X-UI only manages XRAY inbounds/
# clients through XRAY's own API — WireGuard-family peers are not an XRAY
# concept, so there is no "add a client, get it in the app's subscription
# list" path here the way there is for VLESS/Hysteria2/TUIC. Client
# delivery is a plain .conf file (+ QR code the operator generates from
# it), same as every other AmneziaWG/WireGuard deployment in the wild.
#
# Upstream: https://github.com/amnezia-vpn/amneziawg-linux-kernel-module
# Installed via the project's own Ubuntu PPA (ppa:amnezia/ppa) + DKMS,
# exactly as documented upstream — see install_amneziawg() for why this
# step can legitimately fail on some VPS kernels, and why that must not
# be treated as a fatal error for the rest of setup.

source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

AWG_DIR="/etc/amnezia/amneziawg"
AWG_CONFIG="${AWG_DIR}/awg0.conf"
AWG_CLIENT_DIR="/root/amneziawg-clients"
AWG_STATE="${AWG_DIR}/.setup-state"  # egress iface + subnet, read back by uninstall/update

install_amneziawg() {
    log_info "Installing AmneziaWG (kernel module via DKMS)..."

    if command -v awg &>/dev/null && command -v awg-quick &>/dev/null; then
        log_info "awg/awg-quick already present, skipping install"
        return 0
    fi

    # DKMS needs headers matching the RUNNING kernel. On stock Ubuntu
    # cloud images this package exists; on some VPS providers' custom or
    # hardened kernels it does not, and this apt-get is where that shows
    # up — the caller is expected to treat a non-zero return as "skip
    # AmneziaWG", not as a reason to abort the whole exit setup.
    if ! apt-get install -y -qq \
        software-properties-common python3-launchpadlib gnupg2 \
        "linux-headers-$(uname -r)" > /dev/null 2>&1; then
        log_error "AmneziaWG: linux-headers-$(uname -r) not available for this kernel"
        log_error "DKMS cannot build the kernel module without matching headers — skipping"
        return 1
    fi

    if ! add-apt-repository -y ppa:amnezia/ppa > /dev/null 2>&1; then
        log_error "AmneziaWG: failed to add ppa:amnezia/ppa"
        return 1
    fi
    apt-get update -qq

    if ! apt-get install -y -qq amneziawg > /dev/null 2>&1; then
        log_error "AmneziaWG: package install failed (DKMS build likely failed — see: dkms status)"
        return 1
    fi

    if command -v awg &>/dev/null && command -v awg-quick &>/dev/null; then
        log_ok "AmneziaWG installed: $(awg --version 2>/dev/null | head -1)"
    else
        log_error "AmneziaWG installation reported success but awg/awg-quick not found"
        return 1
    fi
}

# Recommended parameter bounds are from the upstream README (kernel-module
# repo, "Configuration" section). Randomized per-install, same reasoning as
# generate_random_port()/generate_short_id() elsewhere: fixed defaults
# across every install of a given installer script become their own
# fingerprint, which defeats the point of an obfuscation layer.
_awg_rand_in() {
    local min="$1" max="$2"
    echo $(( min + RANDOM % (max - min + 1) ))
}

configure_amneziawg() {
    local port="$1"

    log_info "Configuring AmneziaWG..."

    local egress_iface
    egress_iface=$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')
    if [[ -z "$egress_iface" ]]; then
        log_error "AmneziaWG: could not detect default egress interface"
        return 1
    fi

    mkdir -p "$AWG_DIR" "$AWG_CLIENT_DIR"
    chmod 700 "$AWG_DIR" "$AWG_CLIENT_DIR"

    # Randomized /24 subnet — avoids the common 10.0.0.0/10.66.66.0-style
    # defaults that show up identically across thousands of guide-following
    # installs and are themselves a soft fingerprint of "this is a VPN box".
    local subnet_b subnet_c
    subnet_b=$(_awg_rand_in 16 250)
    subnet_c=$(_awg_rand_in 1 254)
    local server_addr="10.${subnet_b}.${subnet_c}.1"
    local client_addr="10.${subnet_b}.${subnet_c}.2"

    local server_privkey server_pubkey client_privkey client_pubkey
    server_privkey=$(awg genkey)
    server_pubkey=$(echo "$server_privkey" | awg pubkey)
    client_privkey=$(awg genkey)
    client_pubkey=$(echo "$client_privkey" | awg pubkey)

    # Obfuscation parameters — bounds per upstream README:
    #   Jc 1..128 (rec. 4-12), Jmin < Jmax <= 1280 (rec. 8 / 80),
    #   S1 <= 1132, S2 <= 1188, S1+56 != S2 (rec. 15-150 each),
    #   H1-H4 unique, 5..2147483647.
    local jc jmin jmax s1 s2 h1 h2 h3 h4
    jc=$(_awg_rand_in 4 12)
    jmin=$(_awg_rand_in 8 40)
    jmax=$(_awg_rand_in $((jmin + 200)) 1270)
    s1=$(_awg_rand_in 15 150)
    s2=$(_awg_rand_in 15 150)
    [[ $((s1 + 56)) -eq "$s2" ]] && s2=$((s2 + 1))  # avoid the one disallowed collision
    h1=$(_awg_rand_in 5 2147483647)
    h2=$(_awg_rand_in 5 2147483647)
    h3=$(_awg_rand_in 5 2147483647)
    h4=$(_awg_rand_in 5 2147483647)
    # Re-roll on collision — vanishingly unlikely in this range, but the
    # protocol requires H1-H4 pairwise-unique, so guard it explicitly.
    while [[ "$h1" == "$h2" || "$h1" == "$h3" || "$h1" == "$h4" || \
             "$h2" == "$h3" || "$h2" == "$h4" || "$h3" == "$h4" ]]; do
        h2=$(_awg_rand_in 5 2147483647)
        h3=$(_awg_rand_in 5 2147483647)
        h4=$(_awg_rand_in 5 2147483647)
    done

    install -m 0600 /dev/null "$AWG_CONFIG"
    cat > "$AWG_CONFIG" << WGEOF
[Interface]
PrivateKey = ${server_privkey}
Address = ${server_addr}/24
ListenPort = ${port}
Jc = ${jc}
Jmin = ${jmin}
Jmax = ${jmax}
S1 = ${s1}
S2 = ${s2}
H1 = ${h1}
H2 = ${h2}
H3 = ${h3}
H4 = ${h4}
PostUp = iptables -A FORWARD -i awg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o ${egress_iface} -j MASQUERADE
PostDown = iptables -D FORWARD -i awg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o ${egress_iface} -j MASQUERADE

[Peer]
# default client — see ${AWG_CLIENT_DIR}/default.conf
PublicKey = ${client_pubkey}
AllowedIPs = ${client_addr}/32
WGEOF

    # awg-quick needs the config directory itself locked down (WireGuard's
    # own convention — it refuses to run otherwise on some builds).
    chmod 600 "$AWG_CONFIG"

    # net.ipv4.ip_forward — same sysctl.d drop-in pattern as enable_bbr().
    cat > /etc/sysctl.d/99-vpn-amneziawg-forward.conf << 'SYSCTL'
net.ipv4.ip_forward=1
SYSCTL
    sysctl --system > /dev/null 2>&1 || true

    # Persist what uninstall/future updates need without re-deriving it.
    printf 'EGRESS_IFACE=%s\nSUBNET=10.%s.%s.0/24\n' \
        "$egress_iface" "$subnet_b" "$subnet_c" > "$AWG_STATE"

    install -m 0600 /dev/null "${AWG_CLIENT_DIR}/default.conf"
    cat > "${AWG_CLIENT_DIR}/default.conf" << CLIENTEOF
[Interface]
PrivateKey = ${client_privkey}
Address = ${client_addr}/32
DNS = 1.1.1.1
Jc = ${jc}
Jmin = ${jmin}
Jmax = ${jmax}
S1 = ${s1}
S2 = ${s2}
H1 = ${h1}
H2 = ${h2}
H3 = ${h3}
H4 = ${h4}

[Peer]
PublicKey = ${server_pubkey}
Endpoint = SERVER_IP_PLACEHOLDER:${port}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
CLIENTEOF

    # Fill in the real IP now that the config exists (kept as a separate
    # step so the heredoc above stays free of a live network call).
    local server_ip
    server_ip=$(curl -s4 --max-time 5 ifconfig.me 2>/dev/null) || server_ip=""
    if [[ -n "$server_ip" ]]; then
        sed -i "s/SERVER_IP_PLACEHOLDER/${server_ip}/" "${AWG_CLIENT_DIR}/default.conf"
    else
        log_warn "Could not detect public IP — edit Endpoint= in ${AWG_CLIENT_DIR}/default.conf manually"
    fi

    export AMNEZIAWG_SERVER_PUBKEY="$server_pubkey"
    log_ok "AmneziaWG configured: interface awg0, subnet 10.${subnet_b}.${subnet_c}.0/24"
    log_ok "Default client config: ${AWG_CLIENT_DIR}/default.conf"
}

restart_amneziawg() {
    systemctl restart "awg-quick@awg0"
    systemctl enable "awg-quick@awg0"

    if systemctl is-active --quiet "awg-quick@awg0"; then
        log_ok "AmneziaWG is running (interface awg0)"
        return 0
    else
        log_error "AmneziaWG failed to start. Check: journalctl -u awg-quick@awg0"
        return 1
    fi
}

uninstall_amneziawg() {
    local purge="${1:-false}"

    log_info "Removing AmneziaWG..."
    systemctl stop "awg-quick@awg0" 2>/dev/null || true
    systemctl disable "awg-quick@awg0" 2>/dev/null || true
    rm -rf "$AWG_DIR" 2>/dev/null || true
    rm -rf "$AWG_CLIENT_DIR" 2>/dev/null || true
    rm -f /etc/sysctl.d/99-vpn-amneziawg-forward.conf 2>/dev/null || true

    if [[ "$purge" == true ]]; then
        DEBIAN_FRONTEND=noninteractive apt-get purge -y amneziawg amneziawg-dkms 2>/dev/null || true
        add-apt-repository -y --remove ppa:amnezia/ppa 2>/dev/null || true
        log_ok "AmneziaWG removed (package + kernel module purged)"
    else
        log_info "AmneziaWG package/kernel module preserved (use --purge-amneziawg to remove)"
    fi
}
