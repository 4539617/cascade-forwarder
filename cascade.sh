#!/usr/bin/env bash

set -euo pipefail

# =========================================================
# Simple Cascade Forwarder
# Safe DNAT/Port Forwarding Manager
# =========================================================

# ---------------- COLORS ----------------

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# ---------------- ROOT CHECK ----------------

check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo -e "${RED}[ERROR] Run as root${NC}"
        exit 1
    fi
}

# ---------------- VALIDATION ----------------

validate_ip() {
    local ip=$1

    [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1

    IFS='.' read -r o1 o2 o3 o4 <<< "$ip"

    for octet in "$o1" "$o2" "$o3" "$o4"; do
        ((octet >= 0 && octet <= 255)) || return 1
    done

    return 0
}

validate_port() {
    local port=$1

    [[ "$port" =~ ^[0-9]+$ ]] || return 1
    ((port >= 1 && port <= 65535))
}

# ---------------- SYSTEM PREP ----------------

prepare_system() {

    echo -e "${CYAN}[*] Preparing system...${NC}"

    export DEBIAN_FRONTEND=noninteractive

    apt-get update -y >/dev/null

    apt-get install -y \
        iptables \
        iptables-persistent \
        netfilter-persistent \
        iproute2 >/dev/null

    # Enable IP Forwarding
    sysctl -w net.ipv4.ip_forward=1 >/dev/null

    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi

    # Enable BBR
    sysctl -w net.core.default_qdisc=fq >/dev/null
    sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null

    grep -q "^net.core.default_qdisc=fq" /etc/sysctl.conf || \
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf

    grep -q "^net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf || \
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf

    echo -e "${GREEN}[OK] System prepared${NC}"
}

# ---------------- INTERFACE DETECT ----------------

detect_interface() {

    local iface

    iface=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $5}' | head -n1)

    if [[ -z "$iface" ]]; then
        echo -e "${RED}[ERROR] Cannot detect network interface${NC}"
        exit 1
    fi

    echo "$iface"
}

# ---------------- IPTABLES HELPERS ----------------

iptables_add() {

    if ! iptables "$@" -C 2>/dev/null; then
        iptables "$@" -A
    fi
}

rule_exists() {
    iptables "$@" -C >/dev/null 2>&1
}

# ---------------- APPLY RULES ----------------

apply_rule() {

    local proto="$1"
    local in_port="$2"
    local out_port="$3"
    local target_ip="$4"

    local iface
    iface=$(detect_interface)

    echo -e "${CYAN}[*] Applying rules...${NC}"

    # INPUT
    iptables -C INPUT -p "$proto" --dport "$in_port" -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -p "$proto" --dport "$in_port" -j ACCEPT

    # DNAT
    iptables -t nat -C PREROUTING \
        -p "$proto" \
        --dport "$in_port" \
        -j DNAT \
        --to-destination "$target_ip:$out_port" 2>/dev/null || \
    iptables -t nat -A PREROUTING \
        -p "$proto" \
        --dport "$in_port" \
        -j DNAT \
        --to-destination "$target_ip:$out_port"

    # MASQUERADE
    iptables -t nat -C POSTROUTING \
        -o "$iface" \
        -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING \
        -o "$iface" \
        -j MASQUERADE

    # FORWARD
    iptables -C FORWARD \
        -p "$proto" \
        -d "$target_ip" \
        --dport "$out_port" \
        -m conntrack \
        --ctstate NEW,ESTABLISHED,RELATED \
        -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD \
        -p "$proto" \
        -d "$target_ip" \
        --dport "$out_port" \
        -m conntrack \
        --ctstate NEW,ESTABLISHED,RELATED \
        -j ACCEPT

    iptables -C FORWARD \
        -p "$proto" \
        -s "$target_ip" \
        --sport "$out_port" \
        -m conntrack \
        --ctstate ESTABLISHED,RELATED \
        -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD \
        -p "$proto" \
        -s "$target_ip" \
        --sport "$out_port" \
        -m conntrack \
        --ctstate ESTABLISHED,RELATED \
        -j ACCEPT

    netfilter-persistent save >/dev/null

    echo -e "${GREEN}[OK] Rule added${NC}"
    echo ""
    echo "Protocol : $proto"
    echo "Incoming : $in_port"
    echo "Target   : $target_ip:$out_port"
    echo ""
}

# ---------------- CONFIGURE RULE ----------------

configure_rule() {

    local proto="$1"

    clear

    echo -e "${MAGENTA}=== Configure Forwarding ===${NC}"
    echo ""

    while true; do
        read -rp "Target IP: " target_ip

        if validate_ip "$target_ip"; then
            break
        fi

        echo -e "${RED}Invalid IP${NC}"
    done

    while true; do
        read -rp "Incoming Port: " in_port

        if validate_port "$in_port"; then
            break
        fi

        echo -e "${RED}Invalid port${NC}"
    done

    while true; do
        read -rp "Outgoing Port: " out_port

        if validate_port "$out_port"; then
            break
        fi

        echo -e "${RED}Invalid port${NC}"
    done

    # Check if port already used
    if ss -tulpn | grep -q ":$in_port "; then
        echo -e "${YELLOW}[WARN] Port already in use${NC}"
    fi

    apply_rule "$proto" "$in_port" "$out_port" "$target_ip"

    read -rp "Press Enter..."
}

# ---------------- LIST RULES ----------------

list_rules() {

    clear

    echo -e "${MAGENTA}=== Active Rules ===${NC}"
    echo ""

    echo -e "${CYAN}PORT\tPROTO\tDESTINATION${NC}"

    iptables -t nat -S PREROUTING | grep DNAT | while read -r line; do

        local port
        local proto
        local dest

        port=$(echo "$line" | grep -oP '(?<=--dport )\d+')
        proto=$(echo "$line" | grep -oP '(?<=-p )\w+')
        dest=$(echo "$line" | grep -oP '(?<=--to-destination )[\d\.:]+')

        echo -e "$port\t$proto\t$dest"
    done

    echo ""

    read -rp "Press Enter..."
}

# ---------------- DELETE RULE ----------------

delete_rule() {

    clear

    echo -e "${MAGENTA}=== Delete Rule ===${NC}"
    echo ""

    declare -a rules

    local index=1

    while read -r line; do

        local port
        local proto
        local dest

        port=$(echo "$line" | grep -oP '(?<=--dport )\d+')
        proto=$(echo "$line" | grep -oP '(?<=-p )\w+')
        dest=$(echo "$line" | grep -oP '(?<=--to-destination )[\d\.:]+')

        if [[ -n "$port" ]]; then

            rules[$index]="$port:$proto:$dest"

            echo "[$index] $proto $port -> $dest"

            ((index++))
        fi

    done < <(iptables -t nat -S PREROUTING | grep DNAT)

    if [[ ${#rules[@]} -eq 0 ]]; then
        echo ""
        echo -e "${RED}No rules found${NC}"
        read -rp "Press Enter..."
        return
    fi

    echo ""

    read -rp "Rule number: " choice

    [[ -n "${rules[$choice]:-}" ]] || return

    IFS=':' read -r port proto dest <<< "${rules[$choice]}"

    target_ip="${dest%:*}"
    target_port="${dest#*:}"

    iptables -t nat -D PREROUTING \
        -p "$proto" \
        --dport "$port" \
        -j DNAT \
        --to-destination "$dest"

    iptables -D INPUT \
        -p "$proto" \
        --dport "$port" \
        -j ACCEPT

    iptables -D FORWARD \
        -p "$proto" \
        -d "$target_ip" \
        --dport "$target_port" \
        -m conntrack \
        --ctstate NEW,ESTABLISHED,RELATED \
        -j ACCEPT

    iptables -D FORWARD \
        -p "$proto" \
        -s "$target_ip" \
        --sport "$target_port" \
        -m conntrack \
        --ctstate ESTABLISHED,RELATED \
        -j ACCEPT

    netfilter-persistent save >/dev/null

    echo ""
    echo -e "${GREEN}[OK] Rule removed${NC}"

    read -rp "Press Enter..."
}

# ---------------- FLUSH ----------------

flush_rules() {

    clear

    echo -e "${RED}WARNING!${NC}"
    echo "This will remove ALL iptables rules."
    echo ""

    iptables-save > ~/iptables-backup.rules

    echo "Backup saved:"
    echo "~/iptables-backup.rules"
    echo ""

    read -rp "Continue? (yes/no): " confirm

    [[ "$confirm" == "yes" ]] || return

    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT

    iptables -F
    iptables -X

    iptables -t nat -F
    iptables -t nat -X

    iptables -t mangle -F
    iptables -t mangle -X

    netfilter-persistent save >/dev/null

    echo ""
    echo -e "${GREEN}[OK] All rules removed${NC}"

    read -rp "Press Enter..."
}

# ---------------- MENU ----------------

show_menu() {

    while true; do

        clear

        echo -e "${MAGENTA}"
        echo "======================================"
        echo "      CASCADE FORWARDING MANAGER"
        echo "======================================"
        echo -e "${NC}"

        echo "1) WireGuard / AmneziaWG (UDP)"
        echo "2) VLESS / XRay (TCP)"
        echo "3) MTProto / TProxy (TCP)"
        echo "4) Custom TCP Rule"
        echo "5) Custom UDP Rule"
        echo "6) List Rules"
        echo "7) Delete Rule"
        echo "8) Flush ALL Rules"
        echo "0) Exit"

        echo ""

        read -rp "Select: " choice

        case "$choice" in
            1)
                configure_rule "udp"
                ;;
            2)
                configure_rule "tcp"
                ;;
            3)
                configure_rule "tcp"
                ;;
            4)
                configure_rule "tcp"
                ;;
            5)
                configure_rule "udp"
                ;;
            6)
                list_rules
                ;;
            7)
                delete_rule
                ;;
            8)
                flush_rules
                ;;
            0)
                exit 0
                ;;
        esac
    done
}

# ---------------- START ----------------

check_root
prepare_system
show_menu