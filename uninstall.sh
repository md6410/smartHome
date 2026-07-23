#!/bin/bash
# =====================================================================
# smartHome - COMPLETE UNINSTALLER
#
# Reads /var/lib/smarthome/manifest and reverses exactly what
# install.sh created: services, unit files, firewall rules, ACLs,
# group memberships, the Caddy package and its apt source.
#
#   cd smartHome && bash uninstall.sh
#
# Anything that existed before the install is left alone. Caddy is only
# removed if install.sh was the one that installed it, and the original
# Caddyfile is put back if there was one.
#
# Content you made - websites, uploads, the chat database, the route
# database - is only deleted if you ask for it, one prompt at a time.
#
#   --dry-run   show what would happen, change nothing
#   --purge     also delete all of that content, no prompts
# =====================================================================

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; NC='\033[0m'

say()  { echo -e "${CYAN}$*${NC}"; }
ok()   { echo -e "${GREEN}  ok  $*${NC}"; }
warn() { echo -e "${YELLOW}  !   $*${NC}"; }
die()  { echo -e "${RED}x $*${NC}" >&2; exit 1; }

DRY=0; PURGE=0
for a in "$@"; do
    case "$a" in
        --dry-run) DRY=1 ;;
        --purge)   PURGE=1 ;;
        -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
        *) die "Unknown option: $a" ;;
    esac
done

[[ $EUID -eq 0 ]] && die "Don't run as root. Run: bash uninstall.sh"
command -v sudo >/dev/null || die "sudo is required."

STATE_DIR="/var/lib/smarthome"
MANIFEST="$STATE_DIR/manifest"

run() {  # run <description> <command...>
    local desc="$1"; shift
    if [[ $DRY -eq 1 ]]; then
        echo -e "${YELLOW}  would: $desc${NC}"
    else
        "$@" >/dev/null 2>&1 && ok "$desc" || warn "$desc (skipped)"
    fi
}

ask() {  # ask <question> -> 0 for yes
    [[ $PURGE -eq 1 ]] && return 0
    [[ $DRY   -eq 1 ]] && return 1
    local reply
    read -rp "$1 (y/n): " -n 1 -r reply; echo
    [[ $reply =~ ^[Yy]$ ]]
}

# ---------------------------------------------------------------------
# Read the manifest
# ---------------------------------------------------------------------
if [[ ! -f "$MANIFEST" ]]; then
    warn "No manifest at $MANIFEST."
    echo "Either smartHome was never installed by install.sh, or it was already removed."
    ask "Remove the standard services and files anyway?" || exit 0
    MANIFEST=""
fi

vals() {  # vals <type>  -> every value recorded under that type
    [[ -n "$MANIFEST" ]] || return 0
    sudo grep "^$1:" "$MANIFEST" 2>/dev/null | sed "s/^$1://" | awk '!seen[$0]++'
}

INSTALL_DIR="$(vals meta | grep '^install_dir=' | tail -1 | cut -d= -f2-)"
WEBROOT="$(vals meta | grep '^webroot=' | tail -1 | cut -d= -f2-)"
BACKUP_DIR="$(vals meta | grep '^backup=' | tail -1 | cut -d= -f2-)"
INSTALL_DIR="${INSTALL_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"

echo -e "${MAGENTA}smartHome - uninstall${NC}"
echo "======================================"
[[ $DRY   -eq 1 ]] && echo -e "${YELLOW}Dry run - nothing will be changed.${NC}"
[[ $PURGE -eq 1 ]] && echo -e "${RED}Purge - your content will be deleted without asking.${NC}"
echo "  Install folder: $INSTALL_DIR"
echo "  Website folder: ${WEBROOT:-not recorded}"
echo "  Backups:        ${BACKUP_DIR:-none}"
echo
echo "This removes the services, unit files, firewall rules and panel."
echo
if [[ $DRY -eq 0 ]]; then
    read -rp "Continue? (y/n): " -n 1 -r; echo
    [[ $REPLY =~ ^[Yy]$ ]] || exit 1
fi

# ---------------------------------------------------------------------
# 1. Stop and disable services
# ---------------------------------------------------------------------
say "[1/9] Services"
SERVICES="$(vals service)"
[[ -z "$SERVICES" ]] && SERVICES="smarthome.service chatserver.service proxyctl.service smarthome-group.target"
for s in $SERVICES; do
    systemctl list-unit-files 2>/dev/null | grep -q "^$s" || continue
    run "stopped $s"    sudo systemctl stop "$s"
    run "disabled $s"   sudo systemctl disable "$s"
done

# The upload and firmware servers are started as child processes by
# app.py rather than by systemd, so systemctl never sees them.
for p in uploadServer.py firmware_server-3.py firmware_server.py; do
    pgrep -f "$p" >/dev/null 2>&1 && run "stopped stray $p" sudo pkill -f "$p"
done

# ---------------------------------------------------------------------
# 2. Unit files
# ---------------------------------------------------------------------
say "[2/9] Unit files"
FILES="$(vals file)"
[[ -z "$FILES" ]] && FILES="/etc/systemd/system/smarthome.service
/etc/systemd/system/chatserver.service
/etc/systemd/system/proxyctl.service
/etc/systemd/system/smarthome-group.target"
while read -r f; do
    [[ -n "$f" && -e "$f" ]] || continue
    case "$f" in
        /etc/systemd/system/*|/etc/apt/sources.list.d/*|/usr/share/keyrings/*)
            run "removed $f" sudo rm -f "$f" ;;
        *) warn "left $f in place (not a file this uninstaller manages)" ;;
    esac
done <<< "$FILES"
run "reloaded systemd" sudo systemctl daemon-reload

# ---------------------------------------------------------------------
# 3. Caddy configuration
# ---------------------------------------------------------------------
say "[3/9] Caddy configuration"
if [[ -n "$BACKUP_DIR" && -f "$BACKUP_DIR/Caddyfile.orig" ]]; then
    if ask "  Restore the Caddyfile that existed before the install?"; then
        run "restored /etc/caddy/Caddyfile" sudo cp "$BACKUP_DIR/Caddyfile.orig" /etc/caddy/Caddyfile
        run "reloaded caddy" sudo systemctl reload caddy
    else
        run "removed the generated Caddyfile" sudo rm -f /etc/caddy/Caddyfile
    fi
elif [[ -f /etc/caddy/Caddyfile ]] && sudo grep -q "Generated by proxyctl" /etc/caddy/Caddyfile 2>/dev/null; then
    run "removed the generated Caddyfile" sudo rm -f /etc/caddy/Caddyfile
else
    warn "Caddyfile was not written by this installer - left alone"
fi

# ---------------------------------------------------------------------
# 4. Caddy package - only if install.sh added it
# ---------------------------------------------------------------------
say "[4/9] Caddy package"
if vals pkg | grep -qx caddy; then
    if ask "  Caddy was installed by install.sh. Remove it?"; then
        run "stopped caddy"    sudo systemctl stop caddy
        run "disabled caddy"   sudo systemctl disable caddy
        run "removed caddy"    sudo apt-get remove -y -qq caddy
        run "autoremoved deps" sudo apt-get autoremove -y -qq
        run "refreshed apt"    sudo apt-get update -y -qq
    else
        ok "keeping caddy"
    fi
else
    ok "Caddy predates this install - left alone"
fi

# ---------------------------------------------------------------------
# 5. Firewall
# ---------------------------------------------------------------------
say "[5/9] Firewall"
if command -v ufw >/dev/null; then
    while read -r r; do
        [[ -n "$r" ]] || continue
        # 22, 80 and 443 are almost certainly wanted by something else
        case "$r" in 22/tcp|80/tcp|443/tcp) warn "kept $r - other services likely need it"; continue ;; esac
        run "deleted allow $r" sudo ufw delete allow "$r"
    done <<< "$(vals ufw)"

    while read -r r; do
        [[ -n "$r" ]] || continue
        cidr="${r%%|*}"; port="${r##*|}"
        run "deleted allow from $cidr to $port" \
            sudo ufw delete allow from "$cidr" to any port "$port" proto tcp
    done <<< "$(vals ufw_from)"

    if vals ufw_enabled | grep -qx 1; then
        warn "ufw was enabled by the installer - left enabled (disable with: sudo ufw disable)"
    fi
else
    ok "ufw not present"
fi

# ---------------------------------------------------------------------
# 6. ACLs and group memberships
# ---------------------------------------------------------------------
say "[6/9] Permissions"
while read -r p; do
    [[ -n "$p" && -e "$p" ]] || continue
    run "removed caddy traverse ACL on $p" sudo setfacl -x u:caddy "$p"
done <<< "$(vals acl)"

USER_REC="$(vals meta | grep '^user=' | tail -1 | cut -d= -f2-)"
USER_REC="${USER_REC:-$(whoami)}"
while read -r g; do
    [[ -n "$g" ]] || continue
    run "removed $USER_REC from group $g" sudo gpasswd -d "$USER_REC" "$g"
done <<< "$(vals group)"

# nginx was only stopped, never removed - offer it back
while read -r s; do
    [[ -n "$s" ]] || continue
    if ask "  $s was disabled to free port 80. Re-enable it?"; then
        run "re-enabled $s" sudo systemctl enable --now "$s"
    fi
done <<< "$(vals disabled_service)"

# ---------------------------------------------------------------------
# 7. Panel data
# ---------------------------------------------------------------------
say "[7/9] Panel data"
for f in "$INSTALL_DIR/proxy/proxyctl.db" "$INSTALL_DIR/proxy/dryrun"; do
    [[ -e "$f" ]] || continue
    if ask "  Delete $f (your routes and settings)?"; then
        run "removed $f" sudo rm -rf "$f"
    fi
done

if [[ -d /var/log/caddy ]]; then
    if ask "  Delete /var/log/caddy (the request log)?"; then
        run "removed /var/log/caddy" sudo rm -rf /var/log/caddy
    fi
fi

# ---------------------------------------------------------------------
# 8. Your content
# ---------------------------------------------------------------------
say "[8/9] Your content"
if [[ -n "$WEBROOT" && -d "$WEBROOT" ]]; then
    COUNT="$(sudo find "$WEBROOT" -type f 2>/dev/null | wc -l)"
    if ask "  Delete $WEBROOT and the $COUNT website files in it?"; then
        run "removed $WEBROOT" sudo rm -rf "$WEBROOT"
    else
        ok "kept $WEBROOT"
    fi
fi

for d in "$INSTALL_DIR/uploads" "$INSTALL_DIR/logs" "$INSTALL_DIR/instance"; do
    [[ -d "$d" ]] || continue
    if ask "  Delete $d?"; then
        run "removed $d" sudo rm -rf "$d"
    fi
done

# Anything else the manifest recorded as ours and nothing above covered.
# The state directory is deliberately left for the last step.
while read -r d; do
    [[ -n "$d" && -d "$d" ]] || continue
    case "$d" in
        "$STATE_DIR"|"$WEBROOT"|/var/log/caddy) continue ;;
        "$INSTALL_DIR/uploads"|"$INSTALL_DIR/logs"|"$INSTALL_DIR/instance") continue ;;
    esac
    if ask "  Delete $d?"; then
        run "removed $d" sudo rm -rf "$d"
    fi
done <<< "$(vals dir)"

# ---------------------------------------------------------------------
# 9. Installer state
# ---------------------------------------------------------------------
say "[9/9] Installer state"
if [[ -d "$STATE_DIR" ]]; then
    echo "  Backups taken during install are in $STATE_DIR."
    if ask "  Delete $STATE_DIR, including those backups?"; then
        run "removed $STATE_DIR" sudo rm -rf "$STATE_DIR"
    else
        ok "kept $STATE_DIR"
    fi
fi

echo
if [[ $DRY -eq 1 ]]; then
    echo -e "${YELLOW}Dry run finished - nothing was changed.${NC}"
else
    echo -e "${GREEN}==============================================${NC}"
    echo -e "${GREEN}  Uninstall complete${NC}"
    echo -e "${GREEN}==============================================${NC}"
    echo
    echo "The project folder itself is still here:"
    echo "  $INSTALL_DIR"
    echo "Remove it when you're ready:  rm -rf $INSTALL_DIR"
    echo
    echo "Group changes take effect after: sudo reboot"
fi
echo
