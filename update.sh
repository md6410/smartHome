#!/bin/bash
# =====================================================================
# smartHome - ONE-COMMAND UPDATE
#
#   smarthome-update            pull the latest main and restart
#   smarthome-update --rollback go back to the version before the last update
#   smarthome-update --status   show the running version and services
#   smarthome-update --restart  restart the services on the current code
#
# (or: bash ~/smartHome/update.sh ...)
#
# What it does, in order:
#   1. puts local edits aside (git stash) so the pull cannot fail on them
#   2. pulls the branch, fast-forward only
#   3. installs Python packages again only if requirements.txt changed
#   4. compiles every .py file - a syntax error never reaches the services
#   5. keeps the Caddy boot fix (systemd drop-in) in place
#   6. restarts the services and checks each one answers
#   7. if anything in 4-6 fails, puts the previous version back by itself
# =====================================================================

# Everything lives in main() so bash has read the whole script before
# git pull replaces this file underneath it.
main() {
set -Eeuo pipefail
FORCE_RESTART=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; NC='\033[0m'
say()  { echo -e "${CYAN}$*${NC}"; }
ok()   { echo -e "${GREEN}  ok  $*${NC}"; }
warn() { echo -e "${YELLOW}  !   $*${NC}"; }
die()  { echo -e "${RED}x $*${NC}" >&2; exit 1; }

[[ $EUID -eq 0 ]] && die "Don't run as root. Run: smarthome-update"

SRC_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
cd "$SRC_DIR"
BRANCH="${SMARTHOME_BRANCH:-main}"
LINK=/usr/local/bin/smarthome-update
STATE_DIR=/var/lib/smarthome
MANIFEST="$STATE_DIR/manifest"
PREV_FILE="$SRC_DIR/instance/.previous_version"
# The commit the services were last restarted on. A pull alone does not
# change what is running, so this is compared with HEAD, not origin.
DEPLOYED_FILE="$SRC_DIR/instance/.deployed_version"
DROPIN=/etc/systemd/system/caddy.service.d/smarthome.conf

# Services this checkout runs, the port each listens on, a URL it must
# answer, and the script it runs
SERVICES=(smarthome chatserver proxyctl)
declare -A PORT=([smarthome]=5000 [chatserver]=5554 [proxyctl]=8090)
declare -A HEALTH=(
    [smarthome]="http://127.0.0.1:5000/login"
    [chatserver]="http://127.0.0.1:5554/login"
    [proxyctl]="http://127.0.0.1:8090/"
)
declare -A SCRIPT=([smarthome]=app.py [chatserver]=chatServer.py [proxyctl]=proxy_manager.py)

installed() { systemctl list-unit-files "$1.service" 2>/dev/null | grep -q "^$1.service"; }

# ---------------------------------------------------------------------
show_status() {
    echo -e "${MAGENTA}smartHome${NC}  $(git log -1 --format='%h  %cd  %s' --date=format:'%Y-%m-%d %H:%M')"
    for s in "${SERVICES[@]}" caddy; do
        installed "$s" || continue
        if systemctl is-active --quiet "$s"; then ok "$s running"; else warn "$s $(systemctl is-active "$s" || true)"; fi
    done
}

compile_check() {
    local out
    out="$(find . -name '*.py' -not -path './.git/*' -not -path '*/venv/*' -print0 \
           | xargs -0 python3 -c '
import sys
bad = 0
for f in sys.argv[1:]:
    try:
        with open(f, "rb") as fh:
            compile(fh.read(), f, "exec")
    except SyntaxError as e:
        print(f"{e.filename}:{e.lineno}: {e.msg}"); bad = 1
sys.exit(bad)' 2>&1)" || { echo "$out"; return 1; }
}

# PID of whatever listens on a TCP port, empty if nothing does
port_pid() { sudo ss -ltnpH "sport = :$1" 2>/dev/null | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2; }

# True when the service itself (or its child) listens on its port, or
# when the port owner cannot be read at all
owned_by_service() {   # owned_by_service <service>
    local main pid p
    pid="$(port_pid "${PORT[$1]}")"
    [[ -z "$pid" ]] && return 0
    main="$(systemctl show -p MainPID --value "$1" 2>/dev/null || echo 0)"
    p="$pid"
    while [[ -n "$p" && "$p" != 0 && "$p" != 1 ]]; do
        [[ "$p" == "$main" ]] && return 0
        p="$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' ')"
    done
    return 1
}

# A copy of the app started by hand (python3 app.py) keeps the port, the
# service cannot bind it, and the page you see is still the old one.
free_port_from_strays() {   # free_port_from_strays <service>
    local s="$1" port="${PORT[$1]}" pid args
    owned_by_service "$s" && return 0
    pid="$(port_pid "$port")"
    args="$(ps -o args= -p "$pid" 2>/dev/null || true)"
    if [[ "$args" == *"${SCRIPT[$s]}"* ]]; then
        warn "an old copy of ${SCRIPT[$s]} outside systemd holds port $port (pid $pid) - stopping it"
        sudo kill "$pid" 2>/dev/null || true
        for _ in $(seq 1 10); do ps -p "$pid" >/dev/null 2>&1 || break; sleep 1; done
        if ps -p "$pid" >/dev/null 2>&1; then sudo kill -9 "$pid" 2>/dev/null || true; fi
        return 1    # restart the service so it takes the port
    fi
    warn "port $port is held by another program (pid $pid: $args)"
    warn "$s cannot start until it is stopped"
    return 0
}

restart_and_check() {
    local s url failed=0
    for s in "${SERVICES[@]}"; do
        installed "$s" || continue
        sudo systemctl restart "$s"
    done
    sleep 2
    for s in "${SERVICES[@]}"; do
        installed "$s" || continue
        free_port_from_strays "$s" || sudo systemctl restart "$s"
    done
    # app.py loads OpenCV, which takes a while on a Pi
    for s in "${SERVICES[@]}"; do
        installed "$s" || continue
        url="${HEALTH[$s]}"
        for _ in $(seq 1 40); do
            # The port must belong to the service itself - a stray old copy
            # answering the URL does not count
            if systemctl is-active --quiet "$s" && curl -fs -o /dev/null --max-time 3 "$url" \
               && owned_by_service "$s"; then
                ok "$s is up"; continue 2
            fi
            sleep 1
        done
        warn "$s did not come up - last log lines:"
        sudo journalctl -u "$s" -n 25 --no-pager || true
        failed=1
    done
    if installed caddy; then
        if systemctl is-active --quiet caddy; then ok "caddy is up"; else warn "caddy is $(systemctl is-active caddy || true)"; fi
    fi
    return $failed
}

go_back_to() {   # go_back_to <commit> <reason>
    echo
    warn "$2 - going back to $(git log -1 --format='%h %s' "$1")"
    git reset -q --hard "$1"
    restart_and_check || die "The previous version does not start either. Send the log above."
    mark_deployed
    die "Update undone. Nothing changed. Send the output above to fix it."
}

mark_deployed() { mkdir -p "$SRC_DIR/instance"; git rev-parse HEAD > "$DEPLOYED_FILE"; }

ensure_link() {
    [[ "$(readlink -f "$LINK" 2>/dev/null)" == "$SRC_DIR/update.sh" ]] && return
    sudo ln -sf "$SRC_DIR/update.sh" "$LINK"
    if [[ -f "$MANIFEST" ]]; then echo "file:$LINK" | sudo tee -a "$MANIFEST" >/dev/null; fi
    ok "from now on just type: smarthome-update"
}

ensure_caddy_dropin() {
    installed caddy || return 0
    local want
    want="$(cat <<'EOF'
[Unit]
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0

[Service]
ExecStartPre=+/bin/sh -c 'mkdir -p /var/log/caddy && touch /var/log/caddy/access.log && chown -R caddy:caddy /var/log/caddy && chmod 755 /var/log/caddy && chmod 644 /var/log/caddy/access.log'
Restart=on-failure
RestartSec=5
EOF
)"
    [[ "$(cat "$DROPIN" 2>/dev/null)" == "$want" ]] && return 0
    sudo mkdir -p "$(dirname "$DROPIN")"
    echo "$want" | sudo tee "$DROPIN" >/dev/null
    if [[ -f "$MANIFEST" ]]; then echo "file:$DROPIN" | sudo tee -a "$MANIFEST" >/dev/null; fi
    sudo systemctl daemon-reload
    sudo systemctl restart caddy || true
    ok "caddy boot fix installed"
}

# ---------------------------------------------------------------------
case "${1:-}" in
    --status) show_status; exit 0 ;;
    --rollback)
        [[ -f "$PREV_FILE" ]] || die "No earlier version recorded yet."
        PREV="$(cat "$PREV_FILE")"
        say "Going back to $(git log -1 --format='%h  %s' "$PREV")"
        git checkout -q "$BRANCH" 2>/dev/null || true
        git reset -q --hard "$PREV"
        restart_and_check || die "Rolled back, but a service did not start. Send the log above."
        mark_deployed
        ok "rolled back. Run smarthome-update to come forward again."
        exit 0 ;;
    -h|--help) sed -n '2,21p' "$0"; exit 0 ;;
    --restart) FORCE_RESTART=1 ;;
    "") ;;
    *) die "Unknown option: $1  (try --help)" ;;
esac

echo -e "${MAGENTA}smartHome update${NC}"
echo "======================================"
ensure_link

# ---------------------------------------------------------------------
say "[1/5] Fetching"
OLD="$(git rev-parse HEAD)"
git fetch -q origin "$BRANCH" || die "Could not reach GitHub. Check the internet connection and try again."
NEW="$(git rev-parse "origin/$BRANCH")"

if [[ "$OLD" == "$NEW" ]]; then
    ok "code is already the latest ($(git log -1 --format='%h %s'))"
    ensure_caddy_dropin
    # Pulled by hand, or a restart that never happened: the code on disk
    # is new but the services still run the old one from memory.
    if [[ "${FORCE_RESTART:-0}" == 1 || "$(cat "$DEPLOYED_FILE" 2>/dev/null)" != "$OLD" ]]; then
        warn "the running services may be older than this code - restarting them"
        compile_check || die "The code on disk has a syntax error - services left as they are."
        restart_and_check || die "A service did not start. Send the output above."
        mark_deployed
        ok "services now run $(git log -1 --format='%h')"
        echo "  Refresh the page on your phone to load the new version."
    else
        show_status
    fi
    exit 0
fi

echo "  current: $(git log -1 --format='%h  %s' "$OLD")"
echo "  new:"
git log --format='           %h  %s' "$OLD..$NEW" | head -15

# ---------------------------------------------------------------------
say "[2/5] Updating the code"
if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
    git stash push -q -m "smarthome-update $(date +%Y%m%d-%H%M%S)"
    warn "local edits put aside (see them with: git stash list)"
fi
git checkout -q "$BRANCH" 2>/dev/null || git checkout -q -B "$BRANCH" "origin/$BRANCH"
if ! git merge -q --ff-only "origin/$BRANCH"; then
    die "This copy has its own commits that are not on GitHub - update by hand with: git pull origin $BRANCH"
fi
mkdir -p "$SRC_DIR/instance"
echo "$OLD" > "$PREV_FILE"
ok "now at $(git log -1 --format='%h  %s')"

# ---------------------------------------------------------------------
say "[3/5] Python packages"
if git diff --quiet "$OLD" HEAD -- requirements.txt; then
    ok "requirements.txt unchanged - skipped"
else
    if pip3 install --break-system-packages --dry-run pip >/dev/null 2>&1; then PIPFLAG="--break-system-packages"; else PIPFLAG=""; fi
    # shellcheck disable=SC2086
    pip3 install $PIPFLAG -r requirements.txt || go_back_to "$OLD" "Package install failed"
    ok "packages installed"
fi

# ---------------------------------------------------------------------
say "[4/5] Checking the code"
compile_check || go_back_to "$OLD" "The new code has a syntax error"
ok "all Python files compile"
ensure_caddy_dropin

# ---------------------------------------------------------------------
say "[5/5] Restarting"
restart_and_check || go_back_to "$OLD" "A service did not start"
mark_deployed

echo
echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}  Updated to $(git log -1 --format='%h')${NC}"
echo -e "${GREEN}==============================================${NC}"
echo "  Undo with: smarthome-update --rollback"
echo "  Refresh the page on your phone to load the new version."
exit 0
}

main "$@"
