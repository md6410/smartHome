#!/usr/bin/env python3
"""
proxyctl - reverse proxy manager for the smartHome Raspberry Pi.

Owns /etc/caddy/Caddyfile completely. Routes public hostnames to internal
ports, gets HTTPS certificates automatically, and logs every request.

Lives at smartHome/proxy/ and runs as its own service on :8090.
It shares no code and no database with the smartHome apps.

Run:  sudo python3 proxy_manager.py
UI:   http://<pi-ip>:8090
"""

import os
import re
import json
import time
import sqlite3
import threading
import subprocess
from datetime import datetime
import shutil
import zipfile
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, jsonify, Response, send_from_directory

# =======================================================================
# CONFIGURATION
# =======================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CADDYFILE = os.environ.get("PROXYCTL_CADDYFILE", "/etc/caddy/Caddyfile")
ACCESS_LOG = os.environ.get("PROXYCTL_ACCESS_LOG", "/var/log/caddy/access.log")
DB_PATH = os.path.join(BASE_DIR, "proxyctl.db")
LISTEN_PORT = int(os.environ.get("PROXYCTL_PORT", "8090"))

# Default place for websites served from disk. The panel can change this;
# the stored setting wins, and this is only the starting value.
DEFAULT_WEBROOT = os.environ.get("PROXYCTL_WEBROOT", "/var/www")

# Serving any of these over the web would hand out system files, so they are
# refused as a website root no matter what is typed.
FORBIDDEN_ROOTS = {
    "/", "/etc", "/root", "/boot", "/proc", "/sys", "/dev", "/run",
    "/bin", "/sbin", "/lib", "/usr", "/var", "/var/log", "/home", "/tmp",
}

# DRY_RUN=1 writes to ./dryrun/Caddyfile and never touches the real service.
DRY_RUN = os.environ.get("PROXYCTL_DRY_RUN", "0") == "1"
if DRY_RUN:
    os.makedirs(os.path.join(BASE_DIR, "dryrun"), exist_ok=True)
    CADDYFILE = os.path.join(BASE_DIR, "dryrun", "Caddyfile")

LOG_FIELDS = [
    "time", "source_ip", "domain", "server_port", "scheme", "method",
    "path", "protocol", "status", "bytes_sent", "request_time",
    "upstream", "upstream_status", "user_agent", "referer", "xff",
]

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024   # 512 MB per upload

# =======================================================================
# DATABASE
# =======================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS routes (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    domain       TEXT    NOT NULL UNIQUE,
    route_type   TEXT    NOT NULL DEFAULT 'proxy',   -- proxy | static
    target_host  TEXT    NOT NULL DEFAULT '127.0.0.1',
    target_port  INTEGER NOT NULL DEFAULT 0,
    root_dir     TEXT    NOT NULL DEFAULT '',
    index_files  TEXT    NOT NULL DEFAULT 'index.html index.htm',
    browse       INTEGER NOT NULL DEFAULT 0,
    spa          INTEGER NOT NULL DEFAULT 0,
    listen_http  INTEGER NOT NULL DEFAULT 1,
    listen_https INTEGER NOT NULL DEFAULT 1,
    force_https  INTEGER NOT NULL DEFAULT 1,
    tls_mode     TEXT    NOT NULL DEFAULT 'auto',   -- auto | internal | custom | off
    ssl_cert     TEXT    NOT NULL DEFAULT '',
    ssl_key      TEXT    NOT NULL DEFAULT '',
    websockets   INTEGER NOT NULL DEFAULT 1,
    extra_ports  TEXT    NOT NULL DEFAULT '',
    max_body_mb  INTEGER NOT NULL DEFAULT 64,
    allow_cidrs  TEXT    NOT NULL DEFAULT '',
    enabled      INTEGER NOT NULL DEFAULT 1,
    note         TEXT    NOT NULL DEFAULT '',
    created_at   TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL
);
"""

DEFAULT_SETTINGS = {
    "log_max_mb": "50",
    "log_keep_percent": "50",
    "log_enabled": "1",
    "trim_interval_sec": "60",
    "acme_email": "",
    "fallback_port": "",      # catch-all for requests with no matching domain
    "trusted_proxies": "",    # CDN ranges whose X-Forwarded-For we believe
    "webroot": DEFAULT_WEBROOT,
}

# The four smartHome services, imported on first run so the panel starts
# with working routes. install.sh passes the domain you chose; set
# PROXYCTL_SEED_DOMAIN to an empty string to start with no routes at all.
SEED_DOMAIN = os.environ.get("PROXYCTL_SEED_DOMAIN", "turingco.ir").strip().strip(".")

SEED_ROUTES = [
    (f"home.{SEED_DOMAIN}",         5000, "smart home control"),
    (f"uploadserver.{SEED_DOMAIN}", 8000, "upload server"),
    (f"firmware.{SEED_DOMAIN}",     5001, "firmware server"),
    (f"chat.{SEED_DOMAIN}",         5554, "chat server"),
] if SEED_DOMAIN else []


def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


NEW_COLUMNS = [
    ("route_type", "TEXT NOT NULL DEFAULT 'proxy'"),
    ("root_dir", "TEXT NOT NULL DEFAULT ''"),
    ("index_files", "TEXT NOT NULL DEFAULT 'index.html index.htm'"),
    ("browse", "INTEGER NOT NULL DEFAULT 0"),
    ("spa", "INTEGER NOT NULL DEFAULT 0"),
]


def init_db():
    conn = db()
    conn.executescript(SCHEMA)
    # Databases made by earlier versions predate the static-site columns.
    have = {r["name"] for r in conn.execute("PRAGMA table_info(routes)")}
    for name, decl in NEW_COLUMNS:
        if name not in have:
            conn.execute(f"ALTER TABLE routes ADD COLUMN {name} {decl}")
    conn.commit()
    for k, v in DEFAULT_SETTINGS.items():
        conn.execute("INSERT OR IGNORE INTO settings (key,value) VALUES (?,?)", (k, v))
    conn.commit()

    # First run only: import the routes for the four smartHome services.
    # The marker makes this run exactly once, so clearing every route or
    # emptying the fallback port survives a restart.
    seeded = conn.execute("SELECT value FROM settings WHERE key='seeded'").fetchone()
    if not seeded:
        conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('seeded','1')")
        now = datetime.now().isoformat(timespec="seconds")
        for domain, port, note in SEED_ROUTES:
            conn.execute(
                "INSERT INTO routes (domain,target_port,note,created_at,updated_at) "
                "VALUES (?,?,?,?,?)", (domain, port, note, now, now))
        conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('fallback_port','5000')")
        conn.commit()
    conn.close()


def get_settings():
    conn = db()
    rows = conn.execute("SELECT key,value FROM settings").fetchall()
    conn.close()
    out = dict(DEFAULT_SETTINGS)
    out.update({r["key"]: r["value"] for r in rows})
    return out


def give_to_caddy(path):
    """Caddy serves as its own user, so uploaded files must be readable by it."""
    try:
        import pwd, grp
        uid, gid = pwd.getpwnam("caddy").pw_uid, grp.getgrnam("caddy").gr_gid
    except (KeyError, ImportError):
        return
    try:
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                os.chown(root, uid, gid)
                os.chmod(root, 0o755)
                for f in files:
                    fp = os.path.join(root, f)
                    os.chown(fp, uid, gid)
                    os.chmod(fp, 0o644)
        else:
            os.chown(path, uid, gid)
            os.chmod(path, 0o644)
    except (PermissionError, OSError):
        pass


def get_webroot():
    return get_settings().get("webroot") or DEFAULT_WEBROOT


def check_webroot(path):
    """Validate a candidate website root. Returns (resolved, error)."""
    path = (path or "").strip()
    if not path.startswith("/"):
        return None, "Use a full path starting with /."
    if ".." in path.split("/"):
        return None, "The path cannot contain '..'."
    p = os.path.realpath(path).rstrip("/") or "/"
    if p in FORBIDDEN_ROOTS:
        return None, f"{p} holds system files and cannot be used for websites."
    if os.path.exists(p) and not os.path.isdir(p):
        return None, f"{p} is a file, not a folder."
    return p, None


def audit(action, detail=""):
    conn = db()
    conn.execute("INSERT INTO audit (ts,action,detail) VALUES (?,?,?)",
                 (datetime.now().isoformat(timespec="seconds"), action, detail))
    conn.commit()
    conn.close()


# =======================================================================
# VALIDATION
# =======================================================================

DOMAIN_RE = re.compile(r"^(\*\.)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
HOST_RE = re.compile(r"^[a-zA-Z0-9._-]+$")
CIDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")
TLS_MODES = ("auto", "internal", "custom", "off")


def safe_webroot(path, allow=None):
    """Resolve a folder and refuse anything outside the website root.

    `allow` lets a route keep a folder it already points at, so changing the
    website root later does not make existing routes uneditable.
    """
    if not path:
        return None, "Pick a folder to serve."
    webroot = get_webroot()
    p = os.path.realpath(path if path.startswith("/") else os.path.join(webroot, path))
    if allow and p == os.path.realpath(allow):
        return p, None
    root = os.path.realpath(webroot)
    if p != root and not p.startswith(root + os.sep):
        return None, f"The folder must be inside {webroot}."
    return p, None


def validate_route(d, route_id=None):
    domain = (d.get("domain") or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain):
        return None, f"'{domain}' is not a valid domain. Use example.com or *.example.com."

    route_type = (d.get("route_type") or "proxy").strip()
    if route_type not in ("proxy", "static"):
        return None, "Pick whether this domain goes to a port or a folder."

    host, port, root_dir = "127.0.0.1", 0, ""

    if route_type == "proxy":
        host = (d.get("target_host") or "127.0.0.1").strip()
        if not HOST_RE.match(host):
            return None, f"'{host}' is not a valid target host."
        try:
            port = int(d.get("target_port"))
        except (TypeError, ValueError):
            return None, "Target port must be a number."
        if not 1 <= port <= 65535:
            return None, "Target port must be between 1 and 65535."
        if port == LISTEN_PORT and host in ("127.0.0.1", "localhost"):
            return None, f"Port {LISTEN_PORT} is this control panel. Pick a different target."
    else:
        existing = None
        if route_id:
            conn = db()
            row = conn.execute("SELECT root_dir FROM routes WHERE id=?", (route_id,)).fetchone()
            conn.close()
            existing = row["root_dir"] if row else None
        root_dir, err = safe_webroot((d.get("root_dir") or "").strip(), allow=existing)
        if err:
            return None, err
        if not os.path.isdir(root_dir):
            return None, f"{root_dir} does not exist. Create the folder first."

    index_files = " ".join(
        f for f in (d.get("index_files") or "index.html index.htm").split()
        if re.match(r"^[A-Za-z0-9._-]+$", f)) or "index.html index.htm"

    extra = []
    for c in (d.get("extra_ports") or "").replace(" ", "").split(","):
        if not c:
            continue
        if not c.isdigit() or not 1 <= int(c) <= 65535:
            return None, f"'{c}' is not a valid listen port."
        if int(c) in (80, 443, LISTEN_PORT):
            return None, f"Port {c} is already handled. Use the checkboxes instead."
        extra.append(c)

    cidrs = []
    for c in (d.get("allow_cidrs") or "").replace(" ", "").split(","):
        if not c:
            continue
        if not CIDR_RE.match(c):
            return None, f"'{c}' is not a valid IP or CIDR range."
        cidrs.append(c)

    tls_mode = (d.get("tls_mode") or "auto").strip()
    if tls_mode not in TLS_MODES:
        return None, "Pick a valid certificate mode."

    cert = (d.get("ssl_cert") or "").strip()
    key = (d.get("ssl_key") or "").strip()
    listen_https = int(bool(d.get("listen_https")))
    if listen_https and tls_mode == "custom":
        if not cert or not key:
            return None, "A custom certificate needs both a certificate and a key path."
        for p in (cert, key):
            if ".." in p or not p.startswith("/"):
                return None, f"'{p}' must be an absolute path."

    listen_http = int(bool(d.get("listen_http")))
    if not listen_http and not listen_https and not extra:
        return None, "Pick at least one port to listen on."

    try:
        body_mb = int(d.get("max_body_mb") or 64)
    except ValueError:
        return None, "Max upload size must be a number."
    if not 1 <= body_mb <= 10240:
        return None, "Max upload size must be between 1 and 10240 MB."

    conn = db()
    q = ("SELECT id FROM routes WHERE domain=? AND id!=?", (domain, route_id)) if route_id \
        else ("SELECT id FROM routes WHERE domain=?", (domain,))
    row = conn.execute(*q).fetchone()
    conn.close()
    if row:
        return None, f"{domain} is already routed. Edit that entry instead."

    return {
        "domain": domain, "route_type": route_type,
        "target_host": host, "target_port": port,
        "root_dir": root_dir, "index_files": index_files,
        "browse": int(bool(d.get("browse"))), "spa": int(bool(d.get("spa"))),
        "listen_http": listen_http, "listen_https": listen_https,
        "force_https": int(bool(d.get("force_https"))),
        "tls_mode": tls_mode, "ssl_cert": cert, "ssl_key": key,
        "websockets": int(bool(d.get("websockets"))),
        "extra_ports": ",".join(extra), "max_body_mb": body_mb,
        "allow_cidrs": ",".join(cidrs), "enabled": int(bool(d.get("enabled"))),
        "note": (d.get("note") or "").strip()[:200],
    }, None


# =======================================================================
# CADDYFILE GENERATION
# =======================================================================

def site_addresses(r):
    """Caddy site addresses for one route.

    Bare 'example.com'      -> HTTPS on 443, Caddy auto-redirects 80 -> 443
    'http://example.com'    -> plain HTTP on 80, no certificate
    'http://example.com:N'  -> extra ports, always plain HTTP
    """
    addrs = []
    https = r["listen_https"] and r["tls_mode"] != "off"
    if https:
        addrs.append(r["domain"])
        if r["listen_http"] and not r["force_https"]:
            addrs.append(f"http://{r['domain']}")
    elif r["listen_http"]:
        addrs.append(f"http://{r['domain']}")
    for p in (r["extra_ports"] or "").split(","):
        if p:
            addrs.append(f"http://{r['domain']}:{p}")
    return addrs


def render_site(r):
    """One Caddy site block."""
    L = []
    if r["note"]:
        L.append(f"# {r['note']}")
    L.append(", ".join(site_addresses(r)) + " {")

    if r["listen_https"]:
        if r["tls_mode"] == "internal":
            L.append("\ttls internal")
        elif r["tls_mode"] == "custom":
            L.append(f"\ttls {r['ssl_cert']} {r['ssl_key']}")
        # 'auto' needs no directive - Caddy gets a certificate by itself.

    if r["allow_cidrs"]:
        L.append("\t@denied not remote_ip " + " ".join(r["allow_cidrs"].split(",")))
        L.append("\tabort @denied")

    L.append("\trequest_body {")
    L.append(f"\t\tmax_size {r['max_body_mb']}MB")
    L.append("\t}")

    L.append("\tlog {")
    L.append(f"\t\toutput file {ACCESS_LOG} {{")
    L.append("\t\t\troll_disabled")
    L.append("\t\t}")
    L.append("\t\tformat json")
    L.append("\t}")

    if r.get("route_type") == "static":
        L.append(f"\troot * {r['root_dir']}")
        if r.get("spa"):
            # Single-page apps route in the browser, so unknown paths must
            # fall back to the entry file rather than 404.
            L.append("\ttry_files {path} {path}/ /index.html")
        L.append("\tencode gzip zstd")
        idx = r.get("index_files") or "index.html index.htm"
        if r.get("browse"):
            L.append("\tfile_server browse {")
            L.append(f"\t\tindex {idx}")
            L.append("\t}")
        else:
            L.append("\tfile_server {")
            L.append(f"\t\tindex {idx}")
            L.append("\t}")
    else:
        L.append(f"\treverse_proxy {r['target_host']}:{r['target_port']} {{")
        L.append("\t\theader_up X-Real-IP {remote_host}")
        L.append("\t\tflush_interval -1")   # streaming: cameras, chat, SSE
        L.append("\t}")
    L.append("}")
    return "\n".join(L)


def render_caddyfile():
    s = get_settings()
    conn = db()
    routes = conn.execute("SELECT * FROM routes WHERE enabled=1 ORDER BY domain").fetchall()
    conn.close()

    out = [
        "# ---------------------------------------------------------------",
        "# Generated by proxyctl. Every edit here is lost on the next apply.",
        "# Change routes at http://<pi>:8090 instead.",
        f"# written {datetime.now().isoformat(timespec='seconds')}",
        "# ---------------------------------------------------------------",
    ]
    globals_ = []
    if s["acme_email"]:
        globals_.append(f"\temail {s['acme_email']}")
    proxies = [c for c in (s["trusted_proxies"] or "").replace(",", " ").split() if c]
    if proxies:
        # Behind a CDN every request arrives from an edge server. Trusting
        # these ranges lets Caddy read the real visitor IP from
        # X-Forwarded-For instead of logging the CDN.
        globals_ += ["\tservers {", "\t\ttrusted_proxies static " + " ".join(proxies), "\t}"]
    if globals_:
        out += ["{"] + globals_ + ["}"]

    for r in routes:
        out.append("")
        out.append(render_site(dict(r)))

    # Catch-all: anything arriving on :80 without a matching domain,
    # which is how the LAN reaches the Pi by IP address.
    if s["fallback_port"]:
        out += [
            "",
            "# Requests with no matching domain (LAN access by IP)",
            ":80 {",
            "\tlog {",
            f"\t\toutput file {ACCESS_LOG} {{",
            "\t\t\troll_disabled",
            "\t\t}",
            "\t\tformat json",
            "\t}",
            f"\treverse_proxy 127.0.0.1:{s['fallback_port']}",
            "}",
        ]
    return "\n".join(out) + "\n"


def run(cmd):
    if DRY_RUN:
        return True, f"[dry run] {' '.join(cmd)}"
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return p.returncode == 0, (p.stdout + p.stderr).strip()
    except FileNotFoundError:
        return False, f"{cmd[0]} is not installed."
    except subprocess.TimeoutExpired:
        return False, f"{cmd[0]} timed out."


def ensure_log_path():
    """Caddy runs as its own user and refuses a config it cannot log to.

    Create the directory and file up front and hand them to that user, so a
    fresh install or a rotated-away log never blocks a reload.
    """
    if DRY_RUN:
        return True, ""
    try:
        d = os.path.dirname(ACCESS_LOG)
        os.makedirs(d, exist_ok=True)
        if not os.path.exists(ACCESS_LOG):
            open(ACCESS_LOG, "a").close()
        import pwd, grp
        try:
            uid = pwd.getpwnam("caddy").pw_uid
            gid = grp.getgrnam("caddy").gr_gid
        except KeyError:
            return True, ""          # no caddy user; leave ownership alone
        os.chown(d, uid, gid)
        os.chown(ACCESS_LOG, uid, gid)
        os.chmod(d, 0o755)
        os.chmod(ACCESS_LOG, 0o644)
        return True, ""
    except PermissionError:
        return False, (f"Cannot prepare {ACCESS_LOG}. Run proxyctl as root, or fix it by hand:\n"
                       f"  sudo mkdir -p {os.path.dirname(ACCESS_LOG)}\n"
                       f"  sudo touch {ACCESS_LOG}\n"
                       f"  sudo chown -R caddy:caddy {os.path.dirname(ACCESS_LOG)}")
    except Exception as e:
        return False, f"Could not prepare the log file: {e}"


def apply_config():
    """Validate, write, reload. Rolls back on any failure."""
    ok, msg = ensure_log_path()
    if not ok:
        return False, msg

    body = render_caddyfile()
    tmp = CADDYFILE + ".proxyctl-new"
    backup = None
    if os.path.exists(CADDYFILE):
        with open(CADDYFILE) as f:
            backup = f.read()

    try:
        with open(tmp, "w") as f:
            f.write(body)

        ok, out = run(["caddy", "validate", "--config", tmp, "--adapter", "caddyfile"])
        if not ok:
            os.remove(tmp)
            return False, "Config rejected, nothing changed:\n" + out

        os.replace(tmp, CADDYFILE)
        ok, out = run(["systemctl", "reload", "caddy"])
        if not ok:
            # A reload that fails leaves the service wedged in 'reloading'.
            # A full restart is the only way back.
            ok, out2 = run(["systemctl", "restart", "caddy"])
            out = out + "\n" + out2
        if not ok:
            if backup is not None:
                with open(CADDYFILE, "w") as f:
                    f.write(backup)
                run(["systemctl", "reload", "caddy"])
            return False, "Reload failed, previous config restored:\n" + out

        conn = db()
        n = conn.execute("SELECT COUNT(*) c FROM routes WHERE enabled=1").fetchone()["c"]
        conn.close()
        audit("apply", f"{n} route(s)")
        return True, f"{n} route(s) live. Caddy reloaded."

    except PermissionError:
        return False, f"Permission denied writing {CADDYFILE}. Run proxyctl as root."
    except Exception as e:
        if os.path.exists(tmp):
            os.remove(tmp)
        return False, f"Apply failed: {e}"


# =======================================================================
# LOGS  (Caddy writes one JSON object per line)
# =======================================================================

def parse_log_line(line):
    try:
        j = json.loads(line)
    except (ValueError, TypeError):
        return None
    if j.get("logger") and "access" not in j.get("logger", ""):
        return None
    req = j.get("request", {}) or {}
    hdr = req.get("headers", {}) or {}
    tls = req.get("tls")
    host = req.get("host", "")
    domain, _, hport = host.partition(":")

    def h(name):
        v = hdr.get(name)
        return v[0] if isinstance(v, list) and v else ""

    ts = j.get("ts")
    try:
        when = datetime.fromtimestamp(float(ts)).isoformat(timespec="seconds")
    except (TypeError, ValueError):
        when = str(ts or "")

    up = ""
    for key in ("upstream", "upstream_addr"):
        if j.get(key):
            up = str(j[key])
            break

    return {
        "time": when,
        "source_ip": req.get("client_ip") or req.get("remote_ip") or "",
        "domain": domain,
        "server_port": hport or ("443" if tls else "80"),
        "scheme": "https" if tls else "http",
        "method": req.get("method", ""),
        "path": req.get("uri", ""),
        "protocol": req.get("proto", ""),
        "status": int(j.get("status") or 0),
        "bytes_sent": int(j.get("size") or 0),
        "request_time": j.get("duration") or 0,
        "upstream": up,
        "upstream_status": "",
        "user_agent": h("User-Agent"),
        "referer": h("Referer"),
        "xff": h("X-Forwarded-For"),
    }


def tail_lines(path, count):
    if not os.path.exists(path):
        return []
    size = os.path.getsize(path)
    data = b""
    with open(path, "rb") as f:
        pos = size
        while pos > 0 and data.count(b"\n") <= count:
            step = min(8192, pos)
            pos -= step
            f.seek(pos)
            data = f.read(step) + data
    return data.decode("utf-8", "replace").splitlines()[-count:]


def read_logs(limit=200, q="", domain="", status_class="", source_ip=""):
    # Caddy's access log does not record which upstream served the request,
    # so map it back from the route table.
    conn = db()
    upstream_of = {
        r["domain"]: f"{r['target_host']}:{r['target_port']}"
        for r in conn.execute("SELECT domain,target_host,target_port FROM routes")
    }
    conn.close()
    lines = tail_lines(ACCESS_LOG, max(limit * 6, 1200))
    out = []
    q = q.lower()
    for line in reversed(lines):
        rec = parse_log_line(line)
        if not rec:
            continue
        if domain and domain.lower() not in rec["domain"].lower():
            continue
        if source_ip and not rec["source_ip"].startswith(source_ip):
            continue
        if status_class and str(rec["status"] // 100) != status_class:
            continue
        if q and q not in line.lower():
            continue
        if not rec["upstream"]:
            rec["upstream"] = upstream_of.get(rec["domain"], "")
        out.append(rec)
        if len(out) >= limit:
            break
    return out


def trim_log():
    s = get_settings()
    cap = int(s["log_max_mb"]) * 1024 * 1024
    keep_pct = max(10, min(90, int(s["log_keep_percent"])))
    if not os.path.exists(ACCESS_LOG):
        return False
    size = os.path.getsize(ACCESS_LOG)
    if size <= cap:
        return False
    keep = int(cap * keep_pct / 100)
    with open(ACCESS_LOG, "rb") as f:
        f.seek(size - keep)
        f.readline()
        rest = f.read()
    tmp = ACCESS_LOG + ".trim"
    with open(tmp, "wb") as f:
        f.write(rest)
    os.replace(tmp, ACCESS_LOG)
    audit("log_trim", f"{size // 1048576}MB -> {len(rest) // 1048576}MB")
    return True


def trim_worker():
    while True:
        try:
            if get_settings()["log_enabled"] == "1":
                trim_log()
            time.sleep(int(get_settings()["trim_interval_sec"]))
        except Exception:
            time.sleep(60)


# =======================================================================
# API
# =======================================================================

@app.route("/")
def index():
    return render_template("proxy.html", dry_run=DRY_RUN, access_log=ACCESS_LOG,
                           caddyfile=CADDYFILE)


@app.get("/api/routes")
def api_list():
    conn = db()
    rows = conn.execute("SELECT * FROM routes ORDER BY enabled DESC, domain").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.post("/api/routes")
def api_create():
    clean, err = validate_route(request.json or {})
    if err:
        return jsonify({"ok": False, "error": err}), 400
    now = datetime.now().isoformat(timespec="seconds")
    cols = list(clean) + ["created_at", "updated_at"]
    vals = list(clean.values()) + [now, now]
    conn = db()
    cur = conn.execute(
        f"INSERT INTO routes ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", vals)
    conn.commit()
    rid = cur.lastrowid
    conn.close()
    audit("create", clean["domain"])
    return jsonify({"ok": True, "id": rid})


@app.put("/api/routes/<int:rid>")
def api_update(rid):
    clean, err = validate_route(request.json or {}, route_id=rid)
    if err:
        return jsonify({"ok": False, "error": err}), 400
    clean["updated_at"] = datetime.now().isoformat(timespec="seconds")
    conn = db()
    conn.execute(f"UPDATE routes SET {','.join(f'{k}=?' for k in clean)} WHERE id=?",
                 list(clean.values()) + [rid])
    conn.commit()
    conn.close()
    audit("update", clean["domain"])
    return jsonify({"ok": True})


@app.delete("/api/routes/<int:rid>")
def api_delete(rid):
    conn = db()
    row = conn.execute("SELECT domain FROM routes WHERE id=?", (rid,)).fetchone()
    conn.execute("DELETE FROM routes WHERE id=?", (rid,))
    conn.commit()
    conn.close()
    audit("delete", row["domain"] if row else str(rid))
    return jsonify({"ok": True})


@app.post("/api/routes/<int:rid>/toggle")
def api_toggle(rid):
    conn = db()
    conn.execute("UPDATE routes SET enabled = 1 - enabled WHERE id=?", (rid,))
    conn.commit()
    row = conn.execute("SELECT domain,enabled FROM routes WHERE id=?", (rid,)).fetchone()
    conn.close()
    audit("toggle", f"{row['domain']} -> {'on' if row['enabled'] else 'off'}")
    return jsonify({"ok": True, "enabled": row["enabled"]})


@app.get("/api/routes/<int:rid>/preview")
def api_preview(rid):
    conn = db()
    row = conn.execute("SELECT * FROM routes WHERE id=?", (rid,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"ok": False, "error": "No such route."}), 404
    return jsonify({"ok": True, "conf": render_site(dict(row))})


@app.get("/api/caddyfile")
def api_caddyfile():
    return jsonify({"ok": True, "conf": render_caddyfile()})


@app.post("/api/apply")
def api_apply():
    ok, msg = apply_config()
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 400)


@app.post("/api/test")
def api_test():
    tmp = os.path.join(BASE_DIR, ".caddyfile.check")
    with open(tmp, "w") as f:
        f.write(render_caddyfile())
    ok, out = run(["caddy", "validate", "--config", tmp, "--adapter", "caddyfile"])
    os.remove(tmp)
    return jsonify({"ok": ok, "message": out or "Config is valid."})


@app.get("/api/status")
def api_status():
    ok, out = run(["systemctl", "is-active", "caddy"])
    state = out.strip()
    conn = db()
    total = conn.execute("SELECT COUNT(*) c FROM routes").fetchone()["c"]
    live = conn.execute("SELECT COUNT(*) c FROM routes WHERE enabled=1").fetchone()["c"]
    conn.close()
    s = get_settings()
    return jsonify({
        "nginx_running": (state == "active") or DRY_RUN,
        "nginx_state": ("reload stuck - restart caddy" if state == "reloading" else state) or "unknown",
        "engine": "caddy",
        "routes_total": total, "routes_live": live,
        "log_bytes": os.path.getsize(ACCESS_LOG) if os.path.exists(ACCESS_LOG) else 0,
        "log_cap_bytes": int(s["log_max_mb"]) * 1024 * 1024,
        "dry_run": DRY_RUN,
    })


@app.get("/api/logs")
def api_logs():
    return jsonify(read_logs(
        limit=min(int(request.args.get("limit", 200)), 1000),
        q=request.args.get("q", ""), domain=request.args.get("domain", ""),
        status_class=request.args.get("status_class", ""),
        source_ip=request.args.get("source_ip", "")))


@app.get("/api/logs/export")
def api_logs_export():
    recs = read_logs(limit=1000, q=request.args.get("q", ""))
    rows = [",".join(LOG_FIELDS)] + [
        ",".join('"' + str(r[f]).replace('"', '""') + '"' for f in LOG_FIELDS) for r in recs]
    return Response("\n".join(rows), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=proxyctl_log.csv"})


@app.post("/api/logs/clear")
def api_logs_clear():
    try:
        open(ACCESS_LOG, "w").close()
        run(["systemctl", "reload", "caddy"])
        audit("log_clear", "")
        return jsonify({"ok": True, "message": "Log cleared."})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.get("/api/settings")
def api_get_settings():
    return jsonify(get_settings())


@app.post("/api/settings")
def api_set_settings():
    data = request.json or {}
    if "webroot" in data:
        p, err = check_webroot(data["webroot"])
        if err:
            return jsonify({"ok": False, "error": err}), 400
        try:
            os.makedirs(p, exist_ok=True)
            give_to_caddy(p) if os.path.isdir(p) else None
        except PermissionError:
            return jsonify({"ok": False,
                            "error": f"Cannot create {p}. Run proxyctl as root."}), 400
        except OSError as e:
            return jsonify({"ok": False, "error": f"Cannot use {p}: {e}"}), 400
        data["webroot"] = p
    if "trusted_proxies" in data:
        for c in str(data["trusted_proxies"]).replace(",", " ").split():
            if not re.match(r"^[0-9a-fA-F:.]+(/\d{1,3})?$", c):
                return jsonify({"ok": False,
                                "error": f"'{c}' is not a valid IP range."}), 400
    conn = db()
    for k, v in data.items():
        if k in DEFAULT_SETTINGS:
            conn.execute("INSERT INTO settings (key,value) VALUES (?,?) "
                         "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, str(v)))
    conn.commit()
    conn.close()
    audit("settings", json.dumps(data))
    trim_log()
    return jsonify({"ok": True, "settings": get_settings()})


@app.get("/api/folders")
def api_folders():
    """Folders available to serve, plus whether each has an entry file."""
    try:
        webroot = get_webroot()
        os.makedirs(webroot, exist_ok=True)
        out = []
        for name in sorted(os.listdir(webroot)):
            path = os.path.join(webroot, name)
            if not os.path.isdir(path):
                continue
            try:
                files = os.listdir(path)
            except OSError:
                files = []
            out.append({
                "name": name, "path": path,
                "has_index": any(f in files for f in ("index.html", "index.htm")),
                "file_count": len(files),
            })
        return jsonify({"ok": True, "webroot": webroot, "folders": out})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.post("/api/folders")
def api_folder_create():
    name = (request.json or {}).get("name", "").strip()
    if not re.match(r"^[A-Za-z0-9._-]{1,64}$", name):
        return jsonify({"ok": False, "error":
                        "Use letters, numbers, dots, dashes or underscores."}), 400
    path, err = safe_webroot(name)
    if err:
        return jsonify({"ok": False, "error": err}), 400
    try:
        os.makedirs(path, exist_ok=True)
        # Caddy runs as its own user and must be able to read the files.
        import pwd, grp
        try:
            os.chown(path, pwd.getpwnam("caddy").pw_uid, grp.getgrnam("caddy").gr_gid)
        except (KeyError, PermissionError):
            pass
        os.chmod(path, 0o755)
        audit("folder_create", path)
        return jsonify({"ok": True, "path": path})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


def folder_path(name):
    """Resolve a folder name from the panel, refusing anything outside the root."""
    if not re.match(r"^[A-Za-z0-9._-]{1,64}$", name or ""):
        return None, "That folder name is not allowed."
    path, err = safe_webroot(name)
    if err:
        return None, err
    if not os.path.isdir(path):
        return None, "That folder does not exist."
    return path, None


@app.get("/api/folders/<name>/files")
def api_folder_files(name):
    base, err = folder_path(name)
    if err:
        return jsonify({"ok": False, "error": err}), 400
    out = []
    for root, dirs, files in os.walk(base):
        for f in files:
            fp = os.path.join(root, f)
            try:
                out.append({"name": os.path.relpath(fp, base),
                            "size": os.path.getsize(fp)})
            except OSError:
                pass
        if len(out) > 2000:
            break
    out.sort(key=lambda x: x["name"])
    return jsonify({"ok": True, "folder": name, "path": base, "files": out,
                    "has_index": os.path.exists(os.path.join(base, "index.html"))})


@app.post("/api/folders/<name>/upload")
def api_folder_upload(name):
    """Accept files from the panel. A .zip is unpacked in place."""
    base, err = folder_path(name)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    files = request.files.getlist("files")
    if not files:
        return jsonify({"ok": False, "error": "No files were sent."}), 400

    saved, unpacked = 0, 0
    for f in files:
        # Browsers send a relative path for folder uploads; keep the structure
        # but rebuild it from sanitised parts so nothing escapes the folder.
        raw = f.filename or ""
        parts = [secure_filename(p) for p in raw.replace("\\", "/").split("/")
                 if p not in ("", ".", "..")]
        parts = [p for p in parts if p]
        if not parts:
            continue
        dest = os.path.join(base, *parts)
        if not os.path.realpath(dest).startswith(os.path.realpath(base) + os.sep):
            continue
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        f.save(dest)
        saved += 1

        if dest.lower().endswith(".zip"):
            try:
                with zipfile.ZipFile(dest) as z:
                    for member in z.namelist():
                        if member.endswith("/"):
                            continue
                        mparts = [secure_filename(p) for p in member.replace("\\", "/").split("/")
                                  if p not in ("", ".", "..")]
                        mparts = [p for p in mparts if p]
                        if not mparts:
                            continue
                        target = os.path.join(base, *mparts)
                        # Guard against archives containing ../ paths.
                        if not os.path.realpath(target).startswith(
                                os.path.realpath(base) + os.sep):
                            continue
                        os.makedirs(os.path.dirname(target), exist_ok=True)
                        with z.open(member) as src, open(target, "wb") as dst:
                            shutil.copyfileobj(src, dst)
                        unpacked += 1
                os.remove(dest)
                saved -= 1
            except zipfile.BadZipFile:
                return jsonify({"ok": False, "error": f"{parts[-1]} is not a valid zip."}), 400

    give_to_caddy(base)
    bits = []
    if saved:
        bits.append(f"{saved} file{'s' if saved != 1 else ''} uploaded")
    if unpacked:
        bits.append(f"{unpacked} file{'s' if unpacked != 1 else ''} unpacked")
    audit("upload", f"{name}: {', '.join(bits)}")
    return jsonify({"ok": True, "message": ". ".join(bits) or "Nothing to upload.",
                    "has_index": os.path.exists(os.path.join(base, "index.html"))})


@app.delete("/api/folders/<name>/files")
def api_folder_file_delete(name):
    base, err = folder_path(name)
    if err:
        return jsonify({"ok": False, "error": err}), 400
    rel = (request.args.get("file") or "").strip()
    target = os.path.realpath(os.path.join(base, rel))
    if not target.startswith(os.path.realpath(base) + os.sep):
        return jsonify({"ok": False, "error": "That file is outside the folder."}), 400
    try:
        os.remove(target)
        audit("file_delete", f"{name}/{rel}")
        return jsonify({"ok": True})
    except OSError as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.delete("/api/folders/<name>")
def api_folder_delete(name):
    base, err = folder_path(name)
    if err:
        return jsonify({"ok": False, "error": err}), 400
    conn = db()
    used = conn.execute("SELECT domain FROM routes WHERE root_dir=?", (base,)).fetchone()
    conn.close()
    if used:
        return jsonify({"ok": False,
                        "error": f"{used['domain']} still serves this folder. "
                                 "Remove that route first."}), 400
    try:
        shutil.rmtree(base)
        audit("folder_delete", base)
        return jsonify({"ok": True})
    except OSError as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.get("/api/audit")
def api_audit():
    conn = db()
    rows = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    init_db()
    threading.Thread(target=trim_worker, daemon=True).start()
    print(f" * proxyctl on http://0.0.0.0:{LISTEN_PORT}  (caddy, dry_run={DRY_RUN})")
    app.run(host="0.0.0.0", port=LISTEN_PORT, threaded=True)
