# smartHome

Home automation server for the Raspberry Pi: control, chat, file upload and
firmware OTA, sitting behind a reverse proxy you manage from a web panel.

| Service | Port | Started by |
|---|---|---|
| Smart home control (`app.py`) | 5000 | systemd |
| Chat server (`chatServer.py`) | 5554 | systemd |
| Upload server (`uploadServer.py`) | 8000 | dashboard toggle |
| Firmware server (`firmware_server-3.py`) | 5001 | dashboard toggle |
| **proxyctl** routing panel (`proxy/`) | 8090 | systemd |
| Caddy | 80, 443 | systemd |

---

## Install

On a fresh Raspberry Pi OS:

```bash
git clone https://github.com/md6410/smartHome.git
cd smartHome
bash install.sh
```

It asks three questions — your base domain, an email for Let's Encrypt, and
where static websites should live — then does everything else: packages,
Python libraries, Caddy, all four services, the routing panel, permissions
and the firewall.

Remove it all again with:

```bash
bash uninstall.sh
```

---

## The routing panel

Open `http://<pi-ip>:8090`.

This is the piece that decides where a request goes. When something arrives
on port 80, 443, or any extra port you name, Caddy reads the `Host` header
and the panel's rules send it to the right port on the Pi.

**Routes.** Each route maps a domain to a target. Two kinds:

- **Proxy** — forward to a host and port, e.g. `chat.example.com` → `127.0.0.1:5554`
- **Static** — serve files from a folder under your website root, with
  optional directory browsing and single-page-app fallback

Per route you can set TLS (automatic Let's Encrypt, Caddy's internal CA, your
own certificate files, or off), an HTTP→HTTPS redirect, WebSocket support,
a maximum upload size, an IP or CIDR allow-list, extra listening ports, and
an enable/disable switch. The **Config** button shows the exact Caddy block
before it goes live.

**Apply is atomic.** It writes the new config, validates it, and reloads only
if validation passes — otherwise the previous config is restored. A bad route
cannot take the Pi offline.

**Request log.** Time, source IP, domain, port, scheme, method, path, status,
bytes, response time, upstream, user agent, referer and `X-Forwarded-For`.
Filter by any field, refresh live, export to CSV. Set the maximum log size in
MB under Settings; a background thread trims the oldest entries once the cap
is reached.

**Websites.** Upload files or whole folders straight into your website root
from the Files tab. Uploaded files are handed to the `caddy` user
automatically, which is the usual reason a static site returns 403.

`/etc/caddy/Caddyfile` is generated. Every apply overwrites it, so make
changes in the panel, not in the file.

---

## DNS

Point A records at your public IP:

```
home          → your public IP
chat          → your public IP
uploadserver  → your public IP
firmware      → your public IP
```

Behind Cloudflare or Arvan, set SSL mode to **Full** (not Flexible, which
causes redirect loops, and not Full (strict) until a real certificate exists).

Behind any CDN, every request appears to come from an edge server. Paste the
CDN's IP ranges into **Settings → Trusted proxies** so the log records the
real visitor IP from `X-Forwarded-For` instead of the CDN.

If a domain uses automatic Let's Encrypt while a CDN is in front of it, the
certificate challenge can fail before the first certificate exists. Turn off
the HTTP→HTTPS redirect for that route until it issues.

---

## After installing

```bash
systemctl status proxyctl caddy smarthome --no-pager
journalctl -u proxyctl -f
curl -I -H 'Host: home.example.com' http://127.0.0.1/
```

Start and stop everything together:

```bash
sudo systemctl start smarthome-group.target
sudo systemctl stop  smarthome-group.target
```

The upload and firmware servers are launched by `app.py` from the dashboard,
not by systemd, so they won't appear in `systemctl`.

---

## Updating

One command pulls the latest `main` and restarts everything:

```bash
smarthome-update
```

It puts local edits aside (`git stash`), fast-forwards, reinstalls Python
packages only when `requirements.txt` changed, refuses code that does not
compile, restarts the services and checks each one answers. If any of that
fails it puts the previous version back on its own.

It also restarts when the code was pulled by hand but the services still run
the old version, and stops a hand-started copy of a server (for example
`python3 app.py`) that keeps the port from the real service.

```bash
smarthome-update --rollback   # back to the version before the last update
smarthome-update --status     # running version and service state
smarthome-update --restart    # restart the services on the code already pulled
```

`install.sh` creates the `smarthome-update` command. On an older install,
run `bash ~/smartHome/update.sh` once and it creates it.

---

## Fingerprint login

Sign in to the control panel with a fingerprint, face or phone PIN
(WebAuthn passkeys, the same design as 8soda.ir).

1. Open the panel at `https://home.<your domain>` on the phone and sign in
   with your password once.
2. Tap **Turn on** on the banner, or **More → Fingerprint login → Turn on
   for this device**, and confirm with your fingerprint.
3. From then on the login page asks for the fingerprint by itself.

It only works on the https address: browsers refuse passkeys on plain http
and on the LAN IP, and the card says so there. The key stays in the phone's
secure hardware; the Pi stores only public keys, in
`instance/passkeys.db`. Remove a lost phone from the same card.

Needs `python3-cryptography` (installed by `install.sh` and
`smarthome-update`). The address keys are bound to defaults to
`home.$SMARTHOME_DOMAIN`; override with `SMARTHOME_PASSKEY_RP_ID` (and
`SMARTHOME_PASSKEY_ORIGINS`) in `smarthome.service` if you use another one.

Eight failed sign-ins (password or fingerprint) from one address lock that
address out for 15 minutes.

---

## Uninstall

```bash
bash uninstall.sh              # asks before deleting anything you made
bash uninstall.sh --dry-run    # show what would happen, change nothing
bash uninstall.sh --purge      # delete everything, no prompts
```

`install.sh` writes every file, service, package, ACL, group and firewall rule
it creates to `/var/lib/smarthome/manifest`. The uninstaller reads that back
and reverses exactly those entries, so anything that was on the machine
beforehand is left alone:

- Caddy is only removed if `install.sh` was what installed it
- a Caddyfile that existed before the install is offered back
- nginx, if it was disabled to free port 80, is offered back
- ports 22, 80 and 443 stay open, since other things usually need them
- your websites, uploads, chat database and route database are each removed
  only if you say yes

Backups taken during install are kept in `/var/lib/smarthome/backup-<date>/`
until you let the uninstaller delete them. The project folder itself is never
deleted; remove it yourself when you're done.

---

## Security notes

Worth doing before this faces the internet:

- **The panel on :8090 has no login.** The installer restricts it to your LAN
  with ufw. Keep it that way, or put it behind a route with an IP allow-list.
- **`instance/chat.db` is committed to this repository**, and `app.py` has
  contained a hard-coded `SECRET_KEY` and a `users_db` in source. If your fork
  is public, treat every password and session in it as exposed and rotate
  them. Every server now generates its own session key in `instance/` on
  first start (`local_secrets.py`), and the included `.gitignore` keeps
  databases, uploads and logs out of future commits — but it cannot remove
  what is already in the history.
- **Default logins still in source:** chat `admin` / `admin123` (created on
  first run), upload server `user1` / `password1` (until `users.json`
  exists), and the firmware and control-panel passwords in their `.py`
  files. Change them.
- **Upload server password reset** lives at `/reset/<secret>`; the secret is
  random per install, in `instance/.secret_upload_reset`.
- **Upload limits.** Each route allows 64 MB by default. Raise it on the
  upload server's route if you push larger files.

---

## Layout

```
smartHome/
├── install.sh              one-shot installer
├── uninstall.sh            reverses it, manifest-driven
├── update.sh               one-command update, auto-rollback
├── requirements.txt
├── app.py                  control system + dashboard        :5000
├── passkeys.py             fingerprint login (WebAuthn)
├── chatServer.py           chat, Socket.IO                    :5554
├── uploadServer.py         file uploads                       :8000
├── firmware_server-3.py    firmware OTA                       :5001
├── proxy/
│   ├── proxy_manager.py    routing panel                      :8090
│   ├── templates/
│   │   └── proxy.html
│   └── proxyctl.db         routes, settings, audit (created on first run)
├── templates/              dashboard, login, chat, settings…
├── static/
└── instance/
```

## Running the panel by hand

```bash
cd proxy
PROXYCTL_DRY_RUN=1 python3 proxy_manager.py
```

Dry run writes to `proxy/dryrun/Caddyfile` and never touches the real service —
useful for trying routes out. Other variables: `PROXYCTL_PORT`,
`PROXYCTL_WEBROOT`, `PROXYCTL_CADDYFILE`, `PROXYCTL_ACCESS_LOG`,
`PROXYCTL_SEED_DOMAIN`.

Settings stored in the database win over these variables, which only supply
the starting values on first run. To change the website root later, use
**Settings → Website folder** in the panel.
