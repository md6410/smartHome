"""Per-install secrets, generated on first run and kept out of git.

Every server used to ship a hard-coded Flask secret key. Anyone who has
read the repository could sign their own session cookie with it and log
in as any user. Each install now gets its own random key, stored in
instance/ (which .gitignore already excludes) and reused across restarts
so logins survive a reboot.
"""
import os
import secrets

_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')


def load_secret(name, nbytes=32):
    os.makedirs(_DIR, exist_ok=True)
    path = os.path.join(_DIR, f'.secret_{name}')
    try:
        with open(path) as f:
            value = f.read().strip()
        if value:
            return value
    except FileNotFoundError:
        pass
    value = secrets.token_hex(nbytes)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(value)
    return value
