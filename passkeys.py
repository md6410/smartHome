"""Fingerprint / face / device-PIN login (WebAuthn passkeys).

Ported from the 8soda.ir implementation, keeping the lessons it learned
on real phones. In short:

  register  the phone makes a key pair inside its secure hardware. The
            private key never leaves it; we store the public key.
  login     we hand out a random challenge, the phone signs it after the
            fingerprint/face check, we verify the signature.

No password crosses the wire, nothing worth stealing sits on the Pi, and
a phishing page gets nothing: the browser binds every key to the domain.

Attestation is not checked on purpose (asking for it pops a scary
"allow device identification" prompt on iPhones and adds nothing for a
home panel). What is checked: domain, origin, challenge, the
"user verified" flag and the signature itself.

Needs the `cryptography` package (apt: python3-cryptography). Without it
the feature stays switched off and password login works as before.
"""
import base64
import binascii
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    HAVE_CRYPTO = True
except ImportError:          # pragma: no cover - depends on the Pi
    HAVE_CRYPTO = False

CHALLENGE_TTL = 300          # seconds; the user is touching the sensor right now
MAX_PER_USER = 10
DEVICE_COOKIE = 'pk_dev'
DEVICE_TTL = 400 * 86400

ALG_ES256 = -7
ALG_RS256 = -257


class PasskeyError(Exception):
    """A failure whose message is fit to show the user."""


# =======================================================================
# base64url
# =======================================================================
def b64u_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def b64u_decode(s):
    """Raw bytes, or b'' when the input is not valid base64url."""
    s = str(s or '').strip()
    if len(s) % 4 == 1:
        return b''
    s = s.replace('-', '+').replace('_', '/') + '=' * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return b''


# =======================================================================
# CBOR - only what WebAuthn uses (ints, byte/text strings, arrays, maps)
# =======================================================================
def _cbor_value(s, i):
    if i >= len(s):
        raise ValueError('cbor: unexpected end')
    ib = s[i]
    i += 1
    major, ai = ib >> 5, ib & 0x1F
    if ai < 24:
        length = ai
    elif ai in (24, 25, 26, 27):
        n = 1 << (ai - 24)
        if i + n > len(s):
            raise ValueError('cbor: unexpected end')
        length = int.from_bytes(s[i:i + n], 'big')
        i += n
    else:
        raise ValueError('cbor: indefinite or reserved length')

    if major == 0:
        return length, i
    if major == 1:
        return -1 - length, i
    if major in (2, 3):
        if i + length > len(s):
            raise ValueError('cbor: bad string length')
        raw = s[i:i + length]
        return (raw if major == 2 else raw.decode('utf-8')), i + length
    if major == 4:
        out = []
        for _ in range(length):
            v, i = _cbor_value(s, i)
            out.append(v)
        return out, i
    if major == 5:
        out = {}
        for _ in range(length):
            k, i = _cbor_value(s, i)
            if not isinstance(k, (int, str)):
                raise ValueError('cbor: bad map key')
            out[k], i = _cbor_value(s, i)
        return out, i
    if major == 6:                    # tag - the value inside is what matters
        return _cbor_value(s, i)
    if major == 7:
        if ai == 20:
            return False, i
        if ai == 21:
            return True, i
        if ai == 22:
            return None, i
    raise ValueError('cbor: unsupported value')


def cbor_decode(s):
    """First CBOR item in s, and the offset just past it."""
    return _cbor_value(s, 0)


# =======================================================================
# COSE public key -> cryptography key
#   ES256 (-7)   P-256: iPhone, Android, most security keys
#   RS256 (-257) older Windows Hello
# =======================================================================
def cose_to_public_key(cose):
    kty, alg = cose.get(1), cose.get(3)
    if kty == 2:
        if alg != ALG_ES256:
            raise PasskeyError('This device uses an unsupported key type.')
        x, y = cose.get(-2, b''), cose.get(-3, b'')
        if cose.get(-1) != 1 or len(x) != 32 or len(y) != 32:
            raise PasskeyError('The device sent an invalid key.')
        key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, 'big'), int.from_bytes(y, 'big'), ec.SECP256R1()).public_key()
        return key, ALG_ES256
    if kty == 3:
        if alg != ALG_RS256:
            raise PasskeyError('This device uses an unsupported key type.')
        n, e = cose.get(-1, b''), cose.get(-2, b'')
        if not n or not e:
            raise PasskeyError('The device sent an invalid key.')
        key = rsa.RSAPublicNumbers(int.from_bytes(e, 'big'), int.from_bytes(n, 'big')).public_key()
        return key, ALG_RS256
    raise PasskeyError('This device uses an unsupported key type.')


def public_key_der(key):
    return key.public_bytes(serialization.Encoding.DER,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def verify_signature(der, alg, signature, data):
    key = serialization.load_der_public_key(der)
    try:
        if alg == ALG_ES256:
            key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        elif alg == ALG_RS256:
            key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        else:
            return False
        return True
    except (InvalidSignature, ValueError):
        return False


# =======================================================================
# authenticatorData: rpIdHash(32) flags(1) signCount(4) [attested data]
# =======================================================================
def parse_auth_data(d):
    if len(d) < 37:
        raise PasskeyError('Could not read the device response.')
    flags = d[32]
    out = {
        'rp_id_hash': d[:32],
        'up': bool(flags & 0x01),      # user present
        'uv': bool(flags & 0x04),      # user *verified*: fingerprint, face or PIN
        'at': bool(flags & 0x40),      # a new key is attached
        'sign_count': int.from_bytes(d[33:37], 'big'),
        'cred_id': b'',
        'cose': None,
    }
    if not out['at']:
        return out
    if len(d) < 55:
        raise PasskeyError('Could not read the device response.')
    id_len = int.from_bytes(d[53:55], 'big')
    if id_len <= 0 or len(d) < 55 + id_len:
        raise PasskeyError('Could not read the device response.')
    out['cred_id'] = d[55:55 + id_len]
    try:
        cose, _ = cbor_decode(d[55 + id_len:])
    except ValueError:
        raise PasskeyError('Could not read the device key.')
    if not isinstance(cose, dict):
        raise PasskeyError('Could not read the device key.')
    out['cose'] = cose
    return out


def label_from_user_agent(ua):
    """A guess, but 'iPhone' beats 'device 3' when choosing what to remove."""
    ua = ua or ''
    for needle, name in (('iPhone', 'iPhone'), ('iPad', 'iPad'), ('Android', 'Android phone'),
                         ('Macintosh', 'Mac'), ('Windows', 'Windows PC'), ('Linux', 'Linux')):
        if needle in ua:
            return name
    return 'This device'


# =======================================================================
# The service
# =======================================================================
class Passkeys:
    def __init__(self, db_path, rp_id, origins, rp_name, secret):
        self.db_path = db_path
        self.rp_id = rp_id.lower()
        self.origins = set(origins)
        self.rp_name = rp_name
        self._secret = secret.encode() if isinstance(secret, str) else secret
        self._challenges = {}
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        with self._db() as c:
            c.execute('''CREATE TABLE IF NOT EXISTS passkeys (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                username     TEXT    NOT NULL,
                cred_id      TEXT    NOT NULL UNIQUE,
                public_key   BLOB    NOT NULL,
                alg          INTEGER NOT NULL,
                sign_count   INTEGER NOT NULL DEFAULT 0,
                transports   TEXT    NOT NULL DEFAULT '',
                discoverable INTEGER,
                label        TEXT    NOT NULL DEFAULT '',
                created_at   TEXT    NOT NULL,
                last_used_at TEXT
            )''')
            c.execute('CREATE INDEX IF NOT EXISTS passkeys_user ON passkeys(username)')

    @property
    def available(self):
        return HAVE_CRYPTO and bool(self.rp_id)

    def _db(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------ storage
    def list(self, username):
        with self._db() as c:
            return [dict(r) for r in c.execute(
                'SELECT * FROM passkeys WHERE username=? ORDER BY id', (username,))]

    def count(self, username):
        with self._db() as c:
            return c.execute('SELECT COUNT(*) FROM passkeys WHERE username=?', (username,)).fetchone()[0]

    def remove(self, username, key_id):
        # username in the WHERE clause: an id edited in the request must
        # not delete someone else's key
        with self._db() as c:
            return c.execute('DELETE FROM passkeys WHERE id=? AND username=?',
                             (key_id, username)).rowcount > 0

    # ---------------------------------------------------------- challenges
    # Kept on the Pi, not in the session cookie: Flask's session lives in
    # the browser, so a "used" challenge could be replayed with an old copy
    # of the cookie. Here every attempt, good or bad, burns it.
    def _challenge_new(self, purpose, username=None):
        value = b64u_encode(secrets.token_bytes(32))
        handle = secrets.token_urlsafe(16)
        now = time.time()
        with self._lock:
            for h in [h for h, c in self._challenges.items() if c['exp'] < now]:
                del self._challenges[h]
            self._challenges[handle] = {'v': value, 'for': purpose, 'user': username,
                                        'exp': now + CHALLENGE_TTL}
        return handle, value

    def _challenge_take(self, handle, purpose, got):
        with self._lock:
            ch = self._challenges.pop(handle or '', None)
        if not ch or ch['for'] != purpose or ch['exp'] < time.time():
            return None
        if not hmac.compare_digest(ch['v'], str(got)):
            return None
        return ch

    def _check_client_data(self, raw, want_type, handle, purpose):
        try:
            c = json.loads(raw.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            raise PasskeyError('Could not read the browser response.')
        if not isinstance(c, dict) or c.get('type') != want_type:
            raise PasskeyError('The response does not match the request.')
        ch = self._challenge_take(handle, purpose, c.get('challenge', ''))
        if ch is None:
            raise PasskeyError('This request expired. Please try again.')
        if c.get('origin') not in self.origins:
            raise PasskeyError('This request came from another address.')
        return ch

    # -------------------------------------------------------- registration
    def create_options(self, username, compat=False):
        handle, challenge = self._challenge_new('register', username)
        # The id stored on the phone. Fixed per account, never the password.
        user_handle = b64u_encode(('h:' + username).encode())
        options = {
            'challenge': challenge,
            'rp': {'id': self.rp_id, 'name': self.rp_name},
            'user': {'id': user_handle, 'name': username, 'displayName': username},
            # ES256 first: shorter and on every phone; RS256 for old Windows Hello
            'pubKeyCredParams': [{'type': 'public-key', 'alg': ALG_ES256},
                                 {'type': 'public-key', 'alg': ALG_RS256}],
            'timeout': 120000,
            'attestation': 'none',
            'excludeCredentials': [{'type': 'public-key', 'id': k['cred_id']}
                                   for k in self.list(username)],
            'authenticatorSelection': {
                # this device's own sensor: Touch ID, Face ID, Android, Windows Hello
                'authenticatorAttachment': 'platform',
                # "required", not "preferred": with preferred, Android may
                # quietly save a key it cannot find again at login
                'residentKey': 'required',
                'requireResidentKey': True,
                'userVerification': 'required',
            },
            # tells us afterwards whether the key really became discoverable
            'extensions': {'credProps': True},
        }
        if compat:
            # Second try, after the strict one was refused. The exact set
            # that worked on the Samsung that refused the strict options in
            # 8soda's testing: a local key, no Google Password Manager (often
            # unreachable from Iran). The fingerprint is still enforced -
            # register_verify checks the UV flag regardless.
            sel = options['authenticatorSelection']
            sel.update(residentKey='discouraged', requireResidentKey=False,
                       userVerification='preferred')
            options['excludeCredentials'] = []
        return handle, options

    def register_verify(self, username, handle, resp, user_agent=''):
        client_raw = b64u_decode(resp.get('clientDataJSON'))
        att_raw = b64u_decode(resp.get('attestationObject'))
        if not client_raw or not att_raw:
            raise PasskeyError('The browser response was incomplete.')

        ch = self._check_client_data(client_raw, 'webauthn.create', handle, 'register')
        if ch['user'] != username:
            raise PasskeyError('This request expired. Please try again.')

        try:
            att, _ = cbor_decode(att_raw)
        except ValueError:
            att = None
        if not isinstance(att, dict) or not isinstance(att.get('authData'), bytes):
            raise PasskeyError('Could not read the device response.')

        ad = parse_auth_data(att['authData'])
        if not ad['at'] or not ad['cred_id'] or not ad['cose']:
            raise PasskeyError('The device response was incomplete.')
        if not hmac.compare_digest(hashlib.sha256(self.rp_id.encode()).digest(), ad['rp_id_hash']):
            raise PasskeyError('This key was made for another site.')
        # Verified, not just present: otherwise anyone holding an unlocked
        # phone could add a key
        if not ad['uv']:
            raise PasskeyError('Your device did not confirm a fingerprint, face or PIN.')

        key, alg = cose_to_public_key(ad['cose'])
        cred_id = b64u_encode(ad['cred_id'])

        rk = resp.get('rk')
        discoverable = None if not isinstance(rk, bool) else int(rk)
        transports = ','.join(sorted({
            ''.join(ch_ for ch_ in str(t).lower() if ch_.isalpha())
            for t in (resp.get('transports') or []) if isinstance(t, str)
        } - {''}))[:120]

        now = datetime.now().isoformat(timespec='seconds')
        with self._db() as c:
            old = c.execute('SELECT id, username FROM passkeys WHERE cred_id=?', (cred_id,)).fetchone()
            if old and old['username'] != username:
                raise PasskeyError('This key is already registered to another account.')
            if old:
                c.execute('UPDATE passkeys SET public_key=?, alg=?, sign_count=?, transports=?, '
                          'discoverable=? WHERE id=?',
                          (public_key_der(key), alg, ad['sign_count'], transports, discoverable, old['id']))
                return {'msg': 'This device was already registered and has been refreshed.',
                        'warn': self.rk_warning(discoverable)}
            n = c.execute('SELECT COUNT(*) FROM passkeys WHERE username=?', (username,)).fetchone()[0]
            if n >= MAX_PER_USER:
                raise PasskeyError('Too many devices registered. Remove one first.')
            c.execute('INSERT INTO passkeys (username, cred_id, public_key, alg, sign_count, '
                      'transports, discoverable, label, created_at) VALUES (?,?,?,?,?,?,?,?,?)',
                      (username, cred_id, public_key_der(key), alg, ad['sign_count'], transports,
                       discoverable, label_from_user_agent(user_agent), now))
        return {'msg': 'Fingerprint login is on for this device.',
                'warn': self.rk_warning(discoverable)}

    @staticmethod
    def rk_warning(discoverable):
        # Only a definite "no": a browser that does not report it is not a no
        if discoverable != 0:
            return ''
        return 'On. This key works only in this browser on this phone.'

    # --------------------------------------------------------------- login
    def request_options(self, username=None):
        handle, challenge = self._challenge_new('login')
        allow = []
        # When we know the account (signed device cookie), list its keys:
        # some Androids cannot find a discoverable key on their own, but
        # always find one they are pointed at
        for k in (self.list(username) if username else []):
            row = {'type': 'public-key', 'id': k['cred_id']}
            if k['transports']:
                row['transports'] = k['transports'].split(',')
            allow.append(row)
        return handle, {
            'challenge': challenge,
            'rpId': self.rp_id,
            'timeout': 120000,
            'userVerification': 'required',
            'allowCredentials': allow,
        }

    def login_verify(self, handle, resp):
        """Returns the username the signature belongs to."""
        return self._verify_assertion(handle, resp, 'login')['username']

    # ------------------------------------------------------ confirmations
    # The same fingerprint signature, used to approve one action (opening a
    # door) by someone already signed in. The challenge names the action and
    # the account, so a signature for the parking door cannot open the
    # front door, and nobody else's key can approve it.
    def confirm_options(self, username, action):
        keys = self.list(username)
        if not keys:
            raise PasskeyError('Turn on fingerprint login first.')
        handle, challenge = self._challenge_new('confirm:' + action, username)
        allow = []
        for k in keys:
            row = {'type': 'public-key', 'id': k['cred_id']}
            if k['transports']:
                row['transports'] = k['transports'].split(',')
            allow.append(row)
        return handle, {
            'challenge': challenge,
            'rpId': self.rp_id,
            'timeout': 60000,
            'userVerification': 'required',
            'allowCredentials': allow,
        }

    def confirm_verify(self, username, handle, resp, action):
        k = self._verify_assertion(handle, resp, 'confirm:' + action, username)
        if k['username'] != username:
            raise PasskeyError('That fingerprint belongs to another account.')

    def _verify_assertion(self, handle, resp, purpose, username=None):
        cred_id = str(resp.get('id') or '')
        client_raw = b64u_decode(resp.get('clientDataJSON'))
        auth_raw = b64u_decode(resp.get('authenticatorData'))
        sig = b64u_decode(resp.get('signature'))
        if not cred_id or not client_raw or not auth_raw or not sig:
            raise PasskeyError('The browser response was incomplete.')

        with self._db() as c:
            k = c.execute('SELECT * FROM passkeys WHERE cred_id=?', (cred_id,)).fetchone()
        if not k:
            with self._lock:
                self._challenges.pop(handle or '', None)
            raise PasskeyError('This device is not registered to any account.')

        ch = self._check_client_data(client_raw, 'webauthn.get', handle, purpose)
        if username is not None and ch['user'] != username:
            raise PasskeyError('This request expired. Please try again.')
        ad = parse_auth_data(auth_raw)
        if not hmac.compare_digest(hashlib.sha256(self.rp_id.encode()).digest(), ad['rp_id_hash']):
            raise PasskeyError('This key was made for another site.')
        if not ad['uv']:
            raise PasskeyError('Your device did not confirm a fingerprint, face or PIN.')

        signed = auth_raw + hashlib.sha256(client_raw).digest()
        if not verify_signature(k['public_key'], k['alg'], sig, signed):
            raise PasskeyError('The device signature did not verify.')

        # A counter that went backwards means a copied key. Many devices
        # (iPhone, synced keys) always send 0 - that is not a sign of anything.
        was, now = k['sign_count'], ad['sign_count']
        if was > 0 and now > 0 and now <= was:
            raise PasskeyError('This key is not valid any more. Sign in with your password '
                               'and register this device again.')

        with self._db() as c:
            c.execute('UPDATE passkeys SET sign_count=?, last_used_at=? WHERE id=?',
                      (max(now, was), datetime.now().isoformat(timespec='seconds'), k['id']))
        return dict(k)

    # -------------------------------------------------------- device note
    # A signed cookie saying "this browser has a key for <user>". It opens
    # nothing by itself - login still needs a real fingerprint signature -
    # it only lets the login page offer that account's keys and start the
    # fingerprint prompt by itself.
    def _device_sig(self, username):
        return hmac.new(self._secret, ('pkdev|' + username).encode(), hashlib.sha256).hexdigest()[:32]

    def device_cookie_value(self, username):
        return b64u_encode(username.encode()) + '.' + self._device_sig(username)

    def device_user(self, cookie):
        cookie = cookie or ''
        if '.' not in cookie:
            return None
        enc, sig = cookie.rsplit('.', 1)
        try:
            username = b64u_decode(enc).decode('utf-8')
        except UnicodeDecodeError:
            return None
        if not username or not hmac.compare_digest(self._device_sig(username), sig):
            return None
        return username


# =======================================================================
# Failed-login lockout, shared by the password and fingerprint doors
# =======================================================================
class LoginGate:
    def __init__(self, max_fails=8, window=15 * 60):
        self.max_fails = max_fails
        self.window = window
        self._fails = {}
        self._lock = threading.Lock()

    def locked_for(self, who):
        now = time.time()
        with self._lock:
            times = [t for t in self._fails.get(who, []) if now - t < self.window]
            self._fails[who] = times
            if len(times) < self.max_fails:
                return 0
            return int(self.window - (now - times[0])) + 1

    def fail(self, who):
        with self._lock:
            self._fails.setdefault(who, []).append(time.time())

    def reset(self, who):
        with self._lock:
            self._fails.pop(who, None)
