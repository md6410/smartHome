/* ============================================================
   Fingerprint / face login - browser side (WebAuthn passkeys)

   This file makes no security decisions. It only translates: the
   server speaks base64url, the browser API wants ArrayBuffers. Every
   check (domain, challenge, signature) happens on the Pi.

   Everything stays hidden until the device proves it can do this.
   An old browser, plain http, the LAN address, or a computer without
   a sensor raise no error - the API is just missing or says false -
   and a button that does nothing is worse than no button.
   ============================================================ */
(function () {
  'use strict';

  function b64uToBuf(s) {
    s = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s), buf = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }
  function bufToB64u(buf) {
    var b = new Uint8Array(buf), s = '';
    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  /* ---------- can this device do it? ---------- */
  function hasApi() {
    return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create);
  }
  function hasPlatform() {
    if (!hasApi()) return Promise.resolve(false);
    var fn = window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable;
    if (!fn) return Promise.resolve(false);
    return fn.call(window.PublicKeyCredential).catch(function () { return false; });
  }
  /* Keys are bound to one address. On any other (the LAN IP, another
     domain) the browser refuses, so say where to go instead of failing. */
  function onRightHost(rpId) {
    var h = location.hostname.toLowerCase();
    return !!rpId && (h === rpId || h.slice(-(rpId.length + 1)) === '.' + rpId);
  }

  function post(url, data) {
    return fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(data || {})
    }).then(function (r) {
      if (r.redirected && r.url.indexOf('/login') !== -1) return { ok: false, error: 'Please sign in again.' };
      return r.json().catch(function () { return { ok: false, error: 'The server reply could not be read. Refresh the page.' }; });
    });
  }

  /* A message from the server is shown as it is */
  function pkErr(msg) {
    var e = new Error(msg || 'That did not work. Please try again.');
    e.pkSaid = true;
    return e;
  }

  /* NotAllowedError means both "you cancelled" and "no key for this site
     on this device" - the browser does not say which. So it is never
     shown red, and the hint covers both. */
  var NOT_FOUND_HINT = 'Cancelled, or no fingerprint key on this device. Sign in with your password ' +
                       'once, then turn on fingerprint login under More.';
  function humanError(e, kind) {
    if (e && e.pkSaid && e.message) return e.message;
    var n = (e && e.name) || '';
    if (n === 'NotAllowedError' || n === 'AbortError') {
      if (kind === 'confirm') return 'Not opened - the fingerprint was cancelled or not recognised.';
      return kind === 'login' ? NOT_FOUND_HINT : '';
    }
    if (n === 'InvalidStateError') return 'This device is already registered. Remove it from the list below and add it again if login does not work.';
    if (n === 'NotSupportedError') return 'This device does not support fingerprint or face login.';
    if (n === 'SecurityError') return 'Open the panel from its https address to use fingerprint login.';
    return 'That did not work. Please try again.';
  }

  /* ---------- the two ceremonies ---------- */
  function register(compat) {
    return post('/passkey/register/options', compat ? { compat: 1 } : {}).then(function (r) {
      if (!r.ok) throw pkErr(r.error);
      var o = r.options;
      o.challenge = b64uToBuf(o.challenge);
      o.user.id = b64uToBuf(o.user.id);
      (o.excludeCredentials || []).forEach(function (c) { c.id = b64uToBuf(c.id); });
      return navigator.credentials.create({ publicKey: o });
    }).then(function (cred) {
      if (!cred) throw pkErr('No answer from the device.');
      var tr = [];
      try { if (cred.response.getTransports) tr = cred.response.getTransports() || []; } catch (e) { tr = []; }
      /* credProps.rk: did the key really become findable? true, false, or
         "browser did not say" - the last stays undefined so the server does
         not mistake it for false */
      var rk;
      try {
        var ext = cred.getClientExtensionResults ? cred.getClientExtensionResults() : null;
        if (ext && ext.credProps && typeof ext.credProps.rk === 'boolean') rk = ext.credProps.rk;
      } catch (e) { rk = undefined; }
      var payload = {
        id: cred.id,
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        attestationObject: bufToB64u(cred.response.attestationObject),
        transports: tr
      };
      if (typeof rk === 'boolean') payload.rk = rk;
      return post('/passkey/register/verify', payload);
    });
  }

  function login() {
    return post('/passkey/login/options').then(function (r) {
      if (!r.ok) throw pkErr(r.error);
      var o = r.options;
      o.challenge = b64uToBuf(o.challenge);
      (o.allowCredentials || []).forEach(function (c) { c.id = b64uToBuf(c.id); });
      // Some browsers read an empty list as "none", so leave it out
      if (!o.allowCredentials || !o.allowCredentials.length) delete o.allowCredentials;
      return navigator.credentials.get({ publicKey: o });
    }).then(function (cred) {
      if (!cred) throw pkErr('No answer from the device.');
      return post('/passkey/login/verify', {
        id: cred.id,
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        authenticatorData: bufToB64u(cred.response.authenticatorData),
        signature: bufToB64u(cred.response.signature),
        userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : ''
      });
    });
  }

  /* ---------- page helpers ---------- */
  function setNote(box, text, kind) {
    var n = box.querySelector('[data-pk-note]');
    if (!n) return;
    n.textContent = text || '';
    n.className = 'pk-note' + (kind ? ' pk-note--' + kind : '');
    n.hidden = !text;
  }
  function busy(btn, on, label) {
    btn.disabled = !!on;
    var t = btn.querySelector('[data-pk-label]') || btn;
    if (on) { btn.dataset.pkIdle = btn.dataset.pkIdle || t.textContent; t.textContent = label || 'Waiting for your device…'; }
    else if (btn.dataset.pkIdle) t.textContent = btn.dataset.pkIdle;
  }
  function store(kind, key, val) {
    try {
      var s = kind === 'session' ? sessionStorage : localStorage;
      if (val === undefined) return s.getItem(key);
      if (val === null) s.removeItem(key); else s.setItem(key, val);
    } catch (e) { return null; }
    return null;
  }

  /* ---------- login page ---------- */
  function bindLogin(box) {
    var rp = box.dataset.pkRp, btn = box.querySelector('[data-pk-go]');
    var tap = document.querySelector('[data-pk-tap]');
    if (!btn || !onRightHost(rp)) return;
    hasPlatform().then(function (can) {
      if (!can) return;
      box.hidden = false;

      function showTap(waiting) {
        if (!tap) return;
        tap.querySelector('[data-pk-tap-text]').textContent =
          waiting ? 'Waiting for your fingerprint…' : 'Tap anywhere to sign in with your fingerprint';
        tap.classList.toggle('waiting', !!waiting);
        tap.hidden = false;
      }
      function hideTap() { if (tap) tap.hidden = true; }

      function go(fromAuto) {
        var t0 = Date.now();
        setNote(box, '');
        busy(btn, true);
        return login().then(function (r) {
          if (r && r.ok) {
            store('session', 'pk_auto_done', null);
            location.href = r.go || '/';
            return;
          }
          hideTap();
          busy(btn, false);
          setNote(box, (r && r.error) || 'Sign-in failed.', 'bad');
        }).catch(function (e) {
          busy(btn, false);
          var refused = e && (e.name === 'NotAllowedError' || e.name === 'AbortError');
          /* Safari (and some in-app browsers) refuse a prompt that did not
             start from a tap - instantly. A person closing the prompt takes
             longer than that. So a fast refusal of the automatic start turns
             the whole screen into the button: one tap anywhere and it asks. */
          if (fromAuto && refused && Date.now() - t0 < 1500 && tap) {
            showTap(false);
            return;
          }
          hideTap();
          setNote(box, humanError(e, 'login'), refused ? '' : 'bad');
        });
      }
      btn.addEventListener('click', function () { go(false); });

      if (tap) {
        tap.addEventListener('click', function () {
          if (tap.classList.contains('waiting')) return;
          showTap(true);
          go(false);
        });
        tap.querySelector('[data-pk-tap-skip]').addEventListener('click', function (e) {
          e.stopPropagation();
          hideTap();
          var u = document.querySelector('input[name="username"]');
          if (u) u.focus();
        });
      }

      /* Start by itself only when the server says this browser holds a
         key. The guard is set *before* starting: if the prompt is closed
         or the page reloaded mid-way, it does not pop up again until
         this tab is closed - only the button stays. */
      if (box.dataset.pkAuto === '1' && store('session', 'pk_auto_done') !== '1') {
        store('session', 'pk_auto_done', '1');
        showTap(true);
        go(true);
      }
    });
  }

  /* ---------- approve one action (opening a door) ---------- */
  function confirmAction(action) {
    return post('/passkey/confirm/options', { action: action }).then(function (r) {
      if (!r.ok) throw pkErr(r.error);
      var o = r.options;
      o.challenge = b64uToBuf(o.challenge);
      (o.allowCredentials || []).forEach(function (c) { c.id = b64uToBuf(c.id); });
      return navigator.credentials.get({ publicKey: o });
    }).then(function (cred) {
      if (!cred) throw pkErr('No answer from the device.');
      return {
        id: cred.id,
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        authenticatorData: bufToB64u(cred.response.authenticatorData),
        signature: bufToB64u(cred.response.signature)
      };
    });
  }

  /* ---------- control panel card ---------- */
  function bindManage(box) {
    var rp = box.dataset.pkRp, btn = box.querySelector('[data-pk-go]'), list = box.querySelector('[data-pk-list]');
    var why = box.querySelector('[data-pk-why]');

    function loadList() {
      fetch('/passkey/devices', { credentials: 'same-origin', cache: 'no-store' })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          var devices = (d && d.devices) || [];
          box.dataset.pkCount = devices.length;
          var lbl = btn && btn.querySelector('[data-pk-label]');
          if (lbl && !btn.disabled) {
            lbl.textContent = devices.length ? 'Add this device' : 'Turn on for this device';
            delete btn.dataset.pkIdle;
          }
          var meta = box.querySelector('[data-pk-meta]');
          if (meta) meta.textContent = devices.length ? devices.length + ' device' + (devices.length > 1 ? 's' : '') : 'Off';
          list.innerHTML = '';
          devices.forEach(function (k) {
            var row = document.createElement('div');
            row.className = 'pk-dev';
            var info = document.createElement('div');
            var b = document.createElement('b'); b.textContent = k.label;
            var sm = document.createElement('small');
            sm.textContent = 'Added ' + k.created + (k.lastUsed ? ' · used ' + k.lastUsed : '') + (k.localOnly ? ' · this browser only' : '');
            info.appendChild(b); info.appendChild(sm);
            var del = document.createElement('button');
            del.type = 'button'; del.className = 'pk-del'; del.setAttribute('aria-label', 'Remove ' + k.label);
            del.innerHTML = '<i class="fa-solid fa-trash-can"></i>';
            del.addEventListener('click', function () {
              if (!del.classList.contains('armed')) {
                del.classList.add('armed'); del.innerHTML = 'Remove?';
                setTimeout(function () { del.classList.remove('armed'); del.innerHTML = '<i class="fa-solid fa-trash-can"></i>'; }, 3000);
                return;
              }
              post('/passkey/remove', { id: k.id }).then(function (r) {
                setNote(box, r.ok ? r.msg : r.error, r.ok ? 'ok' : 'bad');
                loadList();
              });
            });
            row.appendChild(info); row.appendChild(del);
            list.appendChild(row);
          });
          box.dispatchEvent(new CustomEvent('pk:devices', { detail: devices }));
        }).catch(function () {});
    }
    loadList();

    function cannot(text) {
      if (why) { why.textContent = text; why.hidden = false; }
      btn.hidden = true;
    }
    if (!hasApi()) return cannot('This browser does not support fingerprint login.');
    if (!onRightHost(rp) || !window.isSecureContext) {
      return cannot('To turn this on, open the panel at https://' + rp + ' on this phone.');
    }
    hasPlatform().then(function (can) {
      if (!can) return cannot('This device has no fingerprint or face sensor that browsers can use.');
      btn.hidden = false;
      btn.addEventListener('click', function () {
        regGo(store('local', 'pk_compat') === '1');
      });
    });

    /* Strict first; if the phone refuses (Samsung Pass as default, no
       Google Password Manager), straight to the compatible try - and
       remember it, so this phone skips the failing prompt next time. */
    function regGo(compat) {
      setNote(box, '');
      busy(btn, true);
      register(compat).then(function (r) {
        busy(btn, false);
        if (r && r.ok) {
          setNote(box, r.warn || r.msg || 'Turned on.', r.warn ? '' : 'ok');
          loadList();
          return;
        }
        setNote(box, (r && r.error) || 'Could not turn it on.', 'bad');
      }).catch(function (e) {
        var n = (e && e.name) || '';
        var notAllowed = n === 'NotAllowedError' || n === 'AbortError';
        try { console.info('passkey', n, compat ? 'compat' : 'strict', (e && e.message) || ''); } catch (x) {}
        if (notAllowed && !compat) {
          store('local', 'pk_compat', '1');
          regGo(true);
          return;
        }
        busy(btn, false);
        setNote(box, notAllowed ? 'Not turned on. If you closed the prompt, tap again - password login works as always.'
                                : humanError(e, 'register'), notAllowed ? '' : 'bad');
      });
    }
  }

  function bindAll() {
    document.querySelectorAll('[data-pk-login]').forEach(bindLogin);
    document.querySelectorAll('[data-pk-manage]').forEach(bindManage);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bindAll);
  else bindAll();

  window.HomePasskey = {
    supported: function (rp) {
      return hasApi() && onRightHost(rp) && window.isSecureContext ? hasPlatform() : Promise.resolve(false);
    },
    confirm: confirmAction,
    message: function (e) { return humanError(e, 'confirm'); }
  };
})();
