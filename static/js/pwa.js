/* ============================================================
   Install as an app - offer, iPhone hint, service worker.

   Lessons kept from 8soda.ir:
   - The browser's own install event is always taken and silenced
     first, before deciding whether to show our banner. Otherwise
     Chrome shows its own grey install bar every time ours is hidden.
   - "x" snoozes the offer for two weeks; installing ends it for good;
     inside the installed app nothing is offered.
   - iPhone has no install event: Safari gets a short "Share, then Add
     to Home Screen" hint instead. Not in in-app browsers (Instagram,
     Telegram), where that menu does not exist.
   ============================================================ */
(function () {
  'use strict';
  var KEY = 'home-app-offer-hide', AGAIN_DAYS = 14;

  if ('serviceWorker' in navigator && window.isSecureContext) {
    addEventListener('load', function () {
      navigator.serviceWorker.register('/sw.js').catch(function () {});
    });
  }

  var standalone = matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
  var ua = navigator.userAgent;
  var iOS = /iPad|iPhone|iPod/.test(ua) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  var inApp = /FBAN|FBAV|Instagram|Line\/|Twitter|MicroMessenger|GSA|Telegram/i.test(ua);
  var iosSafari = iOS && /Safari/.test(ua) && !/CriOS|FxiOS|EdgiOS|OPiOS/.test(ua) && !inApp;

  var IOS_HINT = 'Tap the Share button, then “Add to Home Screen”.';
  var OTHER_HINT = 'Open your browser menu and choose “Install app” or “Add to Home screen”.';

  var banner = document.getElementById('app_offer');
  var deferred = null, timer = null;

  function snoozed() {
    try {
      var until = parseInt(localStorage.getItem(KEY) || '0', 10);
      return until && Date.now() < until;
    } catch (e) { return false; }
  }
  function hide(days) {
    if (banner) banner.hidden = true;
    if (days) { try { localStorage.setItem(KEY, String(Date.now() + days * 86400000)); } catch (e) {} }
  }
  function allowed() { return !!banner && !standalone && !snoozed(); }

  function show(hint) {
    if (!banner) return;
    // One offer at a time: wait while the fingerprint offer is up
    var other = document.getElementById('pk_offer');
    if (!hint && other && !other.hidden) { clearTimeout(timer); timer = setTimeout(show, 6000); return; }
    var text = banner.querySelector('[data-app-text]'), go = banner.querySelector('[data-app-go]');
    if (hint) {
      text.textContent = hint;
      go.textContent = 'Got it';
      banner.dataset.mode = 'hint';
    } else {
      text.textContent = 'Opens from your home screen, like an app.';
      go.textContent = 'Install';
      banner.dataset.mode = 'install';
    }
    banner.hidden = false;
  }

  function install() {
    try { localStorage.removeItem(KEY); } catch (e) {}
    if (deferred) {
      deferred.prompt();
      deferred.userChoice.then(function (res) {
        hide(res.outcome === 'accepted' ? 3650 : AGAIN_DAYS);
        deferred = null;
        refreshManual();
      });
      return;
    }
    show(iosSafari || iOS ? IOS_HINT : OTHER_HINT);
  }

  addEventListener('beforeinstallprompt', function (ev) {
    ev.preventDefault();
    deferred = ev;
    refreshManual();
    if (allowed()) { clearTimeout(timer); timer = setTimeout(show, 2500); }
  });
  addEventListener('appinstalled', function () { hide(3650); deferred = null; refreshManual(); });

  if (banner) {
    banner.querySelector('[data-app-x]').addEventListener('click', function () { hide(AGAIN_DAYS); });
    banner.querySelector('[data-app-go]').addEventListener('click', function () {
      if (banner.dataset.mode === 'hint') { hide(AGAIN_DAYS); return; }
      install();
    });
  }

  if (iosSafari && allowed()) { timer = setTimeout(function () { show(IOS_HINT); }, 2500); }

  /* The "Install app" row under More - for whoever closed the banner */
  function refreshManual() {
    document.querySelectorAll('[data-app-install]').forEach(function (row) {
      row.hidden = standalone;
    });
  }
  document.querySelectorAll('[data-app-install] [data-app-install-go]').forEach(function (b) {
    b.addEventListener('click', function () {
      install();
      if (banner && !banner.hidden) banner.scrollIntoView({ behavior: 'smooth', block: 'center' });
    });
  });
  refreshManual();

  window.HomeApp = { standalone: standalone };
})();
