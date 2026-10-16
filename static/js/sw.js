/* ============================================================
   Service worker - makes the panel installable as an app.

   One rule above all: nothing about the house is ever cached. Light
   states, the cooler, the doors and every page come from the Pi each
   time - a cached "light is off" that is really on is worse than no
   app. Only static files (styles, scripts, fonts, icons) are kept, and
   even those are fetched fresh whenever the Pi answers, so an update
   is picked up on the next load without bumping anything here.

   When the Pi cannot be reached, a page opened from the app shows
   "Can't reach home" instead of the browser's error.
   ============================================================ */
const VERSION = 'home-v1';
const STATIC_CACHE = VERSION + '-static';
const OFFLINE_URL = '/static/offline.html';
const PRECACHE = [
  OFFLINE_URL,
  '/static/css/all.min.css',
  '/static/webfonts/fa-solid-900.woff2',
  '/static/images/icon-192.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE)
      // one at a time: addAll() gives up entirely if a single file fails
      .then((c) => Promise.all(PRECACHE.map((u) => c.add(u).catch(() => {}))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => !k.startsWith(VERSION)).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;                      // controls go straight to the Pi
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // Pages: always the network. Offline page only when the Pi is unreachable.
  if (req.mode === 'navigate') {
    event.respondWith(fetch(req).catch(() => caches.match(OFFLINE_URL)));
    return;
  }

  // Static files: fresh when possible, the kept copy when not
  if (url.pathname.startsWith('/static/')) {
    event.respondWith(
      fetch(req).then((res) => {
        if (res.ok) {
          const copy = res.clone();
          caches.open(STATIC_CACHE).then((c) => c.put(req, copy));
        }
        return res;
      }).catch(() => caches.match(req))
    );
  }
  // Everything else (status, API) is not touched: straight to the network
});
