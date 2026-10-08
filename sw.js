// Offline support: app files are network-first (so updates show up on the next open) with a
// cached fallback; the version-pinned Firebase SDK is cache-first. Data requests pass through.
const CACHE = 'cradle-v3';
const SDK = 'https://www.gstatic.com/firebasejs/13.0.0/';
const SHELL = ['./', 'index.html', 'styles.css', 'app.js', 'config.js', 'who.js', 'manifest.webmanifest', 'icon-180.png', 'icon-512.png'];

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    await cache.addAll(SHELL);
    await cache.addAll(['firebase-app.js', 'firebase-auth.js', 'firebase-firestore.js'].map((f) => SDK + f)).catch(() => {});
    await self.skipWaiting();
  })());
});
self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) if (key !== CACHE) await caches.delete(key);
    await self.clients.claim();
  })());
});
self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.href.startsWith(SDK)) {
    event.respondWith(caches.match(req).then((hit) => hit || fetch(req).then((res) => {
      if (res.ok) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(req, copy)); }
      return res;
    })));
  } else if (url.origin === self.location.origin) {
    event.respondWith(fetch(req).then((res) => {
      if (res.ok) { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(req, copy)); }
      return res;
    }).catch(() => caches.match(req, { ignoreSearch: true })));
  }
});
