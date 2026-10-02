// Golden Pace service worker: offline-first app shell.
// VERSION is stamped automatically by tools/build.js.
const VERSION = 'df4380a2a824';
const CACHE = `golden-pace-${VERSION}`;
const SHELL = [
  './',
  'app',
  'index.html',
  'privacy.html',
  'terms.html',
  'faq.html',
  'welcome.html',
  'styles.css',
  'manifest.webmanifest',
  'favicon.svg',
  'favicon.ico',
  'favicon-32.png',
  'favicon-16.png',
  'vendor/dexie.min.js',
  'vendor/chart.umd.js',
  'vendor/confetti.browser.js',
  'icons/icon-192.png',
  'icons/icon-512.png',
  'icons/apple-touch-icon.png'
];

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k.startsWith('golden-pace-') && k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  // Never touch other sites (the Gemini nutrition call must always go to the network).
  if (url.origin !== self.location.origin) return;
  // Signup, downloads and admin pages are live server responses; never serve them from the cache.
  if (/^\/(api|admin|guide)\//.test(url.pathname) || url.pathname === '/healthz') return;

  // Cache first for speed and offline use, refreshed in the background.
  event.respondWith(
    caches.open(CACHE).then(async cache => {
      const cached = await cache.match(req, { ignoreSearch: true });
      const refresh = fetch(req).then(res => {
        if (res && res.ok) cache.put(req, res.clone());
        return res;
      }).catch(() => null);
      if (cached) { event.waitUntil(refresh); return cached; }
      const fresh = await refresh;
      if (fresh) return fresh;
      if (req.mode === 'navigate') {
        const toApp = url.pathname === '/app';
        return (await cache.match(toApp ? 'app' : 'welcome.html')) || (await cache.match('index.html')) || Response.error();
      }
      return Response.error();
    })
  );
});
