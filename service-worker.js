const CACHE_VERSION = 'matla-jfa-v156';
const STATIC_ASSETS = [
  'Daily-Ops.html',
  'Daily-Ops.html?v=83',
  'JFA_Register.html',
  'styles_2.css',
  'Ops.js',
  'styles_2.css?v=118',
  'Ops.js?v=146',
  'JFA.js?v=86',
  'manifest.json',
  'manifest.json?v=83',
  'favicon.ico',
  'new-matla-logo.png',
  'matla-life-logo2.png',
  'Capital-Legacy.png',
  'matla-life-logo.png',
  'matla-logo.png',
  'matla-logo (1).png',
  'matla-logo-transparent.png',
  'matla-logo-transparent1.png',
  'matla-logo-transparent2.pdf',
  'pwa/icon-192.png',
  'pwa/icon-512.png',
  'pwa/apple-touch-icon-180.png',
  'pwa/apple-touch-icon-167.png',
  'pwa/apple-touch-icon-152.png',
  'pwa/splash-1242x2688.png',
  'pwa/splash-1125x2436.png',
  'pwa/splash-1668x2388.png',
  'pwa/splash-2048x2732.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_VERSION).then((cache) => cache.addAll(STATIC_ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((key) => key !== CACHE_VERSION).map((key) => caches.delete(key)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;
  const destination = request.destination || '';

  // Always prefer fresh HTML to avoid stale UI after deployments.
  if (request.mode === 'navigate' || destination === 'document') {
    event.respondWith(
      fetch(request)
        .then((response) => {
          const copy = response.clone();
          caches.open(CACHE_VERSION).then((cache) => cache.put(request, copy));
          return response;
        })
        .catch(() => caches.match(request).then((cached) => cached || caches.match('Daily-Ops.html')))
    );
    return;
  }

  // Network-first for JS/CSS/fonts to reduce stale app code issues.
  if (['script', 'style', 'worker', 'font'].includes(destination)) {
    event.respondWith(
      fetch(request)
        .then((response) => {
          const copy = response.clone();
          caches.open(CACHE_VERSION).then((cache) => cache.put(request, copy));
          return response;
        })
        .catch(() => caches.match(request))
    );
    return;
  }

  // Cache-first for media assets.
  if (['image', 'audio', 'video'].includes(destination)) {
    event.respondWith(
      caches.match(request).then((cached) => {
        if (cached) return cached;
        return fetch(request).then((response) => {
          const copy = response.clone();
          caches.open(CACHE_VERSION).then((cache) => cache.put(request, copy));
          return response;
        });
      })
    );
    return;
  }

  event.respondWith(
    caches.match(request).then((cached) => {
      if (cached) return cached;
      return fetch(request).then((response) => {
        const copy = response.clone();
        caches.open(CACHE_VERSION).then((cache) => cache.put(request, copy));
        return response;
      }).catch(() => caches.match(request));
    })
  );
});

self.addEventListener('message', (event) => {
  if (event?.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
