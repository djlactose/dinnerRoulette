const CACHE_NAME = 'dinner-v17';

// App shell: files to precache on install
const APP_SHELL = [
  '/',
  '/styles.css?v=4',
  '/app.js?v=21',
  '/manifest.json',
  '/icon-192.png',
  '/icon-512.png',
];

// On install: precache app shell, then skip waiting
self.addEventListener('install', event => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(APP_SHELL))
  );
});

// On activate: claim clients and remove old caches
self.addEventListener('activate', event => {
  self.clients.claim();
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    )
  );
});

// Fetch: network-first for API/navigation, cache-first for static assets
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // Skip non-GET requests (POST, PUT, DELETE, etc.)
  if (event.request.method !== 'GET') return;

  // Skip cross-origin requests (CDN scripts, fonts, etc.) — let the browser handle them
  if (url.origin !== self.location.origin) return;

  // Skip Socket.IO, API calls, and auth endpoints — always go to network
  if (url.pathname.startsWith('/api/') ||
      url.pathname.startsWith('/socket.io/')) {
    return;
  }

  // For navigation requests (HTML pages): network-first with cache fallback
  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request)
        .then(response => {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
          return response;
        })
        .catch(() => caches.match('/'))
    );
    return;
  }

  // For static assets: cache-first with network fallback
  event.respondWith(
    caches.match(event.request).then(cached => {
      if (cached) return cached;
      return fetch(event.request).then(response => {
        // Only cache successful same-origin responses
        if (response.ok && url.origin === self.location.origin) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
        }
        return response;
      });
    })
  );
});

// Push: show notification from server payload
self.addEventListener('push', event => {
  if (!event.data) return;
  const data = event.data.json();
  const options = {
    body: data.body,
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    tag: data.tag || 'dinner-roulette',
    renotify: true,
    data: { url: data.url || '/' },
  };
  event.waitUntil(
    self.registration.showNotification(data.title || 'Dinner Roulette', options)
  );
});

// Notification click: focus existing window or open new one
self.addEventListener('notificationclick', event => {
  event.notification.close();
  const rawUrl = event.notification.data?.url || '/';
  const url = rawUrl.startsWith('/') ? rawUrl : '/';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(windowClients => {
      for (const client of windowClients) {
        if (client.url.includes(self.location.origin) && 'focus' in client) {
          return client.focus();
        }
      }
      return clients.openWindow(url);
    })
  );
});
