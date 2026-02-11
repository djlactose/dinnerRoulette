const CACHE_NAME = 'dinner-v12';

// On install: skip waiting and clear all old caches
self.addEventListener('install', event => {
  self.skipWaiting();
  event.waitUntil(
    caches.keys().then(keys => Promise.all(keys.map(k => caches.delete(k))))
  );
});

// On activate: claim clients immediately
self.addEventListener('activate', event => {
  self.clients.claim();
  event.waitUntil(
    caches.keys().then(keys => Promise.all(keys.map(k => caches.delete(k))))
  );
});

// Fetch: pass through to network (no caching)
self.addEventListener('fetch', event => {
  // Let the browser handle it normally
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
  const url = event.notification.data?.url || '/';
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
