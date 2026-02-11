const CACHE_NAME = 'dinner-v11';

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
