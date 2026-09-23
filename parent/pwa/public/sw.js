const SHELL = "guard-parent-shell-v2";
// Do not pin HTML to a deleted hashed bundle after a new deployment.
// Offline application-shell support needs versioned bundles; this preview caches only static metadata.
const ASSETS = ["/manifest.webmanifest", "/icon.svg"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(SHELL).then((cache) => cache.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== "GET" || url.origin !== self.location.origin || url.pathname.startsWith("/v1/") || !ASSETS.includes(url.pathname)) {
    return;
  }
  event.respondWith(caches.open(SHELL).then((cache) => cache.match(request)).then((cached) => cached || fetch(request)));
});
