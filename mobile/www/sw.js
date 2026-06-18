// Service worker PWA OMNI SOC : coquille offline + réception web-push.
const CACHE = "omni-soc-v1";
const SHELL = ["/m/", "/m/index.html", "/m/manifest.json"];

self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(
    ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});

// Réseau d'abord pour l'API, cache pour la coquille (offline = dernière coquille connue).
self.addEventListener("fetch", e => {
  const u = new URL(e.request.url);
  if (u.pathname.startsWith("/m/api/")) return; // jamais de cache sur l'API
  e.respondWith(fetch(e.request).catch(() => caches.match(e.request).then(r => r || caches.match("/m/index.html"))));
});

// Web-push : payload minimal {title, body} (rien de sensible).
self.addEventListener("push", e => {
  let d = { title: "Alerte SIEM", body: "Nouvelle alerte critique" };
  try { d = e.data.json(); } catch (_) {}
  e.waitUntil(self.registration.showNotification(d.title || "Alerte SIEM", {
    body: d.body || "", icon: "/m/icon-192.png", badge: "/m/icon-192.png",
    tag: "omni-alert", renotify: true, vibrate: [120, 60, 120]
  }));
});
self.addEventListener("notificationclick", e => {
  e.notification.close();
  e.waitUntil(clients.matchAll({ type: "window" }).then(ws => {
    for (const w of ws) if (w.url.includes("/m/") && "focus" in w) return w.focus();
    return clients.openWindow("/m/");
  }));
});
