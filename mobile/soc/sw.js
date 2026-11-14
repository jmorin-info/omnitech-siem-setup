/* Service worker de la console OMNI SOC (/soc/) — OMNITECH, 12/11/2026 (v4 : CSP stricte, scripts dans app*.js).
 * - Coquille de l'application en cache versionné (VERSION) : ouverture instantanée et hors ligne.
 * - Navigation : réseau d'abord (délai 5 s), puis dernière coquille connue.
 * - Bibliothèques et images de /soc/ : cache d'abord.
 * - API /m/api/ : seules quelques lectures sont gardées (24 h au plus) pour l'écran hors ligne ;
 *   jamais les POST, le flux temps réel, la recherche ni les fiches entité. Purge à la déconnexion.
 * - Notifications push (VAPID) : le clic ouvre la page indiquée par le serveur (incident, entité).
 * - Mise à jour : la nouvelle version attend ; la page propose « Recharger » (message skip-waiting).
 */
"use strict";
const VERSION = "soc-v4-202611122130";
const SHELL_CACHE = "soc-shell-" + VERSION;
const DATA_CACHE = "soc-data-v1";
const CFG_CACHE = "soc-cfg";
const DATA_MAX_AGE_MS = 24 * 3600 * 1000;
const SHELL = [
  "/soc/", "/soc/manifest.webmanifest", "/soc/chart.min.js",
  "/soc/app-boot.js?v=202611122130", "/soc/app-csp.js?v=202611122130", "/soc/app-loader.js?v=202611122130", "/soc/app.js?v=202611122130", "/soc/app-soar.js?v=202611122130", "/soc/app-v3.js?v=202611122130", "/soc/app-handlers.js?v=202611122130",
  "/soc/icons/icon-192.png", "/soc/icons/icon-512.png", "/soc/icons/maskable-192.png",
  "/soc/icons/badge-96.png", "/soc/icons/favicon-32.png", "/soc/icons/apple-touch-180.png"
];
// lectures gardées pour l'écran hors ligne (chemin exact, paramètres compris dans la clé)
const DATA_OK = new Set(["me", "kpis", "timeseries", "by-tactic", "top-detections", "top-sources", "cases",
  "attack-matrix", "health", "risk", "kpi-trend", "siem-ops", "soar", "detections", "leaks2", "geo", "guidance"]);

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(SHELL_CACHE).then((c) => c.addAll(SHELL.map((u) => new Request(u, { cache: "reload" })))));
  // pas de skipWaiting ici : la page propose la mise à jour (sauf première installation, sans page contrôlée)
});

self.addEventListener("activate", (e) => {
  e.waitUntil((async () => {
    const ks = await caches.keys();
    // on ne touche qu'à nos propres caches (la PWA /m/ partage l'origine)
    await Promise.all(ks.filter((k) => k.startsWith("soc-shell-") && k !== SHELL_CACHE).map((k) => caches.delete(k)));
    await purgeOldData();
    await self.clients.claim();
  })());
});

self.addEventListener("message", (e) => {
  const d = e.data || {};
  if (d.type === "skip-waiting") self.skipWaiting();
  else if (d.type === "purge-data") e.waitUntil(caches.delete(DATA_CACHE));
  else if (d.type === "cfg") e.waitUntil(setCfg(d.cfg || {}));
  else if (d.type === "version" && e.source) e.source.postMessage({ type: "version", version: VERSION });
});

async function getCfg() {
  try { const r = await (await caches.open(CFG_CACHE)).match("/soc/__cfg"); return r ? await r.json() : {}; } catch (_) { return {}; }
}
async function setCfg(cfg) {
  const c = await caches.open(CFG_CACHE);
  await c.put("/soc/__cfg", new Response(JSON.stringify(cfg), { headers: { "Content-Type": "application/json" } }));
  if (cfg.offline === false) await caches.delete(DATA_CACHE);
}
async function purgeOldData() {
  try {
    const c = await caches.open(DATA_CACHE);
    for (const req of await c.keys()) {
      const r = await c.match(req); const t = +(r && r.headers.get("X-SOC-Date")) || 0;
      if (Date.now() - t > DATA_MAX_AGE_MS) await c.delete(req);
    }
  } catch (_) {}
}

function withTimeout(p, ms) {
  return new Promise((res, rej) => { const t = setTimeout(() => rej(new Error("délai")), ms); p.then((v) => { clearTimeout(t); res(v); }, (e) => { clearTimeout(t); rej(e); }); });
}

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;
  const u = new URL(req.url);
  if (u.origin !== self.location.origin) return;

  // API : lectures autorisées seulement, réseau d'abord
  if (u.pathname.startsWith("/m/api/")) {
    const name = u.pathname.slice(7);
    if (!DATA_OK.has(name)) return;
    e.respondWith(apiNetworkFirst(req));
    return;
  }
  if (!u.pathname.startsWith("/soc/")) return;

  // navigation : réseau d'abord avec délai, puis coquille en cache
  if (req.mode === "navigate") {
    e.respondWith((async () => {
      try {
        const r = await withTimeout(fetch(req), 5000);
        if (r && r.ok) { const c = await caches.open(SHELL_CACHE); c.put("/soc/", r.clone()); }
        return r;
      } catch (_) {
        const c = await caches.open(SHELL_CACHE);
        return (await c.match("/soc/")) || new Response("<h1>Console SOC hors ligne</h1><p>Aucune copie locale disponible.</p>",
          { status: 503, headers: { "Content-Type": "text/html; charset=utf-8" } });
      }
    })());
    return;
  }
  if (u.pathname === "/soc/sw.js") return;
  // fichiers statiques de /soc/ : cache d'abord, puis réseau (et mise en cache)
  e.respondWith((async () => {
    const c = await caches.open(SHELL_CACHE);
    const hit = await c.match(req, { ignoreSearch: !/^\/soc\/app[\w-]*\.js$/.test(u.pathname) });
    if (hit) return hit;
    const r = await fetch(req);
    if (r && r.ok && r.type === "basic" && !/\.(html)$/.test(u.pathname)) c.put(req, r.clone());
    return r;
  })());
});

async function apiNetworkFirst(req) {
  const cfg = await getCfg();
  const keep = cfg.offline !== false;
  try {
    const r = await fetch(req);
    if (keep && r.ok) {
      const body = await r.clone().arrayBuffer();
      const h = new Headers(r.headers); h.set("X-SOC-Date", String(Date.now()));
      (await caches.open(DATA_CACHE)).put(req, new Response(body, { status: 200, headers: h }));
    } else if (r.status === 401) {
      await caches.delete(DATA_CACHE); // session expirée : on ne garde rien
    }
    return r;
  } catch (err) {
    if (keep) {
      const hit = await (await caches.open(DATA_CACHE)).match(req);
      const t = hit ? +(hit.headers.get("X-SOC-Date")) || 0 : 0;
      if (hit && Date.now() - t < DATA_MAX_AGE_MS) {
        const h = new Headers(hit.headers); h.set("X-SOC-Cache", String(t));
        return new Response(await hit.arrayBuffer(), { status: 200, headers: h });
      }
    }
    throw err;
  }
}

// ----- notifications push -----
self.addEventListener("push", (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (_) { try { d = { body: e.data.text() }; } catch (__) { d = {}; } }
  const url = typeof d.url === "string" && d.url.startsWith("/soc/") ? d.url : "/soc/#p=incidents";
  const crit = d.sev === "critical" || d.sev === "high";
  e.waitUntil(self.registration.showNotification(d.title || "Alerte SIEM", {
    body: d.body || "Ouvrir la console pour le détail.",
    icon: "/soc/icons/icon-192.png",
    badge: "/soc/icons/badge-96.png",
    tag: d.tag || "omni-soc",
    renotify: true,
    requireInteraction: crit,
    timestamp: Date.now(),
    vibrate: crit ? [200, 80, 200, 80, 200] : [120, 60, 120],
    data: { url },
    actions: [{ action: "ouvrir", title: "Ouvrir" }, { action: "incidents", title: "Incidents" }]
  }));
});

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const url = e.action === "incidents" ? "/soc/#p=incidents" : ((e.notification.data && e.notification.data.url) || "/soc/#p=incidents");
  e.waitUntil((async () => {
    const ws = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const w of ws) {
      if (new URL(w.url).pathname.startsWith("/soc/")) {
        try { await w.focus(); } catch (_) {}
        w.postMessage({ type: "open", url });
        return;
      }
    }
    await self.clients.openWindow(url);
  })());
});

// le navigateur a renouvelé l'abonnement : on le redéclare au serveur (session requise)
self.addEventListener("pushsubscriptionchange", (e) => {
  e.waitUntil((async () => {
    try {
      const k = await (await fetch("/m/api/vapid", { credentials: "same-origin" })).json();
      const key = Uint8Array.from(atob((k.publicKey + "=".repeat((4 - k.publicKey.length % 4) % 4)).replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
      const sub = await self.registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
      await fetch("/m/api/subscribe", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ subscription: sub }) });
    } catch (_) {}
  })());
});
