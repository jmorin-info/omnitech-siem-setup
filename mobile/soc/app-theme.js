/* Console SOC : apparence définie par l'administrateur (nom, sous-titre, logo, couleurs, thème par défaut).
 * Chargé dans <head> juste après app-boot.js : applique sans délai la dernière configuration connue
 * (copie locale), puis la configuration du serveur (GET /m/api/appearance) une fois la session ouverte.
 * Compatible CSP stricte : aucun style en ligne écrit dans le HTML ; les couleurs passent par
 * document.documentElement.style.setProperty (CSSOM), que la directive style-src ne restreint pas.
 * Toute valeur absente ou invalide laisse la valeur d'origine de la feuille de style : la console
 * ne peut pas être rendue inutilisable par ce réglage.
 */
(function () {
  "use strict";
  var KEYS = ["pro-accent", "cy", "bg", "card", "fg", "mut", "pro-sidebar"];
  var HEX = /^#[0-9a-f]{6}$/;
  var LS_KEY = "soc_appearance";
  var root = document.documentElement;
  var state = { cfg: null, preview: null, logoNode: null, observer: null };

  function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function lsSet(k, v) { try { if (v == null) localStorage.removeItem(k); else localStorage.setItem(k, v); } catch (e) { /* stockage indisponible */ } }

  /* Normalise une configuration reçue (serveur ou copie locale) : tout ce qui n'est pas reconnu est ignoré. */
  function clean(raw) {
    var c = { name: "", subtitle: "", theme_default: "system", colors: { dark: {}, light: {} }, logo: null };
    if (!raw || typeof raw !== "object") return c;
    if (typeof raw.name === "string") c.name = raw.name.slice(0, 40);
    if (typeof raw.subtitle === "string") c.subtitle = raw.subtitle.slice(0, 60);
    if (raw.theme_default === "dark" || raw.theme_default === "light") c.theme_default = raw.theme_default;
    ["dark", "light"].forEach(function (m) {
      var src = raw.colors && raw.colors[m];
      if (!src || typeof src !== "object") return;
      KEYS.forEach(function (k) {
        var v = typeof src[k] === "string" ? src[k].toLowerCase() : "";
        if (HEX.test(v)) c.colors[m][k] = v;
      });
    });
    var lg = raw.logo;
    if (lg && typeof lg.url === "string" && /^\/m\/api\/appearance\/logo\?v=[0-9a-f]{1,64}$/.test(lg.url)) c.logo = { url: lg.url };
    else if (lg && typeof lg.src === "string" && /^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+\/=]+$/.test(lg.src)) c.logo = { src: lg.src };
    return c;
  }

  function mode() { return root.getAttribute("data-theme") === "light" ? "light" : "dark"; }

  function applyColors(c) {
    var cur = (c && c.colors && c.colors[mode()]) || {};
    KEYS.forEach(function (k) {
      if (cur[k]) root.style.setProperty("--" + k, cur[k]);
      else root.style.removeProperty("--" + k);
    });
    /* --blu suit l'accent du texte dans la feuille de style professionnelle */
    if (cur.cy) root.style.setProperty("--blu", cur.cy); else root.style.removeProperty("--blu");
  }

  function cssString(s) { return '"' + String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"'; }

  function applyTexts(c) {
    var name = (c && c.name) || "OMNI SOC";
    var sub = (c && c.subtitle) || "";
    window.SOC_APP_NAME = name;
    try {
      document.title = document.title.replace(/(^| · )[^·]*$/, function (m, sep) { return sep + name; });
      if (document.title.indexOf(name) < 0) document.title = name;
    } catch (e) { /* titre inchangé */ }
    if (c && c.name) root.style.setProperty("--soc-crumb", cssString(c.name + " / "));
    else root.style.removeProperty("--soc-crumb");
    var b = document.querySelector(".brand b");
    if (b) b.textContent = name;
    var s = document.querySelector(".brand span");
    if (s) {
      if (!s.hasAttribute("data-orig")) s.setAttribute("data-orig", s.textContent);
      s.textContent = sub || s.getAttribute("data-orig");
    }
    var h1 = document.querySelector("#login .lcard h1");
    if (h1) {
      if (!state.loginTitle) state.loginTitle = Array.prototype.slice.call(h1.childNodes).map(function (n) { return n.cloneNode(true); });
      if (c && c.name) h1.textContent = c.name;
      else { h1.textContent = ""; state.loginTitle.forEach(function (n) { h1.appendChild(n.cloneNode(true)); }); }
    }
  }

  function restoreLogo(el) {
    if (!state.logoNode) return;
    el.textContent = "";
    state.logoNode.forEach(function (n) { el.appendChild(n.cloneNode(true)); });
    el.classList.remove("soc-custom-logo");
    var brand = el.closest(".brand");
    if (brand) brand.classList.remove("soc-brand-wide");
  }

  // Logo large : placé au-dessus du nom pour rester lisible dans le bandeau latéral.
  function layoutLogo(el, img) {
    var brand = el.closest(".brand");
    if (!brand || !img.naturalHeight) return;
    brand.classList.toggle("soc-brand-wide", img.naturalWidth / img.naturalHeight >= 1.6);
  }

  function applyLogo(c) {
    var el = document.querySelector(".brand .logo");
    if (!el) return;
    if (!state.logoNode) state.logoNode = Array.prototype.slice.call(el.childNodes).map(function (n) { return n.cloneNode(true); });
    var src = c && c.logo ? (c.logo.src || c.logo.url) : "";
    if (!src) { restoreLogo(el); return; }
    var img = el.querySelector("img.soc-logo-img");
    if (img && img.getAttribute("src") === src) { layoutLogo(el, img); return; }
    img = document.createElement("img");
    img.className = "soc-logo-img";
    img.alt = "Logo " + ((c && c.name) || "OMNI SOC");
    img.decoding = "async";
    img.addEventListener("error", function () { restoreLogo(el); });
    img.addEventListener("load", function () { layoutLogo(el, img); });
    img.src = src;
    el.textContent = "";
    el.appendChild(img);
    el.classList.add("soc-custom-logo");
  }

  function applyDefaultTheme(c) {
    var d = c && c.theme_default;
    window.SOC_THEME_DEFAULT = d === "light" || d === "dark" ? d : null;
    var own = lsGet("soc_theme");
    if (own === "light" || own === "dark") return;
    var t = window.SOC_THEME_DEFAULT ||
      ((window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) ? "light" : "dark");
    if (root.getAttribute("data-theme") !== t) root.setAttribute("data-theme", t);
  }

  function effective() { return state.preview || state.cfg; }

  function applyAll() {
    var c = effective();
    applyDefaultTheme(c);
    applyColors(c);
    if (document.readyState !== "loading") { applyTexts(c); applyLogo(c); }
  }

  /* Changement de thème (bouton, menu, préférence système) : réappliquer les couleurs du mode. */
  try {
    state.observer = new MutationObserver(function () { applyColors(effective()); });
    state.observer.observe(root, { attributes: true, attributeFilter: ["data-theme"] });
  } catch (e) { /* navigateur ancien : couleurs du premier mode seulement */ }

  function setConfig(raw, persist) {
    state.cfg = clean(raw);
    if (persist) {
      var copy = { name: state.cfg.name, subtitle: state.cfg.subtitle, theme_default: state.cfg.theme_default, colors: state.cfg.colors };
      lsSet(LS_KEY, JSON.stringify(copy));
    }
    applyAll();
  }

  function load() {
    return fetch("/m/api/appearance", { credentials: "same-origin", headers: { Accept: "application/json" }, cache: "no-store" })
      .then(function (r) {
        if (r.status === 401) return null;
        if (!r.ok) throw new Error("HTTP " + r.status);
        return r.json();
      })
      .then(function (d) { if (d) setConfig(d, true); return d; })
      .catch(function () { /* serveur injoignable ou ancien backend : configuration locale ou d'origine */ return null; });
  }

  /* Copie locale : application immédiate, avant tout rendu. */
  var cached = null;
  try { cached = JSON.parse(lsGet(LS_KEY) || "null"); } catch (e) { cached = null; }
  setConfig(cached, false);

  document.addEventListener("DOMContentLoaded", function () {
    applyAll();
    load().then(function (d) {
      if (d) return;
      /* page de connexion : recharger après ouverture de la session */
      var app = document.getElementById("app");
      if (!app || !window.MutationObserver) return;
      var mo = new MutationObserver(function () {
        if (app.style.display === "grid") { mo.disconnect(); load(); }
      });
      mo.observe(app, { attributes: true, attributeFilter: ["style"] });
    });
  });

  /* Interface pour l'espace Administration (aperçu local, rechargement après enregistrement). */
  window.socAppearance = {
    keys: KEYS.slice(),
    current: function () { return state.cfg; },
    preview: function (raw) { state.preview = clean(raw); applyAll(); },
    endPreview: function () { state.preview = null; applyAll(); },
    reload: function () { state.preview = null; return load(); }
  };
})();
