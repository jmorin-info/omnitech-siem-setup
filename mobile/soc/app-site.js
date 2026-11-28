/* Capacités du site (GET /m/api/site) : la console ne montre que les pages des sources que le
 * site collecte et signale les fonctions non configurées (jamais un faux zéro).
 * Catalogue : integrations/sources.json ; configuration : clé « site » de /etc/omni-siem/integrations.json.
 * CSP stricte : aucun script en ligne, aucun gestionnaire on* (voir app-csp.js). */
(function () {
  "use strict";
  var applied = false;

  function navAnchor(page) { return document.querySelector('#nav a[data-p="' + page + '"]'); }

  function notice(page, text) {
    var section = document.getElementById("p-" + page);
    if (!section || section.querySelector(".site-notice")) return;
    var box = document.createElement("div");
    box.className = "mbanner site-notice";
    box.setAttribute("role", "note");
    var body = document.createElement("div");
    var title = document.createElement("b");
    title.textContent = "Non configuré sur ce site";
    var sub = document.createElement("div");
    sub.className = "msub";
    sub.textContent = text;
    body.appendChild(title); body.appendChild(sub); box.appendChild(body);
    section.insertBefore(box, section.firstChild);
  }

  function rename(name) {
    // Libellés historiques de la console : nom du site (apparence) à la place.
    if (!name || typeof I18N === "undefined") return;
    Object.keys(I18N).forEach(function (lang) {
      var dict = I18N[lang];
      Object.keys(dict).forEach(function (key) {
        if (typeof dict[key] === "string" && dict[key].indexOf("OMNITECH") >= 0) {
          dict[key] = dict[key].replace(/OMNITECH SECURITY|OMNITECH/g, name);
        }
      });
    });
  }

  function apply(site) {
    if (!site || typeof site !== "object" || !site.pages) return;
    applied = true;
    document.documentElement.setAttribute("data-site-legacy", site.legacy ? "1" : "0");
    Object.keys(site.pages).forEach(function (page) {
      var state = site.pages[page] || {};
      var anchor = navAnchor(page);
      if (state.visible === false) {
        if (anchor && anchor.classList.contains("on")) {
          var home = navAnchor("overview");
          if (home) home.click();
        }
        if (anchor && anchor.parentNode) anchor.parentNode.removeChild(anchor);
        if (typeof CMDPAGES !== "undefined") {
          var at = CMDPAGES.indexOf(page);
          if (at >= 0) CMDPAGES.splice(at, 1);
        }
      } else if (state.notice) {
        notice(page, state.notice);
      }
    });
    if (site.detections && site.detections.configured === false) {
      notice("overview", "Aucune définition d'alerte n'est provisionnée : les compteurs d'alertes, d'incidents et de tri restent vides. Les détections calculées par les pipelines et toutes les données reçues restent visibles (Santé & Collecte).");
    }
    if (!site.legacy) rename(window.SOC_APP_NAME && window.SOC_APP_NAME !== "OMNI SOC" ? window.SOC_APP_NAME : "");
    if (site.error && window.console) window.console.warn("Capacités du site :", site.error);
  }

  function load() {
    if (applied) return;
    fetch("/m/api/site", { credentials: "same-origin" }).then(function (r) {
      return r.ok ? r.json() : null;
    }).then(apply).catch(function () { /* hors ligne ou session absente : nouvel essai au prochain chargement */ });
  }

  window.socSiteApply = apply;   // tests de rendu
  document.addEventListener("soc:data-state", load);
  if (document.readyState !== "loading") load(); else document.addEventListener("DOMContentLoaded", load);
})();
