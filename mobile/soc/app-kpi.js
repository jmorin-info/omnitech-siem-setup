/* Page « Indicateurs » de la console SOC : volume d'alertes, MTTD, MTTR, faux positifs, couverture ATT&CK.
 * Données : GET /m/api/soc-kpi?days=N (rôle analyste ou administrateur), calculées par tools/omni-soc-kpi.py.
 * CSP stricte : aucun gestionnaire en ligne ; rendu par création de noeuds DOM et textContent uniquement.
 */
(function () {
  "use strict";
  var API_KPI = "/m/api/soc-kpi";
  var state = { days: 30, loading: false };

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }
  function dur(s) {
    if (s === null || s === undefined) return "n.d.";
    s = Number(s);
    if (Math.abs(s) < 120) return Math.round(s) + " s";
    if (Math.abs(s) < 7200) return (s / 60).toFixed(1).replace(".", ",") + " min";
    if (Math.abs(s) < 172800) return (s / 3600).toFixed(1).replace(".", ",") + " h";
    return (s / 86400).toFixed(1).replace(".", ",") + " j";
  }
  function pct(v) { return v === null || v === undefined ? "n.d." : String(v).replace(".", ",") + " %"; }
  function num(v) { return v === null || v === undefined ? "n.d." : Number(v).toLocaleString("fr"); }

  function tile(label, value, sub, accent) {
    var k = el("div", "kpi " + (accent || "cy"));
    k.appendChild(el("div", "lab", label));
    k.appendChild(el("div", "val mono", value));
    if (sub) k.appendChild(el("div", "sub", sub));
    return k;
  }
  function card(title, tag) {
    var c = el("div", "card kpi-card");
    var h = el("h3");
    h.appendChild(el("span", "", title));
    if (tag) h.appendChild(el("span", "tag", tag));
    c.appendChild(h);
    return c;
  }
  function table(head, rows, numericFrom) {
    var wrap = el("div", "kpi-tblwrap");
    var t = el("table", "kpi-tbl");
    var tr = el("tr");
    head.forEach(function (h, i) { var th = el("th", i >= numericFrom ? "num" : "", h); th.scope = "col"; tr.appendChild(th); });
    var thead = el("thead"); thead.appendChild(tr); t.appendChild(thead);
    var tb = el("tbody");
    if (!rows.length) {
      var r0 = el("tr"), td0 = el("td", "muted", "Aucune donnée sur la période");
      td0.colSpan = head.length; r0.appendChild(td0); tb.appendChild(r0);
    }
    rows.forEach(function (r) {
      var row = el("tr");
      r.forEach(function (v, i) { row.appendChild(el("td", i >= numericFrom ? "num mono" : "", v)); });
      tb.appendChild(row);
    });
    t.appendChild(tb); wrap.appendChild(t);
    return wrap;
  }
  function statRow(label, st) {
    st = st || {};
    return [label, num(st.n), dur(st.mediane), dur(st.p90), dur(st.moyenne)];
  }
  function para(text, cls) { return el("p", cls || "muted kpi-note", text); }

  function render(root, d) {
    root.textContent = "";
    var a = d.alertes || {}, m = d.mttd || {}, mr = d.mttr || {}, cs = mr.dossiers || {}, so = mr.soar || {};
    var t = d.triage || {}, c = d.couverture || {}, p = d.periode || {};

    var bar = el("div", "kpi-bar");
    bar.appendChild(el("span", "muted", "Période : " + String(p.debut || "").slice(0, 16).replace("T", " ") +
      " au " + String(p.fin || "").slice(0, 16).replace("T", " ") + " (UTC)"));
    var grp = el("div", "kpi-period"); grp.setAttribute("role", "group"); grp.setAttribute("aria-label", "Période");
    [7, 30, 90].forEach(function (n) {
      var b = el("button", "iconbtn" + (state.days === n ? " on" : ""), n + " jours");
      b.type = "button"; b.setAttribute("aria-pressed", state.days === n ? "true" : "false");
      b.addEventListener("click", function () { state.days = n; load(); });
      grp.appendChild(b);
    });
    bar.appendChild(grp);
    root.appendChild(bar);

    var tiles = el("div", "grid kpis");
    tiles.appendChild(tile("Alertes", num(a.total), num(a.evenements_non_alertes) + " événements non alertes", "cy"));
    tiles.appendChild(tile("MTTD médian", dur((m.global_borne_basse || {}).mediane) + " à " + dur((m.global_borne_haute || {}).mediane),
      "bornes basse et haute ; unitaires : " + dur((m.unitaires || {}).mediane), "vio"));
    tiles.appendChild(tile("Prise en charge médiane", dur((cs.prise_en_charge || {}).mediane),
      num(cs.dossiers_periode) + " dossiers ; humaine : " + dur((cs.prise_en_charge_humaine || {}).mediane), "amb"));
    tiles.appendChild(tile("Faux positifs (triage)", pct(t.part_faux_positifs),
      "analystes : " + pct(cs.part_faux_positifs_analyste) + " des dossiers qualifiés", "grn"));
    tiles.appendChild(tile("Techniques ATT&CK actives", c.disponible ? num(c.techniques_actives) : "n.d.",
      c.disponible ? (c.tactiques_couvertes + "/" + c.tactiques_total + " tactiques ; " + num(c.techniques_actives_avec_alerte) + " avec alerte") : "définitions non lues", "blu"));
    root.appendChild(tiles);

    var g1 = el("div", "grid cols kpi-grid");
    var c1 = card("Alertes par sévérité");
    c1.appendChild(table(["Sévérité", "Alertes", "Part"], (a.par_severite || []).map(function (x) { return [x.libelle, num(x.alertes), pct(x.part)]; }), 1));
    g1.appendChild(c1);
    var c2 = card("Alertes par source", "stream Graylog d'origine");
    c2.appendChild(table(["Source", "Alertes", "Part"], (a.par_source || []).slice(0, 12).map(function (x) { return [x.titre, num(x.alertes), pct(x.part)]; }), 1));
    g1.appendChild(c2);
    root.appendChild(g1);

    var c3 = card("Détections les plus fréquentes", "15 premières");
    c3.appendChild(table(["Détection", "Alertes", "Part"], (a.par_detection || []).slice(0, 15).map(function (x) { return [x.titre, num(x.alertes), pct(x.part)]; }), 1));
    root.appendChild(c3);

    var c4 = card("MTTD : délai de détection", num(m.alertes_analysees) + " alertes analysées");
    c4.appendChild(para(m.methode || ""));
    c4.appendChild(table(["Mesure", "n", "Médiane", "p90", "Moyenne"], [
      statRow("Détections unitaires (exact)", m.unitaires),
      statRow("Agrégations, borne basse", m.agregations_borne_basse),
      statRow("Agrégations, borne haute", m.agregations_borne_haute),
      statRow("Global, borne basse", m.global_borne_basse),
      statRow("Global, borne haute", m.global_borne_haute)], 1));
    c4.appendChild(table(["Sévérité", "n", "Médiane basse", "Médiane haute", "p90 haute"], (m.par_severite || []).map(function (x) {
      return [x.libelle, num((x.borne_basse || {}).n), dur((x.borne_basse || {}).mediane), dur((x.borne_haute || {}).mediane), dur((x.borne_haute || {}).p90)];
    }), 1));
    root.appendChild(c4);

    var c5 = card("MTTR : prise en charge, clôture, réponse", num(cs.incidents_xdr_periode) + " incidents oms-xdr");
    c5.appendChild(para(cs.methode || ""));
    c5.appendChild(table(["Mesure", "n", "Médiane", "p90", "Moyenne"], [
      statRow("Prise en charge (toutes actions)", cs.prise_en_charge),
      statRow("Prise en charge (humaine)", cs.prise_en_charge_humaine),
      statRow("Clôture", cs.cloture),
      statRow("Alerte vers blocage SOAR", so.delai_alerte_blocage)], 1));
    var acts = so.actions || {};
    c5.appendChild(para("Actions SOAR : " + (Object.keys(acts).map(function (k) { return k.replace(/_/g, " ") + " " + num(acts[k]); }).join(", ") || "aucune") +
      ". Dossiers qualifiés : " + pct(cs.part_incidents_qualifies) + " des incidents."));
    root.appendChild(c5);

    var g2 = el("div", "grid cols kpi-grid");
    var c6 = card("Triage des alertes", num(t.decisions_total) + " décisions");
    c6.appendChild(para(t.methode || ""));
    var dec = t.par_decision || {};
    c6.appendChild(table(["Décision", "Nombre"], Object.keys(dec).sort(function (x, y) { return dec[y] - dec[x]; }).map(function (k) { return [k, num(dec[k])]; }), 1));
    c6.appendChild(para("Faux positifs (règles FP) : " + num(t.faux_positifs) + " (" + pct(t.part_faux_positifs) + ") ; rejets du juge LLM : " +
      num(t.rejets_juge_llm) + " ; bruit écarté sous le seuil : " + pct(t.part_bruit_sous_seuil) + "."));
    g2.appendChild(c6);
    var c7 = card("Couverture ATT&CK", c.disponible ? num(c.definitions_actives) + " définitions actives" : "indisponible");
    if (c.disponible) {
      c7.appendChild(para(c.methode || ""));
      c7.appendChild(table(["Tactique", "Techniques"], (c.par_tactique || []).map(function (x) { return [x.tactique, num(x.techniques)]; }), 1));
      c7.appendChild(para(num(c.definitions_actives_sans_alerte_periode) + " définition(s) active(s) sans alerte sur la période ; " +
        num((c.declarees_sans_definition_active || []).length) + " technique(s) du référentiel sans définition active."));
    } else {
      c7.appendChild(para(c.raison || "Couverture non calculée."));
    }
    g2.appendChild(c7);
    root.appendChild(g2);

    var c8 = card("Lacunes de données", "ce qui n'est pas mesurable aujourd'hui");
    var ul = el("ul", "kpi-gaps");
    (d.lacunes || []).concat(d.avertissements || []).forEach(function (x) { ul.appendChild(el("li", "", x)); });
    if (!ul.childNodes.length) ul.appendChild(el("li", "", "Aucune lacune signalée."));
    c8.appendChild(ul);
    c8.appendChild(para("Calcul : " + String(d.genere_le || "") + " ; mis en cache 10 minutes côté serveur."));
    root.appendChild(c8);
  }

  function message(root, text) {
    root.textContent = "";
    var box = el("div", "card");
    box.appendChild(para(text, "muted"));
    var b = el("button", "iconbtn", "Réessayer"); b.type = "button";
    b.addEventListener("click", load);
    box.appendChild(b);
    root.appendChild(box);
  }

  function load() {
    var root = document.getElementById("kpiRoot");
    if (!root || state.loading) return;
    state.loading = true;
    root.setAttribute("aria-busy", "true");
    if (!root.firstChild) root.appendChild(para("Calcul des indicateurs en cours..."));
    fetch(API_KPI + "?days=" + state.days, { credentials: "same-origin" }).then(function (r) {
      if (r.status === 401) throw "auth";
      if (r.status === 403) throw "role";
      if (!r.ok) throw "http";
      return r.json();
    }).then(function (d) { render(root, d || {}); }).catch(function (e) {
      if (e === "auth") { location.reload(); return; }
      message(root, e === "role" ? "Les indicateurs sont réservés aux rôles analyste et administrateur."
        : "Indicateurs indisponibles : la recherche ou l'outil de calcul ne répond pas.");
    }).then(function () { state.loading = false; root.removeAttribute("aria-busy"); });
  }
  window.loadSocKpi = load;

  var link = document.querySelector('#nav a[data-p="kpi"]');
  if (link) link.addEventListener("click", function () {
    var t = document.getElementById("ptitle");
    if (t) t.textContent = document.documentElement.lang === "en" ? "SOC indicators" : "Indicateurs SOC";
    load();
  });
})();
