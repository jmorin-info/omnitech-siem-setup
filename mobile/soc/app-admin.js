/* Console SOC : espace Administration (réservé aux administrateurs SOC).
 * Toutes les vérifications de sécurité sont faites par le serveur (rôle, origine,
 * jeton anti-CSRF, réseau interne, validation des entrées). Cette page ne fait
 * qu'afficher les données et préparer les demandes :
 *   1. simulation (aperçu avant/après, refus éventuel) ;
 *   2. confirmation explicite avec motif ;
 *   3. pour les actions à fort impact, validation par un second administrateur.
 * Compatible CSP stricte : aucun script en ligne, gestionnaires data-on* résolus
 * par app-csp.js ; les attributs ne contiennent que des indices entiers.
 */
(function () {
  "use strict";
  var ADM = { me: null, tab: "requests", data: {}, prep: null, refs: [], detq: "", auditq: "" };
  var TABS = [
    ["requests", "Validations"], ["access", "Accès"], ["fp", "Faux positifs"], ["soar", "SOAR"],
    ["detections", "Détections"], ["settings", "Paramètres"], ["services", "Supervision"], ["audit", "Journal"]
  ];
  var TAB_API = { requests: "/admin/requests", access: "/admin/users", fp: "/admin/fp", soar: "/admin/soar",
    detections: "/admin/detections", settings: "/admin/settings", services: "/admin/services", audit: "/admin/audit?limit=300" };
  var STATUS = { en_attente: "En attente", approuvee: "Approuvée", rejetee: "Rejetée", expiree: "Expirée",
    faite: "Faite", echec: "Échec", transmise: "Transmise à l'exécuteur", simulee: "Simulée", refusee: "Refusée" };
  var EVENT = { simulation: "Simulation", demande: "Demande", approbation: "Approbation", rejet: "Rejet",
    execution: "Exécution", execution_privilegiee: "Exécution privilégiée", refus: "Refus" };

  function h(s) {
    return (s == null ? "" : String(s)).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function q(sel) { return document.querySelector(sel); }
  function val(id) { var el = document.getElementById(id); return el ? String(el.value || "").trim() : ""; }
  function fmtTs(v) { return String(v || "").slice(0, 16).replace("T", " "); }
  function fmtEpoch(s) {
    if (!s) return "";
    try { return new Date(s * 1000).toLocaleString("fr", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" }); }
    catch (e) { return ""; }
  }
  function show(v) {
    if (v == null || v === "") return "—";
    if (Array.isArray(v)) return v.length ? v.join(", ") : "—";
    if (typeof v === "object") return JSON.stringify(v);
    return String(v);
  }
  function note(kind, text) {
    try {
      if (kind === "ok") toastOk(text); else if (kind === "warn") toastWarn(text); else toastErr(text);
    } catch (e) { /* toasts indisponibles */ }
  }
  function ref(obj) { ADM.refs.push(obj); return ADM.refs.length - 1; }

  function get(path) {
    return fetch("/m/api" + path, { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (r) {
        if (r.status === 401) { location.reload(); throw new Error("auth"); }
        return r.json().then(function (d) { if (!r.ok) throw new Error((d && d.error) || ("HTTP " + r.status)); return d; });
      });
  }
  function post(path, body) {
    return fetch("/m/api" + path, {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json", "X-SOC-CSRF": (ADM.me && ADM.me.csrf) || "" },
      body: JSON.stringify(body)
    }).then(function (r) {
      if (r.status === 401) { location.reload(); throw new Error("auth"); }
      return r.json().then(function (d) { d = d || {}; d._status = r.status; return d; });
    });
  }

  /* ------------------------------------------------------------ navigation */
  function ensureNav() {
    if (q("#nav a[data-p='admin']")) return;
    var a = document.createElement("a");
    a.setAttribute("data-p", "admin"); a.setAttribute("href", "#p=admin"); a.setAttribute("role", "button");
    a.innerHTML = '<span class="ic"><svg class="svi"><use href="#i-key"></use></svg></span><span>Administration</span>';
    var after = q("#nav a[data-p='ops']");
    if (after && after.parentNode) after.parentNode.insertBefore(a, after.nextSibling); else q("#nav").appendChild(a);
    a.addEventListener("click", function (ev) {
      ev.preventDefault();
      document.querySelectorAll("#nav a").forEach(function (x) { x.classList.toggle("on", x === a); });
      document.querySelectorAll(".page").forEach(function (s) { s.classList.toggle("on", s.id === "p-admin"); });
      var tt = q("#ptitle"); if (tt) tt.textContent = "Administration SOC";
      var pd = q("#pdesc");
      if (pd) pd.innerHTML = "<b>Administration SOC</b> — rôles, faux positifs, SOAR, détections, paramètres et supervision. " +
        "Chaque action est simulée avant confirmation, journalisée, et les actions à fort impact exigent la validation d'un second administrateur.";
      render();
    });
    if ((location.hash || "").indexOf("p=admin") >= 0) setTimeout(function () { a.click(); }, 50);
  }

  function init() {
    get("/admin/me").then(function (me) {
      ADM.me = me;
      if (me && me.is_admin) ensureNav();
    }).catch(function () { /* non connecté ou backend ancien : pas d'espace Administration */ });
  }

  /* ------------------------------------------------------------ rendu */
  function banner() {
    var m = ADM.me || {}, items = [];
    items.push('<span class="adm-pill">Compte : <b>' + h(m.user) + "</b> (" + h(m.role_label || m.role) + ")</span>");
    items.push('<span class="adm-pill ' + (m.writes_allowed ? "ok" : "crit") + '">Réseau : ' + (m.client_internal ? "interne" : "externe") +
      (m.writes_allowed ? " — écritures autorisées" : " — écritures refusées (réseaux internes uniquement)") + "</span>");
    if (m.dry_run) items.push('<span class="adm-pill warn">Mode simulation global : aucune action n\'est appliquée</span>');
    items.push('<span class="adm-pill">' + (m.self_approve ? "Auto-validation autorisée" : "Validation par un second administrateur") + "</span>");
    if (!m.self_approve && (m.admins || 0) < 2)
      items.push('<span class="adm-pill warn">Un seul administrateur : les actions à fort impact ne pourront pas être validées</span>');
    return '<div class="adm-banner">' + items.join("") + "</div>";
  }

  function tabs() {
    var pend = ((ADM.data.requests || {}).requests || []).filter(function (r) { return r.status === "en_attente"; }).length;
    return '<div class="adm-tabs" role="tablist" aria-label="Rubriques d\'administration">' + TABS.map(function (t, i) {
      var sel = ADM.tab === t[0];
      return '<button type="button" role="tab" class="adm-tab" aria-selected="' + sel + '" data-onclick="admTab(' + i + ')">' +
        h(t[1]) + (t[0] === "requests" && pend ? ' <span class="adm-count">' + pend + "</span>" : "") + "</button>";
    }).join("") + "</div>";
  }

  function render() {
    var root = q("#admRoot");
    if (!root) return;
    if (!ADM.me || !ADM.me.is_admin) { root.innerHTML = '<div class="empty">Espace réservé aux administrateurs SOC.</div>'; return; }
    root.innerHTML = banner() + tabs() + '<div id="admPanel"></div><div id="admBody"><div class="muted">Chargement…</div></div>';
    load(ADM.tab);
  }

  function load(tab) {
    var path = TAB_API[tab];
    get(path).then(function (d) {
      ADM.data[tab] = d;
      if (ADM.tab !== tab) return;
      ADM.refs = [];
      var body = q("#admBody");
      if (body) body.innerHTML = RENDER[tab](d);
      if (tab === "requests") { var t = q(".adm-tabs"); if (t) t.outerHTML = tabs(); }
    }).catch(function (e) {
      var body = q("#admBody");
      if (body && ADM.tab === tab) body.innerHTML = '<div class="card"><p class="muted">Données indisponibles : ' + h(e.message) + "</p></div>";
    });
    if (tab !== "requests") get(TAB_API.requests).then(function (d) { ADM.data.requests = d; var t = q(".adm-tabs"); if (t) t.outerHTML = tabs(); }).catch(function () {});
  }

  function card(title, tag, inner) {
    return '<div class="card adm-card"><h3><span>' + h(title) + "</span>" + (tag ? '<span class="tag">' + h(tag) + "</span>" : "") + "</h3>" + inner + "</div>";
  }
  function row(main, meta, actions) {
    return '<div class="adm-row"><div class="adm-main">' + main + (meta ? '<div class="adm-meta">' + meta + "</div>" : "") +
      "</div>" + (actions ? '<div class="adm-actions">' + actions + "</div>" : "") + "</div>";
  }
  function btn(label, handler, kind) {
    return '<button type="button" class="iconbtn adm-btn' + (kind ? " " + kind : "") + '" data-onclick="' + handler + '">' + h(label) + "</button>";
  }
  function field(id, label, input) {
    return '<label class="adm-field" for="' + id + '"><span>' + h(label) + "</span>" + input + "</label>";
  }
  function input(id, ph, max, type) {
    return '<input id="' + id + '" type="' + (type || "text") + '" maxlength="' + (max || 120) + '" placeholder="' + h(ph || "") + '" autocomplete="off">';
  }

  var RENDER = {
    requests: function (d) {
      var rs = d.requests || [];
      if (!rs.length) return card("Demandes d'administration", "", '<div class="empty">Aucune demande.</div>');
      var me = (ADM.me.user || "").toLowerCase();
      return card("Demandes d'administration", "validité " + Math.round((d.approval_ttl_s || 86400) / 3600) + " h · revalidées avant exécution",
        rs.map(function (r) {
          var p = r.preview || {}, i = ref(r), mine = String(r.requested_by || "").toLowerCase() === me;
          var exe = r.execution ? " · exécuteur : " + h(STATUS[r.execution.status] || r.execution.status) + (r.execution.resultat ? " (" + h(r.execution.resultat) + ")" : "") : "";
          var res = r.result && (r.result.error || r.result.message) ? " · " + h(r.result.error || r.result.message) : "";
          var actions = "";
          if (r.status === "en_attente") {
            actions = (mine && !d.self_approve) ? '<span class="muted">En attente d\'un second administrateur</span>' :
              '<input id="admDec' + i + '" maxlength="300" placeholder="Motif (obligatoire pour un rejet)" aria-label="Motif de la décision">' +
              btn("Approuver", "admDecide(" + i + ",'approuver')", "pri") + btn("Rejeter", "admDecide(" + i + ",'rejeter')");
          }
          return row('<span class="adm-chip st-' + h(r.status) + '">' + h(STATUS[r.status] || r.status) + "</span> <b>" + h(r.label || r.action) + "</b> " +
              '<span class="mono">' + h(show(r.params && (r.params.user || r.params.ip || r.params.value || r.params.key || r.params.unit || r.params.id || r.params.entity))) + "</span>",
            "Avant : " + h(show(p.before)) + " · Après : " + h(show(p.after)) + "<br>Motif : " + h(r.motif) +
              " · demandé par " + h(r.requested_by) + " le " + h(fmtTs(r.requested_at)) +
              (r.status === "en_attente" ? " · expire le " + h(fmtEpoch(r.expires_ts)) : "") +
              (r.decided_by ? " · décision de " + h(r.decided_by) + (r.decision_motif ? " (" + h(r.decision_motif) + ")" : "") : "") + exe + res,
            actions);
        }).join(""));
    },

    access: function (d) {
      var us = d.users || [];
      var list = us.map(function (u) {
        var i = ref(u);
        return row("<b>" + h(u.user) + "</b> " + '<span class="adm-chip">' + h(u.role) + "</span>",
          u.source === "configuration" ? "Défini dans la configuration du serveur (SOC_ADMINS), non modifiable ici" :
            "Attribué par " + h(u.by) + " le " + h(fmtTs(u.ts)) + (u.motif ? " · " + h(u.motif) : ""),
          u.modifiable ? btn("Modifier", "admRoleEdit(" + i + ")") : "");
      }).join("") || '<div class="empty">Aucun rôle explicite.</div>';
      var form = '<div class="adm-form">' + field("admRoleUser", "Compte (identifiant Graylog)", input("admRoleUser", "ex. jdupont", 64)) +
        field("admRoleRole", "Rôle", '<select id="admRoleRole"><option value="lecteur">Lecteur</option><option value="analyste">Analyste</option>' +
          '<option value="administrateur">Administrateur</option><option value="aucun">Retirer le rôle explicite</option></select>') +
        btn("Simuler la modification", "admRoleSet()", "pri") + "</div>";
      return card("Comptes et rôles", "rôle par défaut des autres comptes : " + d.default_role, list) +
        card("Attribuer un rôle", "l'ajout ou le retrait d'un administrateur exige une validation", form +
          '<p class="muted adm-help">Lecteur : consultation seule. Analyste : incidents, notes, faux positifs depuis les détections, surveillance d\'entités. ' +
          "Administrateur : espace Administration, demandes SOAR, notifications. L'authentification reste assurée par Graylog.</p>");
    },

    fp: function (d) {
      var rs = d.rules || [];
      var list = rs.map(function (r) {
        var i = ref(r);
        return row('<span class="mono">' + h(r.entity) + "</span> " + '<span class="adm-chip">' + h(r.tag || r.title_sub || "toutes détections non critiques") + "</span>",
          "Jusqu'au " + h(fmtEpoch(r.until)) + " · par " + h(r.by) + (r.justification ? " · " + h(r.justification) : " · justification non tracée (règle antérieure ou ajoutée hors console)"),
          btn("Retirer", "admFpRemove(" + i + ")"));
      }).join("") || '<div class="empty">Aucun faux positif actif.</div>';
      var form = '<div class="adm-form">' + field("admFpEnt", "Entité (clé=valeur)", input("admFpEnt", "ex. src_ip=203.0.113.9 ou user=jdupont", 200)) +
        field("admFpTag", "Étiquette de détection (recommandé)", input("admFpTag", "ex. waf_scan", 60)) +
        field("admFpSub", "ou extrait du titre", input("admFpSub", "facultatif", 80)) +
        field("admFpTtl", "Durée (jours, 1 à 90)", '<input id="admFpTtl" type="number" min="1" max="90" value="30">') +
        field("admFpJust", "Justification (10 caractères minimum)", input("admFpJust", "ex. scanner autorisé du prestataire X, ticket 1234", 300)) +
        btn("Simuler l'ajout", "admFpAdd()", "pri") + "</div>";
      return (d.error ? '<div class="adm-banner"><span class="adm-pill crit">' + h(d.error) + "</span></div>" : "") +
        card("Faux positifs actifs (service de triage)", d.note || "", list) + card("Déclarer un faux positif", "sourdine du mail, l'alerte reste visible", form);
    },

    soar: function (d) {
      var p = d.params || {}, spec = d.param_spec || {};
      var head = '<div class="adm-banner"><span class="adm-pill ' + (d.mode === "simulation" ? "warn" : "ok") + '">Moteur SOAR : mode ' + h(d.mode || "inconnu") +
        "</span><span class=\"adm-pill\">IP bloquées : " + h(d.count) + "</span></div>";
      var active = (d.active || []).map(function (x) {
        var i = ref(x);
        return row('<span class="mono">' + h(x.ip) + "</span>" + (x.pays ? ' <span class="adm-chip">' + h(x.pays) + "</span>" : ""),
          h(x.detection || x.motif || "détection SOAR") + " · reste " + h(x.remaining_h) + " h", btn("Débloquer", "admSoarUnblock(" + i + ")"));
      }).join("") || '<div class="empty">Aucune IP bloquée.</div>';
      var block = '<div class="adm-form">' + field("admBlockIp", "IPv4 publique", input("admBlockIp", "ex. 203.0.113.10", 15)) +
        btn("Simuler le blocage", "admSoarBlock()", "pri") + "</div>";
      var ex = d.static_exclusions;
      var exl = ex == null ? '<div class="empty">Liste fixe illisible depuis la console.</div>' : (ex.map(function (e) {
        var i = ref(e);
        return row('<span class="mono">' + h(e.value) + "</span>", h(e.motif), btn("Retirer", "admExclRemove(" + i + ")"));
      }).join("") || '<div class="empty">Liste fixe vide.</div>');
      var exf = '<div class="adm-form">' + field("admExclVal", "IP ou réseau public (CIDR /16 minimum)", input("admExclVal", "ex. 203.0.113.0/24", 43)) +
        btn("Simuler l'ajout", "admExclAdd()", "pri") + "</div>";
      return head + card("IP bloquées", "levée automatique, liste lue par les FortiGate", active) +
        card("Blocage manuel", "fort impact : validation par un second administrateur", block) +
        card("Exclusions fixes", "jamais bloquées automatiquement", exl + exf) +
        card("Paramètres du moteur SOAR", d.env_readable ? "fichier soar.env" : "fichier illisible depuis la console", paramForm("soar", spec, p));
    },

    detections: function (d) {
      if (!d.available) return card("Détections Graylog", "", '<p class="muted">' + h(d.error || "Indisponible") + "</p>");
      ADM.dets = d.definitions || [];
      return card("Détections Graylog", d.enabled + " actives · " + d.disabled + " désactivées",
        '<input id="admDetQ" class="search" placeholder="Filtrer par titre" data-oninput="admDetFilter(this.value)" autocomplete="off" value="' + h(ADM.detq) + '">' +
        '<div id="admDetList">' + detList() + "</div>");
    },

    settings: function (d) {
      return card("Triage des alertes", d.triage_readable ? "fichier de configuration du triage" : "fichier illisible depuis la console (droits du backend)",
          paramForm("triage", d.triage_spec || {}, d.triage || {})) +
        '<p class="muted adm-help">' + h(d.note || "") + " Les valeurs sont bornées côté serveur et réécrites par l'exécuteur privilégié, avec sauvegarde du fichier." +
          " La console n'affiche ni ne pilote la couche LLM du triage : son état n'est pas vérifié ici ; sans elle, la zone grise est décidée par le score.</p>";
    },

    services: function (d) {
      var us = d.units || [];
      var hb = d.executor_heartbeat_age_s;
      var head = '<div class="adm-banner"><span class="adm-pill ' + (d.failed ? "crit" : "ok") + '">' + h(d.failed) + " unité(s) en échec sur " + us.length + "</span>" +
        '<span class="adm-pill ' + (hb != null && hb < 900 ? "ok" : "warn") + '">Exécuteur : ' + (hb == null ? "jamais exécuté" : "dernier passage il y a " + Math.round(hb / 60) + " min") + "</span>" +
        '<span class="adm-pill">Console ' + h((d.versions || {}).console_build) + " · backend " + h((d.versions || {}).backend_sha256) + "</span></div>";
      var list = us.map(function (u) {
        var i = ref(u);
        return row('<span class="adm-dot lv-' + h(u.level) + '"></span><span class="mono">' + h(u.unit) + "</span> " + '<span class="adm-chip">' + h(u.active + "/" + u.sub) + "</span>",
          h(u.description) + (u.result && u.result !== "success" ? " · résultat : " + h(u.result) : "") +
            (u.last_trigger ? " · dernier déclenchement : " + h(u.last_trigger) : "") + (u.next ? " · prochain : " + h(u.next) : "") +
            (u.started ? " · démarré : " + h(u.started) : ""),
          u.restartable ? btn("Redémarrer", "admRestart(" + i + ")") : "");
      }).join("") || '<div class="empty">Aucune unité omni-* ou oms-* trouvée.</div>';
      return head + card("Services et timers", "lecture seule · redémarrage uniquement pour la liste blanche (" + ((d.restartable || []).length ? h(d.restartable.join(", ")) : "vide") + ")", list);
    },

    audit: function (d) {
      ADM.audit = d.entries || [];
      return '<div class="adm-banner"><span class="adm-pill ' + (d.chain_ok ? "ok" : "crit") + '">' +
        (d.chain_ok ? "Chaîne d'intégrité vérifiée" : "Chaîne d'intégrité rompue à la ligne " + h(d.broken_at_line)) + "</span>" +
        '<span class="adm-pill">' + h(d.total) + " entrée(s)</span></div>" +
        card("Journal d'audit de l'administration", "ajout seul · chaînage SHA-256 · copie GELF",
          '<input id="admAuditQ" class="search" placeholder="Filtrer (compte, action, cible)" data-oninput="admAuditFilter(this.value)" autocomplete="off" value="' + h(ADM.auditq) + '">' +
          '<div id="admAuditList">' + auditList() + "</div>");
    }
  };

  function paramForm(kind, spec, cur) {
    var keys = Object.keys(spec);
    return keys.map(function (k, n) {
      var s = spec[k], id = "admP_" + kind + "_" + n, inp;
      if (s.type === "enum") inp = '<select id="' + id + '">' + s.values.map(function (v) { return '<option value="' + h(v) + '"' + (cur[k] === v ? " selected" : "") + ">" + h(v) + "</option>"; }).join("") + "</select>";
      else if (s.type === "int") inp = '<input id="' + id + '" type="number" min="' + s.min + '" max="' + s.max + '" value="' + h(cur[k] || "") + '">';
      else inp = '<input id="' + id + '" type="text" maxlength="500" value="' + h(cur[k] || "") + '">';
      var i = ref({ kind: kind, key: k, id: id });
      return row("<b>" + h(s.label || k) + '</b> <span class="mono adm-key">' + h(k) + "</span>",
        "Valeur actuelle : " + h(cur[k] != null ? cur[k] : "non définie dans ce fichier (valeur par défaut du service)") + (s.type === "int" ? " · bornes " + s.min + " à " + s.max : ""),
        inp + btn("Simuler", "admParam(" + i + ")"));
    }).join("");
  }

  function detList() {
    var qv = ADM.detq.toLowerCase();
    var ds = (ADM.dets || []).filter(function (x) { return !qv || String(x.title).toLowerCase().indexOf(qv) >= 0; }).slice(0, 200);
    return ds.map(function (x) {
      var i = ref(x), on = x.state === "ENABLED";
      return row('<span class="adm-dot lv-' + (on ? "ok" : "warn") + '"></span>' + h(x.title) + ' <span class="adm-chip">' + (on ? "active" : "désactivée") + "</span>",
        "Priorité " + h(x.priority) + (x.description ? " · " + h(x.description) : ""),
        btn(on ? "Désactiver" : "Activer", "admDetToggle(" + i + ")"));
    }).join("") || '<div class="empty">Aucune détection.</div>';
  }

  function auditList() {
    var qv = ADM.auditq.toLowerCase();
    var es = (ADM.audit || []).filter(function (e) {
      return !qv || [e.actor, e.action, e.target, e.event, e.motif].join(" ").toLowerCase().indexOf(qv) >= 0;
    }).slice(0, 300);
    return es.map(function (e) {
      var rb = e.extra && e.extra.rollback, act = "";
      if (rb && e.event === "execution") act = btn("Préparer le retour arrière", "admRollback(" + ref(rb) + ")");
      return row('<span class="adm-chip ev-' + h(e.event) + '">' + h(EVENT[e.event] || e.event) + "</span> <b>" + h(e.action) + "</b> " + '<span class="mono">' + h(e.target) + "</span>",
        h(fmtTs(e.ts)) + " · " + h(e.actor) + (e.ip ? " (" + h(e.ip) + ")" : "") + " · n° " + h(e.seq) +
          (e.before != null || e.after != null ? " · " + h(show(e.before)) + " → " + h(show(e.after)) : "") +
          (e.motif ? " · motif : " + h(e.motif) : "") + (e.result ? " · " + h(e.result) : ""),
        act);
    }).join("") || '<div class="empty">Aucune entrée.</div>';
  }

  /* ------------------------------------------------------------ simulation puis confirmation */
  function prepare(action, params) {
    if (ADM.me && !ADM.me.writes_allowed) { note("err", "Écritures d'administration refusées depuis ce réseau."); return; }
    post("/admin/action", { action: action, params: params, simulate: true }).then(function (r) {
      if (!r.ok) { note("err", r.error || "Refusé"); return; }
      ADM.prep = { action: action, params: params, preview: r.preview, label: r.label };
      var p = r.preview || {}, fort = p.impact === "fort";
      var panel = q("#admPanel");
      if (!panel) return;
      panel.innerHTML = '<div class="card adm-confirm" role="dialog" aria-labelledby="admPrepTitle">' +
        '<h3 id="admPrepTitle"><span>Simulation : ' + h(r.label) + "</span><span class=\"tag\">" + (fort ? "fort impact : validation par un second administrateur" : "exécution immédiate après confirmation") + "</span></h3>" +
        '<div class="adm-kv"><span>Avant</span><b>' + h(show(p.before)) + "</b><span>Après</span><b>" + h(show(p.after)) + "</b></div>" +
        "<ul>" + (p.effects || []).map(function (x) { return "<li>" + h(x) + "</li>"; }).join("") + "</ul>" +
        (p.warnings || []).map(function (x) { return '<p class="adm-warn">' + h(x) + "</p>"; }).join("") +
        (p.refus ? '<p class="adm-refus">Action impossible : ' + h(p.refus) + "</p>" :
          field("admMotif", "Motif (obligatoire, journalisé)", '<textarea id="admMotif" maxlength="300" rows="2"></textarea>') +
          '<div class="adm-actions">' + btn(fort ? "Soumettre à validation" : "Confirmer l'action", "admConfirm()", "pri") + btn("Annuler", "admCancel()") + "</div>") +
        (p.refus ? '<div class="adm-actions">' + btn("Fermer", "admCancel()") + "</div>" : "") + "</div>";
      try { panel.scrollIntoView({ behavior: "smooth", block: "start" }); } catch (e) { /* ancien navigateur */ }
      var m = document.getElementById("admMotif"); if (m) m.focus();
    }).catch(function () { note("err", "Connexion au SIEM interrompue."); });
  }

  window.admConfirm = function () {
    var pr = ADM.prep; if (!pr) return;
    var motif = val("admMotif");
    if (motif.length < 4) { note("warn", "Indiquer un motif (4 caractères minimum)."); return; }
    post("/admin/action", { action: pr.action, params: pr.params, motif: motif }).then(function (r) {
      if (!r.ok) { note("err", r.error || "Refusé"); return; }
      note("ok", r.message || (r.pending ? "Demande enregistrée." : "Action effectuée."));
      ADM.prep = null; var panel = q("#admPanel"); if (panel) panel.innerHTML = "";
      load(ADM.tab);
    }).catch(function () { note("err", "Connexion au SIEM interrompue."); });
  };
  window.admCancel = function () { ADM.prep = null; var panel = q("#admPanel"); if (panel) panel.innerHTML = ""; };

  window.admTab = function (i) { var t = TABS[i]; if (!t) return; ADM.tab = t[0]; window.admCancel(); render(); };
  window.admDecide = function (i, decision) {
    var r = ADM.refs[i]; if (!r) return;
    var motif = val("admDec" + i);
    if (decision === "rejeter" && motif.length < 4) { note("warn", "Un rejet exige un motif (4 caractères minimum)."); return; }
    var verb = decision === "approuver" ? "Approuver et exécuter" : "Rejeter";
    if (!window.confirm(verb + " la demande « " + (r.label || r.action) + " » de " + r.requested_by + " ?")) return;
    post("/admin/decide", { id: r.id, decision: decision, motif: motif }).then(function (res) {
      if (!res.ok) { note("err", res.error || "Refusé"); } else { note("ok", res.message || (decision === "approuver" ? "Demande approuvée." : "Demande rejetée.")); }
      load("requests");
    }).catch(function () { note("err", "Connexion au SIEM interrompue."); });
  };
  window.admRoleEdit = function (i) {
    var u = ADM.refs[i]; if (!u) return;
    var a = document.getElementById("admRoleUser"), b = document.getElementById("admRoleRole");
    if (a) a.value = u.user; if (b) b.value = u.role; if (b) b.focus();
  };
  window.admRoleSet = function () { prepare("role_set", { user: val("admRoleUser"), role: val("admRoleRole") }); };
  window.admFpAdd = function () {
    prepare("fp_add", { entity: val("admFpEnt"), tag: val("admFpTag"), title_sub: val("admFpSub"),
      ttl_days: parseInt(val("admFpTtl"), 10), justification: val("admFpJust") });
  };
  window.admFpRemove = function (i) { var r = ADM.refs[i]; if (r) prepare("fp_remove", { entity: r.entity }); };
  window.admSoarUnblock = function (i) { var r = ADM.refs[i]; if (r) prepare("soar_unblock", { ip: r.ip }); };
  window.admSoarBlock = function () { prepare("soar_block", { ip: val("admBlockIp") }); };
  window.admExclAdd = function () { prepare("soar_exclusion_add", { value: val("admExclVal") }); };
  window.admExclRemove = function (i) { var r = ADM.refs[i]; if (r) prepare("soar_exclusion_remove", { value: r.value }); };
  window.admParam = function (i) {
    var r = ADM.refs[i]; if (!r) return;
    prepare(r.kind === "soar" ? "soar_param" : "triage_param", { key: r.key, value: val(r.id) });
  };
  window.admDetToggle = function (i) { var x = ADM.refs[i]; if (x) prepare("detection_toggle", { id: x.id, enabled: x.state !== "ENABLED" }); };
  window.admDetFilter = function (v) { ADM.detq = String(v || ""); var el = q("#admDetList"); if (el) el.innerHTML = detList(); };
  window.admAuditFilter = function (v) { ADM.auditq = String(v || ""); var el = q("#admAuditList"); if (el) el.innerHTML = auditList(); };
  window.admRestart = function (i) { var u = ADM.refs[i]; if (u) prepare("service_restart", { unit: u.unit }); };
  window.admRollback = function (i) { var rb = ADM.refs[i]; if (rb) prepare(rb.action, rb.params || {}); };

  /* démarrage : après l'affichage de l'application (connexion réussie ou session existante) */
  var appEl = q("#app");
  function started() { return appEl && appEl.style.display === "grid"; }
  if (started()) init();
  else if (appEl && window.MutationObserver) {
    var mo = new MutationObserver(function () { if (started()) { mo.disconnect(); init(); } });
    mo.observe(appEl, { attributes: true, attributeFilter: ["style"] });
  }
})();
