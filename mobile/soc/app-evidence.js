/* Read-only evidence detail. All server values enter the DOM as text. */
(function () {
  "use strict";
  var dialog, body, heading, opener, request, generation = 0;
  var text = function (fr, en) { return document.documentElement.lang === "en" ? en : fr; };
  function node(tag, cls, value) {
    var el = document.createElement(tag);
    if (cls) el.className = cls;
    if (value !== undefined && value !== null) el.textContent = String(value);
    return el;
  }
  function value(v) { return v === null || v === undefined || v === "" ? "—" : typeof v === "object" ? JSON.stringify(v, null, 2) : String(v); }
  function stamp(v) {
    if (!v || !Number.isFinite(Date.parse(v))) return null;
    return new Date(v).toISOString();
  }
  function section(title) {
    var s = node("section", "evidence-section"); s.appendChild(node("h3", "", title)); body.appendChild(s); return s;
  }
  function fields(parent, obj) {
    var dl = node("dl", "evidence-fields");
    Object.keys(obj || {}).forEach(function (key) {
      dl.appendChild(node("dt", "", key)); dl.appendChild(node("dd", "", value(obj[key])));
    });
    if (!dl.children.length) parent.appendChild(node("p", "muted", text("Aucun champ fourni.", "No fields provided.")));
    else parent.appendChild(dl);
  }
  function close() {
    generation++; if (request) request.abort();
    if (dialog && dialog.open) dialog.close();
  }
  function setup() {
    if (dialog) return;
    dialog = node("dialog", "evidence-dialog"); dialog.id = "socEvidence";
    dialog.setAttribute("aria-labelledby", "socEvidenceTitle");
    var header = node("div", "evidence-header"); heading = node("h2"); heading.id = "socEvidenceTitle";
    var button = node("button", "iconbtn evidence-close", "✕"); button.type = "button";
    button.setAttribute("aria-label", text("Fermer les détails", "Close details")); button.addEventListener("click", close);
    header.appendChild(heading); header.appendChild(button); dialog.appendChild(header);
    body = node("div", "evidence-body"); body.setAttribute("aria-live", "polite"); dialog.appendChild(body);
    dialog.addEventListener("cancel", function (event) { event.preventDefault(); close(); });
    dialog.addEventListener("click", function (event) { if (event.target === dialog) { var r = dialog.getBoundingClientRect(); if (event.clientX < r.left || event.clientX > r.right || event.clientY < r.top || event.clientY > r.bottom) close(); } });
    dialog.addEventListener("close", function () { if (opener && opener.isConnected) opener.focus(); });
    // Keep Escape local when the evidence is opened over a case or an entity dossier.
    window.addEventListener("keydown", function (event) { if (dialog.open && event.key === "Escape") { event.preventDefault(); event.stopImmediatePropagation(); close(); } }, true);
    document.body.appendChild(dialog);
  }
  function render(d) {
    body.replaceChildren();
    var kinds = {message:text("Message source", "Source message"), detection:text("Message détecté", "Detected message"), alert:text("Alerte Graylog", "Graylog alert"), graylog_event:text("Alerte Graylog", "Graylog alert"), incident:text("Incident corrélé", "Correlated incident"), case:text("Incident corrélé", "Correlated incident"), attack_group:text("Regroupement ATT&CK", "ATT&CK grouping")};
    heading.textContent = d.title || text("Détail de l'événement", "Event detail");
    var summary = section(kinds[d.kind] || text("Élément observé", "Observed record"));
    fields(summary, { [text("Type", "Kind")]: d.kind, [text("Sévérité déclarée", "Reported severity")]: d.severity });
    summary.appendChild(node("pre", "evidence-message", d.message || text("Message non fourni.", "Message not provided.")));
    var provenance = d.provenance || {}, correlation = d.correlation || {}, win = provenance.window;
    var times = section(text("Horodatage et fenêtre d'observation", "Timestamp and observation window"));
    fields(times, { [text("Événement (UTC)", "Event (UTC)")]: stamp(d.ts) || d.ts, [text("Début (UTC)", "From (UTC)")]: win && (stamp(win.from) || win.from), [text("Fin (UTC)", "To (UTC)")]: win && (stamp(win.to) || win.to) });
    times.appendChild(node("p", "muted", text("Ces dates décrivent l'observation fournie ; elles n'établissent pas un enchaînement causal.", "These dates describe the supplied observation; they do not establish a causal sequence.")));
    fields(section(text("Provenance et règle", "Provenance and rule")), { [text("Source", "Source")]: provenance.source, [text("Identifiant de règle", "Rule ID")]: provenance.rule_id, [text("Signaux fournis", "Supplied signals")]: provenance.signals });
    var corr = section(text("Corrélation et limites", "Correlation and limitations"));
    fields(corr, { [text("Mode", "Mode")]: correlation.mode, [text("Éléments de corrélation fournis", "Correlation evidence supplied")]: correlation.proof_available === true ? text("Oui", "Yes") : text("Non", "No") });
    if (correlation.details && Object.keys(correlation.details).length) fields(corr, correlation.details);
    var limits = Array.isArray(correlation.limitations) ? correlation.limitations : [];
    var ul = node("ul", "evidence-limits");
    limits.forEach(function (limit) { ul.appendChild(node("li", "", value(limit))); });
    if (correlation.proof_available !== true) ul.appendChild(node("li", "", text("La preuve historique de corrélation n'est pas disponible dans cet élément.", "Historical correlation proof is not available in this record.")));
    ul.appendChild(node("li", "", text("Un regroupement par entité ou technique ATT&CK ne prouve pas à lui seul une attaque ni un lien causal.", "Grouping by entity or ATT&CK technique alone does not prove an attack or causation."))); corr.appendChild(ul);
    fields(section(text("Champs de contexte", "Context fields")), d.context);
    var entities = section(text("Pivots vers les entités", "Entity pivots"));
    (Array.isArray(d.entities) ? d.entities : []).forEach(function (entity) {
      if (!["user", "host", "ip"].includes(entity.kind) || typeof entity.value !== "string" || !entity.value) return;
      var b = node("button", "stb evidence-pivot", entity.kind + " · " + entity.value + (entity.role ? " · " + entity.role : "")); b.type = "button";
      b.addEventListener("click", function () { close(); if (window.openEntity) window.openEntity(entity.value, entity.value, 20, entity.kind); }); entities.appendChild(b);
    });
    if (!entities.querySelector("button")) entities.appendChild(node("p", "muted", text("Aucune entité typée fournie.", "No typed entity supplied.")));
    var gl = d.graylog || {}, from = stamp(gl.from), to = stamp(gl.to);
    var source = section(text("Vérification dans Graylog", "Verify in Graylog"));
    if (typeof gl.message_path === "string" && /^\/messages\/[^/?#]+\/[^/?#]+$/.test(gl.message_path)) {
      var direct = node("a", "evidence-graylog", text("Ouvrir le message source ↗", "Open source message ↗"));
      direct.href = gl.message_path; direct.target = "_blank"; direct.rel = "noopener noreferrer"; source.appendChild(direct);
    }
    if (typeof gl.query === "string" && gl.query && from && to && from <= to) {
      var a = node("a", "evidence-graylog", text("Ouvrir la recherche sur la fenêtre exacte ↗", "Open search in the exact time window ↗"));
      var params = new URLSearchParams({q:gl.query, rangetype:"absolute", from:from, to:to});
      a.href = "/search?" + params.toString(); a.target = "_blank"; a.rel = "noopener noreferrer"; source.appendChild(a);
      fields(source, { [text("Requête", "Query")]: gl.query, [text("Début UTC", "From UTC")]: from, [text("Fin UTC", "To UTC")]: to });
    } else source.appendChild(node("p", "muted", text("Fenêtre exacte indisponible : aucun lien de preuve reconstitué.", "Exact window unavailable: no reconstructed evidence link.")));
  }
  window.openSocEvidence = async function (ref) {
    setup(); if (request) request.abort(); var current = ++generation;
    if (!dialog.open) { opener = document.activeElement; dialog.showModal(); }
    heading.textContent = text("Détails et provenance", "Details and provenance");
    body.replaceChildren(node("p", "muted", text("Chargement…", "Loading…")));
    if (typeof ref !== "string" || !ref) { body.replaceChildren(node("p", "evidence-error", text("Détail indisponible pour cette ancienne ligne. Rechargez la liste pour obtenir une référence récente.", "Detail unavailable for this older row. Reload the list to obtain a recent reference."))); return; }
    request = new AbortController();
    try {
      var response = await fetch("/m/api/evidence?ref=" + encodeURIComponent(ref), {credentials:"same-origin", cache:"no-store", signal:request.signal});
      if (current !== generation) return;
      if (!response.ok) {
        var errors = {400:text("Référence invalide ou expirée. Rechargez la liste puis ouvrez à nouveau le détail.", "Invalid or expired reference. Reload the list and open the detail again."), 401:text("Session expirée. Reconnectez-vous pour consulter cet élément.", "Session expired. Sign in again to view this record."), 403:text("Votre rôle ne permet pas de consulter cet élément.", "Your role does not allow access to this record."), 404:text("L'élément n'est plus disponible dans la source.", "This record is no longer available in its source.")};
        throw new Error(errors[response.status] || text("Source momentanément indisponible. Réessayez.", "Source temporarily unavailable. Please retry."));
      }
      var data = await response.json(); if (current !== generation) return;
      if (!data || data.schema_version !== 1) throw new Error(text("Format du détail non pris en charge.", "Unsupported detail format."));
      render(data);
    } catch (error) {
      if (current !== generation || error.name === "AbortError") return;
      body.replaceChildren(node("p", "evidence-error", error instanceof TypeError ? text("Détail inaccessible hors ligne. Réessayez après reconnexion.", "Detail unavailable offline. Retry after reconnecting.") : error.message));
    }
  };
  window.bindSocEvidenceRows = function (root, rows, selector) {
    if (!root) return;
    root.querySelectorAll(selector).forEach(function (row, i) {
      var record = rows[i]; if (!record) return;
      var b = node("button", "stb evidence-open", text("Détails et provenance", "Details and provenance")); b.type = "button";
      b.addEventListener("click", function (event) { event.stopPropagation(); window.openSocEvidence(record.ref || record.evidence_ref); }); row.appendChild(b);
    });
  };
}());
