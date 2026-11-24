/* Site-owned pages and bounded widgets. Configuration lives in the backend state directory. */
(function () {
  "use strict";
  var state = { pages: [], selected: "", me: null, config: null, catalog: null, draft: null, serial: 0, preview: null };
  var root = document.getElementById("modulesRoot");
  if (!root) return;
  function node(tag, cls, value) {
    var n = document.createElement(tag); if (cls) n.className = cls;
    if (value !== undefined) n.textContent = String(value); return n;
  }
  function button(label, fn, cls) {
    var b = node("button", cls || "iconbtn", label); b.type = "button"; b.addEventListener("click", fn); return b;
  }
  function copy(value) { return JSON.parse(JSON.stringify(value)); }
  function message(target, text, error) {
    var p = node("p", error ? "modules-error" : "muted", text); p.setAttribute("role", error ? "alert" : "status"); target.appendChild(p); return p;
  }
  function api(path, body) {
    var options = { credentials: "same-origin", headers: { Accept: "application/json" } };
    if (body) { options.method = "POST"; options.headers["Content-Type"] = "application/json";
      options.headers["X-SOC-CSRF"] = state.me && state.me.csrf || ""; options.body = JSON.stringify(body); }
    return fetch("/m/api" + path, options).then(function (r) {
      if (r.status === 401) { location.reload(); throw new Error("Session expirée"); }
      return r.json().then(function (d) { if (!r.ok || d.ok === false) throw new Error(d.error || "Source indisponible (HTTP " + r.status + ")"); return d; });
    });
  }
  function csv(value) { return String(value || "").split(",").map(function (s) { return s.trim(); }).filter(Boolean); }
  function graylogLink(id, title) {
    var a = node("a", "pro-action", title || "Ouvrir le dashboard Graylog");
    a.href = "/dashboards/" + encodeURIComponent(id); a.target = "_blank"; a.rel = "noopener noreferrer"; return a;
  }
  function table(target, columns, rows) {
    var wrap = node("div", "modules-table-wrap"), t = node("table", "modules-table"), head = node("thead"), tr = node("tr");
    columns.forEach(function (v) { tr.appendChild(node("th", "", v)); }); head.appendChild(tr); t.appendChild(head);
    var body = node("tbody"); rows.forEach(function (values) {
      var row = node("tr"); values.forEach(function (v) { row.appendChild(node("td", "", v == null ? "—" : v)); }); body.appendChild(row);
    }); t.appendChild(body); wrap.appendChild(t); target.appendChild(wrap);
  }
  function drawWidget(widget) {
    var card = node("article", "card modules-widget"); card.appendChild(node("h3", "", widget.title));
    if (widget.status !== "ok") { message(card, widget.error || widget.message || "Données indisponibles. Ce résultat ne vaut pas zéro.", true); return card; }
    var data = widget.data || {};
    if (widget.type === "count") card.appendChild(node("div", "modules-value", Number(data.value).toLocaleString("fr")));
    else if (widget.type === "messages") {
      var logs = data.messages || [];
      if (!logs.length) message(card, "Aucun journal dans le périmètre et la période choisis.");
      else table(card, ["Date", "Source", "Message"], logs.map(function (m) { return [m.timestamp, m.source, m.message]; }));
    } else {
      var buckets = data.buckets || [], max = Math.max.apply(null, [1].concat(buckets.map(function (b) { return b.count; })));
      if (!buckets.length) message(card, "Aucune donnée pour ce widget.");
      buckets.forEach(function (b) {
        var row = node("div", "modules-bucket"), label = String(b.key);
        if (widget.type === "timeseries") { var date = new Date(b.key); if (!isNaN(date.getTime())) label = date.toLocaleString("fr"); }
        row.appendChild(node("span", "modules-bucket-label", label));
        var meter = node("meter"); meter.min = 0; meter.max = max; meter.value = b.count;
        meter.setAttribute("aria-label", label + " : " + b.count); row.appendChild(meter);
        row.appendChild(node("span", "mono", Number(b.count).toLocaleString("fr"))); card.appendChild(row);
      });
    }
    return card;
  }
  function loadPage(id, target) {
    var request = ++state.serial; state.selected = id; target.replaceChildren();
    message(target, "Lecture du périmètre configuré…");
    api("/modules/page?id=" + encodeURIComponent(id)).then(function (result) {
      if (request !== state.serial) return;
      target.replaceChildren(); var p = result.page || {};
      target.appendChild(node("h2", "", p.title || "Module"));
      if (p.description) message(target, p.description);
      message(target, "Période : " + p.days + " jour(s). Streams configurés : " + (p.stream_ids || []).length + ".");
      if (p.graylog_dashboard_id) target.appendChild(graylogLink(p.graylog_dashboard_id));
      var grid = node("div", "modules-widgets"); (result.widgets || []).forEach(function (w) { grid.appendChild(drawWidget(w)); });
      target.appendChild(grid); if (result.generated) message(target, "Lecture : " + result.generated);
    }).catch(function (e) { if (request === state.serial) { target.replaceChildren(); message(target, e.message, true); } });
  }
  function renderPages() {
    root.replaceChildren(); var toolbar = node("div", "modules-toolbar");
    var label = node("label", "", "Page de l'environnement "), select = node("select"); select.id = "modulesPage";
    state.pages.forEach(function (p) { var o = node("option", "", p.title); o.value = p.id; select.appendChild(o); });
    label.appendChild(select); toolbar.appendChild(label);
    toolbar.appendChild(button("Actualiser", load));
    if (state.me && state.me.is_admin) toolbar.appendChild(button("Configurer les pages et widgets", openEditor));
    root.appendChild(toolbar); var content = node("div"); content.id = "modulesContent"; root.appendChild(content);
    if (!state.pages.length) {
      message(content, "Aucune page publiée pour votre rôle. Un administrateur peut choisir les streams de cet environnement et créer ses widgets."); return;
    }
    if (!state.pages.some(function (p) { return p.id === state.selected; })) state.selected = state.pages[0].id;
    select.value = state.selected; select.addEventListener("change", function () { loadPage(select.value, content); });
    loadPage(state.selected, content);
  }
  function load() {
    root.setAttribute("aria-busy", "true");
    return Promise.all([api("/modules"), api("/admin/me")]).then(function (values) {
      state.pages = values[0].pages || []; state.me = values[1]; renderPages();
    }).catch(function (e) { root.replaceChildren(); message(root, e.message, true); root.appendChild(button("Réessayer", load)); })
      .then(function () { root.removeAttribute("aria-busy"); });
  }
  function input(target, title, value, changed, type) {
    var label = node("label", "modules-field"), caption = node("span", "", title), n = node("input");
    n.type = type || "text"; n.value = value == null ? "" : value; label.appendChild(caption); label.appendChild(n); target.appendChild(label);
    n.addEventListener("input", function () { changed(n.value); state.preview = null; }); return n;
  }
  function choice(target, title, value, options, changed) {
    var label = node("label", "modules-field"), select = node("select"); label.appendChild(node("span", "", title));
    options.forEach(function (v) { var option = node("option", "", v[1]); option.value = v[0]; select.appendChild(option); });
    select.value = value; label.appendChild(select); target.appendChild(label);
    select.addEventListener("change", function () { changed(select.value); state.preview = null; }); return select;
  }
  function widget(type, title, field) {
    return {id: "w" + Date.now().toString(36) + Math.random().toString(36).slice(2, 7), title: title || "Nouveau widget", type: type || "count", field: field || "", size: 10};
  }
  function newPage(preset) {
    if (state.draft.pages.length >= 20) { window.alert("Vingt pages maximum."); return; }
    var name = {watchguard:"WatchGuard",unifi:"Ubiquiti UniFi",paloalto:"Palo Alto",vuln:"Vulnérabilités du développement",custom:"Nouvelle page"}[preset];
    var suggested = (state.catalog.streams || []).filter(function (s) {
      var title = s.title.toLowerCase(); return preset === "vuln" ? title.indexOf("vuln") >= 0 : title.indexOf(preset) >= 0;
    });
    var id = preset + "-" + Date.now().toString(36);
    var p = {id:id,title:name,description:"",enabled:true,min_role:"administrateur",stream_ids:suggested.length === 1 ? [suggested[0].id] : [],
      event_sources:[],integration_ids:[],query:"",days:1,graylog_dashboard_id:"",widgets:[widget("count","Événements"),widget("timeseries","Activité"),widget("terms","Sources","source"),widget("messages","Derniers journaux")]};
    if (["watchguard","unifi","paloalto"].indexOf(preset) >= 0) p.integration_ids = [preset];
    var dashboards = (state.catalog.dashboards || []).filter(function (d) { return d.title.toLowerCase().indexOf(preset === "vuln" ? "vuln" : preset) >= 0; });
    if (dashboards.length === 1) p.graylog_dashboard_id = dashboards[0].id;
    state.draft.pages.push(p); state.preview = null; renderEditor(p.id);
  }
  function renderEditor(id) {
    root.replaceChildren(); var toolbar = node("div", "modules-toolbar");
    toolbar.appendChild(button("Retour aux pages publiées", load));
    [["custom","Créer une page"],["watchguard","Préréglage WatchGuard"],["unifi","UniFi"],["paloalto","Palo Alto"],["vuln","Vulnérabilités"]].forEach(function (p) {
      toolbar.appendChild(button(p[1], function () { newPage(p[0]); }));
    }); root.appendChild(toolbar);
    root.appendChild(node("h2", "", "Pages et widgets de cet environnement"));
    message(root, "Les réglages restent sur ce serveur. Ils ne modifient pas les dashboards Graylog. Chaque page doit sélectionner au moins un stream et le rôle autorisé à consulter ses données.");
    (state.catalog.errors || []).forEach(function (e) { message(root, typeof e === "string" ? e : e.error || "Catalogue partiellement indisponible", true); });
    var layout = node("div", "modules-editor"), list = node("div", "modules-page-list"), form = node("div");
    state.draft.pages.forEach(function (p) { list.appendChild(button(p.title, function () { renderEditor(p.id); }, p.id === id ? "pro-action pro-action-primary" : "pro-action")); });
    layout.appendChild(list); layout.appendChild(form); root.appendChild(layout);
    var p = state.draft.pages.filter(function (v) { return v.id === id; })[0] || state.draft.pages[0];
    if (p) {
      var fields = node("div", "modules-fields");
      input(fields,"Titre",p.title,function (v) { p.title = v; });
      input(fields,"Description",p.description,function (v) { p.description = v; });
      choice(fields,"Publication",String(p.enabled),[["true","Publiée"],["false","Masquée"]],function (v) { p.enabled = v === "true"; });
      choice(fields,"Rôle minimum",p.min_role,[["administrateur","Administrateur SOC"],["analyste","Analyste"],["lecteur","Lecteur"]],function (v) { p.min_role = v; });
      input(fields,"Période en jours (1 à 30)",p.days,function (v) { p.days = Number(v); },"number");
      input(fields,"Sources normalisées, séparées par des virgules",p.event_sources.join(", "),function (v) { p.event_sources = csv(v); });
      input(fields,"Identifiants d'intégration",p.integration_ids.join(", "),function (v) { p.integration_ids = csv(v); });
      input(fields,"Filtre Graylog/Lucene supplémentaire",p.query,function (v) { p.query = v; });
      choice(fields,"Dashboard Graylog associé",p.graylog_dashboard_id,[["","Aucun"]].concat((state.catalog.dashboards || []).map(function (d) { return [d.id,d.title+" ("+d.widgets+" widgets)"]; })),function (v) { p.graylog_dashboard_id = v; });
      form.appendChild(fields); var streams = node("fieldset", "modules-streams"); streams.appendChild(node("legend","","Streams inclus dans la page"));
      (state.catalog.streams || []).forEach(function (s) {
        var label = node("label"), check = node("input"); check.type = "checkbox"; check.checked = p.stream_ids.indexOf(s.id) >= 0;
        check.addEventListener("change",function () { p.stream_ids = p.stream_ids.filter(function (v) { return v !== s.id; }); if(check.checked)p.stream_ids.push(s.id); state.preview=null; });
        label.appendChild(check); label.appendChild(document.createTextNode(" "+s.title)); streams.appendChild(label);
      }); form.appendChild(streams);
      var datalist = node("datalist"); datalist.id = "modulesFields";
      (state.catalog.fields || []).filter(function (f) { return typeof f === "string" || f.aggregatable; }).forEach(function (f) { var o = node("option"); o.value = typeof f === "string" ? f : f.name; datalist.appendChild(o); }); form.appendChild(datalist);
      form.appendChild(node("h3","","Widgets"));
      p.widgets.forEach(function (w,index) {
        var box = node("fieldset","modules-widget-editor"); box.appendChild(node("legend","","Widget "+(index+1)));
        input(box,"Titre",w.title,function(v){w.title=v;});
        choice(box,"Affichage",w.type,[["count","Compteur"],["timeseries","Évolution temporelle"],["terms","Répartition par champ"],["messages","Journaux"]],function(v){w.type=v;renderEditor(p.id);});
        if(w.type==="terms") {var field=input(box,"Champ agrégable",w.field,function(v){w.field=v;});field.setAttribute("list","modulesFields");}
        if(w.type==="terms"||w.type==="messages")input(box,"Nombre de lignes",w.size,function(v){w.size=Number(v);},"number");
        box.appendChild(button("Monter",function(){if(index){p.widgets.splice(index,1);p.widgets.splice(index-1,0,w);state.preview=null;renderEditor(p.id);}}));
        box.appendChild(button("Retirer ce widget",function(){p.widgets.splice(index,1);state.preview=null;renderEditor(p.id);}));form.appendChild(box);
      });
      form.appendChild(button("Ajouter un widget",function(){if(p.widgets.length<12){p.widgets.push(widget());state.preview=null;renderEditor(p.id);}}));
      form.appendChild(button("Supprimer cette page",function(){if(window.confirm("Retirer la page « "+p.title+" » de la configuration ?")){state.draft.pages=state.draft.pages.filter(function(x){return x.id!==p.id;});state.preview=null;renderEditor();}}));
    } else message(form,"Créer une page ou choisir un préréglage pour commencer.");
    var save = node("section","card modules-save"); var motif=input(save,"Motif du changement","",function(){state.preview=null;});
    var feedback=node("div"); var publishButton=button("Publier ces réglages",function(){submit(false);});publishButton.disabled=true;
    function submit(simulate) {
      feedback.replaceChildren(); publishButton.disabled=true;
      if(!simulate&&state.preview!==JSON.stringify(state.draft)){message(feedback,"Relancer la simulation après modification.",true);return;}
      api("/admin/modules",{params:state.draft,simulate:simulate,motif:motif.value}).then(function(result){
        if(simulate){state.preview=JSON.stringify(state.draft);message(feedback,"Simulation terminée. Vérifier les pages, leurs streams et leurs rôles avant de publier.");
          var pre=node("pre","modules-preview",JSON.stringify(result.preview,null,2));feedback.appendChild(pre);publishButton.disabled=!state.me.writes_allowed;
        } else {
          message(feedback,result.simulation ? "Mode simulation : aucun réglage n'a été modifié." : result.pending ? "Demande transmise pour validation dans Administration." : "Réglages enregistrés.");
          if(Number.isInteger(result.revision))state.draft.revision=result.revision;
          state.preview=null;state.config=null;
        }
      }).catch(function(e){message(feedback,e.message,true);});
    }
    save.appendChild(button("Simuler le changement",function(){submit(true);}));save.appendChild(publishButton);save.appendChild(feedback);root.appendChild(save);
    if(!state.me.writes_allowed)message(save,"Votre réseau n'autorise pas les écritures d'administration.",true);
    if(state.me.dry_run)message(save,"Le mode simulation global est actif : une publication ne modifiera pas les réglages.");
  }
  function openEditor() {
    root.replaceChildren();message(root,"Lecture des streams, dashboards et champs disponibles…");
    api("/admin/modules").then(function(result){state.config=result.config;state.catalog=result.catalog||{};state.draft=copy(state.config);state.preview=null;renderEditor();})
      .catch(function(e){root.replaceChildren();message(root,e.message,true);root.appendChild(button("Retour",load));});
  }
  window.loadSocModules=load;
  var link=document.querySelector('#nav a[data-p="modules"]');if(link)link.addEventListener("click",load);
})();
