/* Progressive presentation and accessibility; no authentication, API or data changes. */
(function () {
  "use strict";
  var q = function (selector) { return document.querySelector(selector); };
  var main = q("#app > main"), nav = q("#nav"), header = q("#app > header");
  if (!main || !nav || !header) return;
  var en = function () { return document.documentElement.lang === "en"; };
  var text = function (fr, english) { return en() ? english : fr; };
  var dataState = null;
  var apiStates = Object.create(null);
  var pageEndpoints = {
    overview:["/kpis","/timeseries","/by-tactic","/top-detections","/top-sources","/cases","/risk","/attack-graph"],
    incidents:["/cases"],detections:["/detections"],entities:["/entities","/watchlist","/entity-search"],
    attack:["/attack-matrix"],graph:["/graph"],twin:["/attack-graph"],ems:["/fortiems"],
    network:["/network"],deploy:["/deploy"],globe:["/geo-flows"],leaks:["/leaks2"],
    health:["/health"],soar:["/soar"],kpi:["/soc-kpi"],ops:["/siem-ops"],admin:["/admin/me"],report:["/report"],playbooks:["/guidance"]
  };
  function node(tag, className, value) {
    var el = document.createElement(tag);
    if (className) el.className = className;
    if (value) el.textContent = value;
    return el;
  }
  function icon(name) {
    var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "svi"); svg.setAttribute("aria-hidden", "true");
    var use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", "#i-" + name); svg.appendChild(use); return svg;
  }
  function launchSearch(query) {
    var button = header.querySelector("[data-onclick='openPal()']");
    if (!button) return;
    button.click();
    var input = q("#palIn");
    if (input && query) {input.value = query; input.dispatchEvent(new Event("input", {bubbles:true}));}
    if (input) input.focus();
  }
  var groups = [
    {fr:"Pilotage", en:"Monitoring", pages:["overview", "incidents", "detections", "kpi"]},
    {fr:"Investigation", en:"Investigation", pages:["entities", "attack", "graph", "twin", "playbooks"]},
    {fr:"Visibilité", en:"Visibility", pages:["ems", "network", "globe", "leaks"]},
    {fr:"Administration", en:"Operations", pages:["health", "soar", "ops", "admin", "deploy", "report"]}
  ];
  var labels = [];
  groups.forEach(function (group) {
    var label = node("div", "pro-nav-label"); labels.push({el:label, group:group}); nav.appendChild(label);
    group.pages.forEach(function (page) {
      var link = nav.querySelector("a[data-p='" + page + "']");
      if (!link) return;
      link.setAttribute("href", "#p=" + page); link.setAttribute("role", "button");
      link.addEventListener("click", function (event) {event.preventDefault();});
      nav.appendChild(link);
    });
  });
  nav.setAttribute("aria-label", "Navigation principale");
  var logo = q(".brand .logo");
  if (logo) {logo.textContent = ""; logo.appendChild(icon("shield")); logo.setAttribute("aria-hidden", "true");}
  var skip = node("a", "pro-skip"); skip.href = "#pro-page-title";
  skip.addEventListener("click", function (event) {event.preventDefault(); title.focus();});
  document.body.insertBefore(skip, document.body.firstChild);
  var heading = node("div", "pro-heading"), titleBlock = node("div"), eyebrow = node("div", "pro-eyebrow");
  var title = node("h1", "pro-page-title"); title.id = "pro-page-title"; title.tabIndex = -1;
  titleBlock.appendChild(eyebrow); titleBlock.appendChild(title);
  var description = q("#pdesc");
  if (description) {description.classList.add("pro-description");titleBlock.appendChild(description);}
  var actions = node("div", "pro-heading-actions");
  var investigation = node("button", "pro-action pro-action-primary"); investigation.type = "button";
  investigation.appendChild(icon("search")); var investigationLabel = node("span"); investigation.appendChild(investigationLabel);
  investigation.addEventListener("click", function () {launchSearch("");}); actions.appendChild(investigation);
  var sources = node("button", "pro-action"); sources.type = "button";
  sources.appendChild(icon("antenna"));var sourcesLabel = node("span"); sources.appendChild(sourcesLabel);
  sources.addEventListener("click", function () {var link=nav.querySelector("[data-p='health']");if(link)link.click();}); actions.appendChild(sources);
  heading.appendChild(titleBlock);heading.appendChild(actions);main.insertBefore(heading, main.firstChild);
  var search = node("form", "pro-searchbar"); search.setAttribute("role", "search"); search.appendChild(icon("search"));
  var searchLabel = node("label", "pro-sr"); searchLabel.htmlFor = "pro-search-input";
  var searchInput = node("input"); searchInput.type = "search";searchInput.id = "pro-search-input";searchInput.autocomplete="off";
  searchInput.setAttribute("aria-describedby", "pro-search-help");
  var submit = node("button", "pro-action"); submit.type="submit";
  search.appendChild(searchLabel);search.appendChild(searchInput);search.appendChild(submit);
  search.addEventListener("submit", function (event) {event.preventDefault();launchSearch(searchInput.value.trim());});
  main.insertBefore(search, heading.nextSibling);
  var context = node("div", "pro-context"), status = node("span", "pro-context-item"), statusText = node("span");
  var statusIcon = icon("refresh");statusIcon.classList.add("pro-status-icon");status.appendChild(statusIcon);status.appendChild(statusText);
  status.setAttribute("role", "status");status.setAttribute("aria-live", "polite");
  var filter = node("span", "pro-context-item pro-filter-state"), note = node("span", "pro-view-note");note.id="pro-search-help";
  context.appendChild(status);context.appendChild(filter);context.appendChild(note);main.insertBefore(context, search.nextSibling);
  var headerSearch = header.querySelector("[data-onclick='openPal()']");
  var headerSearchLabel, key;
  if (headerSearch) {
    headerSearch.classList.add("pro-header-search");headerSearch.removeAttribute("data-i18n-t");headerSearch.removeAttribute("data-i18n-al");
    headerSearch.textContent="";headerSearch.appendChild(icon("search"));headerSearchLabel=node("span");headerSearch.appendChild(headerSearchLabel);
    key=node("kbd", "", "Ctrl K");headerSearch.appendChild(key);
  }
  var filterInputs = ["incQ", "detSearch", "fTactic", "fSource", "entSearch", "gSearch", "pbSearch"];
  filterInputs.forEach(function (id) {
    var el=document.getElementById(id);if(!el)return;
    if(!el.getAttribute("aria-label")) el.setAttribute("aria-label", el.placeholder || id);
    el.addEventListener("input", update);el.addEventListener("change", update);
  });
  function currentPage() {var active=nav.querySelector("a.on");return active?active.getAttribute("data-p"):"overview";}
  function update() {
    skip.hidden=q("#app").style.display!=="grid";
    var page=currentPage(),current=nav.querySelector("a.on"),pageSection=document.getElementById("p-"+page);
    var nextTitle=q("#ptitle")?q("#ptitle").textContent:"OMNI SOC";
    if(title.textContent!==nextTitle)title.textContent=nextTitle;
    var group=groups.filter(function (item) {return item.pages.indexOf(page)>=0;})[0];
    eyebrow.textContent=text("Centre des opérations de sécurité", "Security operations center")+" / "+(group?(en()?group.en:group.fr):"");
    labels.forEach(function (item) {item.el.textContent=en()?item.group.en:item.group.fr;});
    nav.setAttribute("aria-label", text("Navigation principale", "Main navigation"));
    nav.querySelectorAll("a[data-p]").forEach(function (link) {if(link===current)link.setAttribute("aria-current","page");else link.removeAttribute("aria-current");});
    if(pageSection) {pageSection.setAttribute("aria-labelledby",title.id);var busy=q("#refBtn");pageSection.setAttribute("aria-busy",busy&&busy.getAttribute("aria-busy")==="true"?"true":"false");}
    skip.textContent=text("Aller au contenu", "Skip to content");
    investigationLabel.textContent=text("Rechercher", "Search");sourcesLabel.textContent=text("État des sources", "Source health");
    searchLabel.textContent=text("Rechercher des journaux ou une entité", "Search logs or an entity");
    searchInput.placeholder=text("Rechercher un compte, une IP, une machine ou un événement…", "Search an account, IP, host or event…");
    submit.textContent=text("Rechercher", "Search");
    note.textContent=text("Recherche globale : navigation, entités et journaux.", "Global search: navigation, entities and logs.");
    if(headerSearchLabel)headerSearchLabel.textContent=text("Recherche globale", "Global search");
    if(headerSearch)headerSearch.setAttribute("aria-label",text("Ouvrir la recherche globale", "Open global search"));
    var refreshing=q("#refBtn")&&q("#refBtn").getAttribute("aria-busy")==="true";
    context.classList.toggle("pro-refreshing",!!refreshing);
    var fresh=q("#updPill .updtxt");
    var viewStates=(pageEndpoints[page]||[]).map(function(path){return apiStates[path];}).filter(Boolean);
    var viewFailed=viewStates.some(function(state){return state.ok===false;});
    var viewCachedTimes=viewStates.filter(function(state){return state.cachedAt;}).map(function(state){return state.cachedAt;});
    var viewCachedAt=viewCachedTimes.length?Math.min.apply(null,viewCachedTimes):0;
    var cachedAt=dataState&&dataState.cachedAt;
    var coreFailed=dataState&&dataState.ok===false&&!cachedAt;
    cachedAt=cachedAt&&viewCachedAt?Math.min(cachedAt,viewCachedAt):cachedAt||viewCachedAt;
    var cachedDate=cachedAt?new Date(cachedAt).toLocaleString(en()?"en-GB":"fr-FR"):"";
    statusText.textContent=refreshing?text("Actualisation des données…", "Refreshing data…"):
      coreFailed?text("Actualisation échouée · données indisponibles ou anciennes", "Refresh failed · data unavailable or stale"):
      viewFailed?text("Données indisponibles pour cette vue · les valeurs affichées peuvent être anciennes", "Data unavailable for this view · displayed values may be stale"):
      cachedAt?text("Données en cache du ", "Cached data from ")+cachedDate:
      dataState&&dataState.ok===false?text("Actualisation échouée · données indisponibles ou anciennes", "Refresh failed · data unavailable or stale"):
      document.body.classList.contains("offline")?text("Hors ligne · données éventuellement mises en cache", "Offline · cached data may be displayed"):
      fresh?fresh.textContent:text("État des données non disponible", "Data status unavailable");
    context.classList.toggle("pro-stale",!!(cachedAt||viewFailed||(dataState&&dataState.ok===false)));
    if(pageSection)pageSection.classList.toggle("view-stale",!!(viewFailed||viewCachedAt));
    var values=[];
    if(pageSection)pageSection.querySelectorAll("input.search, .dfilter select").forEach(function (el) {if(el.value.trim())values.push(el.tagName==="SELECT"?el.options[el.selectedIndex].text:el.value.trim());});
    var chosen=pageSection&&pageSection.querySelector(".fchip[aria-pressed=true]");
    if(chosen)values.push(chosen.textContent.trim());
    filter.textContent=values.length?text("Filtres : ", "Filters: ")+values.join(" · "):text("Vue : ", "View: ")+nextTitle;
    document.querySelectorAll(".inc[data-onclick],.pi[data-onclick]").forEach(function (row) {
      if(!row.hasAttribute("tabindex")) {row.tabIndex=0;row.setAttribute("role","button");}
    });
  }
  var queued=false;
  function schedule() {if(queued)return;queued=true;requestAnimationFrame(function () {queued=false;update();});}
  document.addEventListener("soc:data-state",function (event) {dataState=event.detail;schedule();});
  document.addEventListener("soc:api-state",function (event) {
    var state=event.detail;if(!state||typeof state.path!=="string")return;
    apiStates[state.path]={ok:state.ok,cachedAt:state.cachedAt||0};schedule();
  });
  var observer=new MutationObserver(function (changes) {
    if(changes.some(function (change) {return !change.target.closest || !change.target.closest(".pro-heading,.pro-searchbar,.pro-context,.pro-nav-label");}))schedule();
  });
  [nav,q("#ptitle"),q("#updPill"),q("#refBtn"),q("#incFeed"),q("#detFeed"),q("#palList")].forEach(function (el) {
    if(el)observer.observe(el,{childList:true,subtree:true,characterData:true,attributes:true,attributeFilter:["class","aria-busy","aria-pressed"]});
  });
  observer.observe(document.documentElement,{attributes:true,attributeFilter:["lang"]});
  observer.observe(document.body,{attributes:true,attributeFilter:["class"]});
  document.addEventListener("click",function(event){if(event.target.closest("#nav,.fchip,#bnav"))schedule();});
  update();
})();
