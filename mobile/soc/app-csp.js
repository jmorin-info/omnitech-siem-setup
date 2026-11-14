/* OMNITECH-SOC-20261112-CSP : gestionnaires d'événements sans script en ligne.
 * La politique CSP de /soc/ n'autorise plus 'unsafe-inline' pour les scripts : les anciens attributs
 * onclick/oninput/onchange/onkeydown/onsubmit sont devenus data-on<événement>. Ce module les exécute
 * par délégation (écoute en phase de capture sur document), avec un analyseur restreint :
 * suite d'appels « a.b(c, 'x', 3, this, event, this.value, document.getElementById('id').value) »
 * séparés par « ; ». Pas d'eval, pas d'opérateurs, pas d'accès calculé, propriétés sensibles refusées.
 * Les identifiants globaux (function, let, const) sont résolus par window.__socH (généré à la fin).
 */
(function () {
  "use strict";
  var EVTS = ["click", "input", "change", "keydown", "submit"];
  var BAD = { constructor: 1, __proto__: 1, prototype: 1, __defineGetter__: 1, __defineSetter__: 1,
              __lookupGetter__: 1, __lookupSetter__: 1, call: 1, apply: 1, bind: 1 };
  var cache = {};

  function tokenize(s) {
    var t = [], i = 0, n = s.length, c, m;
    while (i < n) {
      c = s.charAt(i);
      if (/\s/.test(c)) { i++; continue; }
      if (c === "'" || c === '"') {
        var q = c, v = ""; i++;
        while (i < n && s.charAt(i) !== q) {
          if (s.charAt(i) === "\\") {
            i++; var e = s.charAt(i);
            if (e === "n") v += "\n"; else if (e === "t") v += "\t"; else if (e === "r") v += "\r";
            else if (e === "b") v += "\b"; else if (e === "f") v += "\f";
            else if (e === "u") { v += String.fromCharCode(parseInt(s.substr(i + 1, 4), 16)); i += 4; }
            else v += e;
            i++;
          } else { v += s.charAt(i++); }
        }
        if (i >= n) throw new Error("chaîne non fermée");
        i++; t.push({ k: "s", v: v }); continue;
      }
      if (/[0-9]/.test(c) || (c === "-" && /[0-9]/.test(s.charAt(i + 1)))) {
        m = /^-?\d+(\.\d+)?(e[+-]?\d+)?/i.exec(s.slice(i)); t.push({ k: "n", v: parseFloat(m[0]) }); i += m[0].length; continue;
      }
      if (/[A-Za-z_$]/.test(c)) {
        m = /^[A-Za-z_$][\w$]*/.exec(s.slice(i)); t.push({ k: "i", v: m[0] }); i += m[0].length; continue;
      }
      if ("().,;".indexOf(c) >= 0) { t.push({ k: "p", v: c }); i++; continue; }
      throw new Error("caractère non pris en charge « " + c + " »");
    }
    return t;
  }

  function parse(s) {
    var t = tokenize(s), p = 0;
    function peek(v) { return t[p] && t[p].k === "p" && t[p].v === v; }
    function eat(v) { if (!peek(v)) throw new Error("« " + v + " » attendu"); p++; }
    function primary() {
      var x = t[p++];
      if (!x) throw new Error("fin inattendue");
      if (x.k === "s" || x.k === "n") return { t: "lit", v: x.v };
      if (x.k === "i") {
        if (x.v === "true") return { t: "lit", v: true };
        if (x.v === "false") return { t: "lit", v: false };
        if (x.v === "null") return { t: "lit", v: null };
        if (x.v === "undefined") return { t: "lit", v: undefined };
        if (BAD[x.v]) throw new Error("identifiant interdit");
        return { t: "id", v: x.v };
      }
      throw new Error("jeton inattendu « " + x.v + " »");
    }
    function postfix() {
      var e = primary();
      for (;;) {
        if (peek(".")) {
          p++; var x = t[p++];
          if (!x || x.k !== "i") throw new Error("propriété attendue");
          if (BAD[x.v]) throw new Error("propriété interdite « " + x.v + " »");
          e = { t: "get", o: e, k: x.v };
        } else if (peek("(")) {
          p++; var a = [];
          if (!peek(")")) { a.push(postfix()); while (peek(",")) { p++; a.push(postfix()); } }
          eat(")"); e = { t: "call", f: e, a: a };
        } else break;
      }
      return e;
    }
    var st = [];
    while (p < t.length) {
      if (peek(";")) { p++; continue; }
      st.push(postfix());
      if (p < t.length) eat(";");
    }
    return st;
  }

  function lookup(name) {
    var h = window.__socH;
    if (h && Object.prototype.hasOwnProperty.call(h, name)) { var v = h[name]; if (v !== undefined) return v; }
    if (name in window) return window[name];
    throw new Error("« " + name + " » introuvable");
  }
  // renvoie [objet de base, valeur]
  function ref(e, ctx) {
    switch (e.t) {
      case "lit": return [undefined, e.v];
      case "id":
        if (e.v === "this") return [undefined, ctx.el];
        if (e.v === "event") return [undefined, ctx.ev];
        if (e.v === "window") return [undefined, window];
        if (e.v === "document") return [undefined, document];
        return [undefined, lookup(e.v)];
      case "get":
        var o = ref(e.o, ctx)[1];
        if (o == null) throw new Error("lecture de « " + e.k + " » sur une valeur vide");
        return [o, o[e.k]];
      case "call":
        var r = ref(e.f, ctx), f = r[1];
        if (typeof f !== "function") throw new Error("appel d'une valeur qui n'est pas une fonction");
        var a = [];
        for (var i = 0; i < e.a.length; i++) a.push(ref(e.a[i], ctx)[1]);
        return [undefined, Function.prototype.apply.call(f, r[0] === undefined ? window : r[0], a)];
    }
    throw new Error("expression inconnue");
  }

  function run(code, el, ev) {
    var st = cache[code];
    if (!st) { st = parse(code); cache[code] = st; }
    for (var i = 0; i < st.length; i++) ref(st[i], { el: el, ev: ev });
  }
  window.socRunHandler = run;   // pour les tests

  EVTS.forEach(function (type) {
    var attr = "data-on" + type;
    document.addEventListener(type, function (ev) {
      var n = ev.target, path = [];
      if (n && n.nodeType !== 1) n = n.parentNode;
      // chemin figé avant exécution (un gestionnaire peut remplacer le DOM)
      while (n && n.nodeType === 1) { if (n.hasAttribute(attr)) path.push(n); n = n.parentNode; }
      for (var i = 0; i < path.length; i++) {
        var code = path[i].getAttribute(attr);
        try { run(code, path[i], ev); }
        catch (err) { console.error("SOC : gestionnaire " + type + " en échec (" + code + ") : " + (err && err.message || err)); }
        if (ev.cancelBubble) break;
      }
    }, true);
  });
})();

/* Anciens gestionnaires en ligne qui contenaient des opérateurs : devenus des fonctions nommées. */
function socThemeFlip() { socTheme(document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light"); }
function setLangFlip() { setLang(LANG === "fr" ? "en" : "fr"); }
function gFocusEntityEl(el) { gFocusEntity(((el && el.value) || "").trim().toLowerCase()); }
function socNavKey(ev, p) { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); goNav(p); } }
