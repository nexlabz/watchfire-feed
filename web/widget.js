/* Watchfire widget — the latest items for one topic, on any page.

     <script src="https://nexlabz.github.io/watchfire-feed/widget.js"
             data-topic="npm" data-limit="5" data-theme="auto" async></script>

   data-topic  npm, pypi, rust, go, ai-tools, ci-cd, vulns, ai-platforms,
               snare — or leave it out for every security alert
   data-limit  1–20 (default 5)
   data-theme  auto, light or dark (default auto)

   It reads news.json from the same place it was loaded from and nothing
   else: no cookies, no analytics, no third-party requests. Everything it
   shows is set as text, never as HTML, and only http(s) links are kept. */
(function () {
  var me = document.currentScript;
  if (!me) return;
  var base = new URL(".", me.src).href;
  var ds = me.dataset;
  var topic = ds.topic || "";
  var limit = Math.max(1, Math.min(20, parseInt(ds.limit, 10) || 5));
  var theme = ds.theme === "light" || ds.theme === "dark" ? ds.theme : "auto";

  var host = document.createElement("div");
  me.parentNode.insertBefore(host, me.nextSibling);
  var root = host.attachShadow ? host.attachShadow({ mode: "open" }) : host;

  var light = "--bg:#fff;--fg:#16181d;--mute:#5d6470;--line:#e3e5e9;--hot:#c2410c;--ok:#15803d;";
  var dark = "--bg:#14161a;--fg:#eceef1;--mute:#9aa1ac;--line:#2a2e35;--hot:#fb923c;--ok:#4ade80;";
  var css =
    ":host{all:initial}" +
    ".w{" + (theme === "dark" ? dark : light) + "font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;" +
    "background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:10px;padding:12px 14px;max-width:520px;box-sizing:border-box}" +
    (theme === "auto" ? "@media (prefers-color-scheme:dark){.w{" + dark + "}}" : "") +
    ".h{display:flex;justify-content:space-between;align-items:baseline;gap:8px;margin:0 0 6px;font-weight:600}" +
    ".h a{color:var(--mute);font-weight:400;font-size:12px;text-decoration:none}" +
    "ul{list-style:none;margin:0;padding:0}li{padding:7px 0;border-top:1px solid var(--line)}" +
    "li a{color:var(--fg);text-decoration:none;font-weight:500}li a:hover{text-decoration:underline}" +
    ".m{color:var(--mute);font-size:12px;margin-top:2px}.do{font-size:12.5px;margin-top:3px}" +
    ".s{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.03em;margin-right:6px}" +
    ".critical,.high{color:var(--hot)}.info{color:var(--mute)}.e{color:var(--mute)}";

  function el(tag, cls, txt) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (txt) n.textContent = txt;
    return n;
  }
  function safe(u) {
    try { var x = new URL(u); return x.protocol === "https:" || x.protocol === "http:" ? x.href : null; }
    catch (e) { return null; }
  }
  function ago(iso) {
    var h = Math.round((Date.now() - new Date(iso).getTime()) / 36e5);
    if (!(h >= 0)) return "";
    return h < 1 ? "just now" : h < 48 ? h + "h ago" : Math.round(h / 24) + "d ago";
  }

  var style = el("style"); style.textContent = css; root.appendChild(style);
  var box = el("div", "w"); root.appendChild(box);
  var head = el("div", "h", "Watchfire" + (topic ? " · " + topic : ""));
  box.appendChild(head);
  var list = el("ul"); box.appendChild(list);
  list.appendChild(el("li", "e", "Loading…"));

  fetch(base + "news.json", { credentials: "omit" })
    .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
    .then(function (d) {
      var site = safe(d.site) || "https://fresh-reads.lovable.app/";
      var more = el("a", null, "more →");
      more.href = site + (topic ? "?category=" + encodeURIComponent(topic) : "");
      more.target = "_blank"; more.rel = "noopener";
      head.appendChild(more);
      var items = (d.items || []).filter(function (i) {
        var t = i.topics || [];
        return topic ? t.indexOf(topic) >= 0 : t.some(function (x) { return x !== "ai-platforms"; });
      }).slice(0, limit);
      list.textContent = "";
      if (!items.length) { list.appendChild(el("li", "e", "Nothing in the last 30 days.")); return; }
      items.forEach(function (i) {
        var url = safe(i.url); if (!url) return;
        var li = el("li");
        if (i.severity && i.severity !== "info") li.appendChild(el("span", "s " + i.severity, i.severity));
        var a = el("a", null, String(i.title || "").slice(0, 200));
        a.href = url; a.target = "_blank"; a.rel = "noopener noreferrer";
        li.appendChild(a);
        li.appendChild(el("div", "m", [i.source, i.status, ago(i.published)].filter(Boolean).join(" · ")));
        if (i.action) li.appendChild(el("div", "do", "What to do: " + String(i.action).slice(0, 200)));
        list.appendChild(li);
      });
    })
    .catch(function () { list.textContent = ""; list.appendChild(el("li", "e", "Could not load the Watchfire feed.")); });
})();
