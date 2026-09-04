/* ==========================================================================
   app.js — report state, filtering and layout.

   The report is three 900x675 pages. Widget geometry below was measured off
   the published PDF export at 1:1, so the clone lines up with the original.

   Filters behave the way Looker's do: they apply to every chart backed by the
   record-level data source, and leave the model-metric charts on page 3
   untouched, because those data sources have no protocol/service/priority
   field to filter on.
   ========================================================================== */

(function () {
  "use strict";

  var D = window.IDS_DATA;
  var C = window.Charts;
  var nInt = C.nInt, nDec = C.nDec;

  /* fact tuple offsets */
  var P = 0, S = 1, F = 2, PR = 3, CL = 4, AN = 5, B = 6, CNT = 7, RSUM = 8;

  var COLOR = {
    blue: "#4185f4", red: "#ea4335", amber: "#f9ab00", green: "#34a853",
    olive: "#817717", teal: "#0097a6", other: "#c2c8dd", bubble: "#3f9c4b"
  };

  /* ------------------------------------------------------------- state */

  var state = {
    page: 0,
    filters: { protocol: [], service: [], priority: [] },
    tableState: {}
  };

  function activeFilters() {
    return ["protocol", "service", "priority"].filter(function (k) {
      return state.filters[k].length;
    });
  }

  /* index sets, rebuilt whenever filters change */
  var mask = null;
  function rebuildMask() {
    function setOf(dim, key) {
      var picked = state.filters[key];
      if (!picked.length) return null;
      var s = Object.create(null);
      picked.forEach(function (v) {
        var i = D.dims[dim].indexOf(v);
        if (i >= 0) s[i] = 1;
      });
      return s;
    }
    mask = {
      p: setOf("protocol", "protocol"),
      s: setOf("service", "service"),
      pr: setOf("priority", "priority")
    };
  }

  function keep(f) {
    return (!mask.p || mask.p[f[P]]) &&
           (!mask.s || mask.s[f[S]]) &&
           (!mask.pr || mask.pr[f[PR]]);
  }

  /* Group the cube by one column (or by a function) and sum count + risk. */
  function agg(col) {
    var out = Object.create(null);
    var pick = typeof col === "function" ? col : function (f) { return f[col]; };
    for (var i = 0; i < D.facts.length; i++) {
      var f = D.facts[i];
      if (!keep(f)) continue;
      var k = pick(f);
      if (k === null) continue;
      var c = out[k] || (out[k] = { n: 0, risk: 0 });
      c.n += f[CNT];
      c.risk += f[RSUM];
    }
    return out;
  }

  function totals() {
    var n = 0, risk = 0, anom = 0;
    for (var i = 0; i < D.facts.length; i++) {
      var f = D.facts[i];
      if (!keep(f)) continue;
      n += f[CNT];
      risk += f[RSUM];
      if (f[AN] === 1) anom += f[CNT];
    }
    return { n: n, risk: risk, anom: anom, avg: n ? risk / n : 0 };
  }

  /* rows of the aggregated Top Risk Records table, after filtering */
  function topRiskRows() {
    return D.topRisk.filter(function (r) {
      var fl = state.filters;
      return (!fl.protocol.length || fl.protocol.indexOf(r[0]) >= 0) &&
             (!fl.service.length || fl.service.indexOf(r[1]) >= 0) &&
             (!fl.priority.length || fl.priority.indexOf(r[3]) >= 0);
    }).map(function (r) {
      return { proto: r[0], service: r[1], flag: r[2], priority: r[3], risk: r[4] };
    });
  }

  function sortedPairs(map, dimNames) {
    return Object.keys(map).map(function (k) {
      return { label: dimNames ? dimNames[k] : k, value: map[k].n };
    }).sort(function (a, b) { return b.value - a.value; });
  }

  /* ------------------------------------------------------- page layout */

  var PAGES = [
    { name: "Executive Overview", widgets: execOverview },
    { name: "Traffic Analysis", widgets: trafficAnalysis },
    { name: "ML & Threat Analysis", widgets: mlThreat }
  ];

  /* ---- page 1 -------------------------------------------------------- */
  function execOverview() {
    var t = totals();
    var w = [];

    w.push(kpi(159, 84, 156, 83, "Total Traffic", nInt(t.n), COLOR.blue));
    w.push(kpi(327, 84, 156, 83, "Anomaly Traffic", nInt(t.anom), COLOR.red));
    w.push(kpi(497, 84, 172, 83, "Average Risk Score", nDec(t.avg), COLOR.amber));
    w.push(kpi(681, 84, 204, 83, "Security Health Index", nDec(100 - t.avg), COLOR.green));

    var byPrio = agg(PR);
    w.push({
      id: "prio", x: 159, y: 180, w: 404, h: 227, title: "Priority Distribution",
      render: function (host) {
        C.donut(host, {
          legend: "top",
          slices: D.dims.priority.map(function (p, i) {
            return { label: p, value: byPrio[i] ? byPrio[i].n : 0, color: C.palette[i] };
          }),
          onPick: function (label) { toggleFilter("priority", label); }
        });
      }
    });

    w.push({
      id: "threat", x: 567, y: 180, w: 318, h: 227, title: "Threat Category",
      render: function (host) {
        C.treemap(host, {
          items: D.dims.priority.map(function (p, i) {
            return { label: D.dims.category[i], value: byPrio[i] ? byPrio[i].n : 0 };
          }).filter(function (d) { return d.value > 0; }),
          onPick: function (label) {
            toggleFilter("priority", D.dims.priority[D.dims.category.indexOf(label)]);
          }
        });
      }
    });

    var rows = topRiskRows();
    w.push({
      id: "toprisk", x: 159, y: 414, w: 726, h: 192, title: "Top Risk Records",
      render: function (host) {
        C.table(host, {
          state: state.tableState.toprisk || (state.tableState.toprisk = { page: 0 }),
          rows: rows,
          pageSize: 5,
          sortKey: "risk",
          alwaysPager: true,
          columns: [
            { key: "proto", label: "Protocol Type" },
            { key: "service", label: "Service" },
            { key: "flag", label: "Flag" },
            { key: "priority", label: "Priority" },
            { key: "risk", label: "Risk Score", num: true, bar: true,
              fmt: function (v) { return nDec(v, 3); } }
          ]
        });
      }
    });

    /* the four empty placeholder boxes the report reserves along the bottom */
    [[159, 173], [340, 173], [520, 173], [701, 184]].forEach(function (b, i) {
      w.push({ id: "ph" + i, x: b[0], y: 615, w: b[1], h: 53, placeholder: true });
    });
    return w;
  }

  /* ---- page 2 -------------------------------------------------------- */
  function trafficAnalysis() {
    var w = [];
    var byProto = agg(P), byFlag = agg(F), bySvc = agg(S);

    w.push({
      id: "proto", x: 155, y: 86, w: 369, h: 197, title: "Protocol Distribution",
      render: function (host) {
        C.donut(host, {
          legend: "top",
          slices: D.dims.protocol.map(function (p, i) {
            return { label: p, value: byProto[i] ? byProto[i].n : 0, color: C.palette[i] };
          }).sort(function (a, b) { return b.value - a.value; }),
          onPick: function (label) { toggleFilter("protocol", label); }
        });
      }
    });

    w.push({
      id: "flag", x: 533, y: 86, w: 359, h: 197, title: "Flag Distribution",
      render: function (host) {
        C.donut(host, {
          legend: "right",
          labelMin: 0.055,
          slices: sortedPairs(byFlag, D.dims.flag).map(function (d, i) {
            return { label: d.label, value: d.value, color: C.palette[i % 11] };
          })
        });
      }
    });

    w.push({
      id: "pivot", x: 155, y: 287, w: 737, h: 146, title: "Protocol Priority",
      render: function (host) {
        var m = agg(function (f) { return f[P] + ":" + f[PR]; });
        var order = ["tcp", "udp", "icmp"].filter(function (p) {
          return !state.filters.protocol.length ||
                 state.filters.protocol.indexOf(p) >= 0;
        });
        var cols = D.dims.priority.filter(function (p) {
          return !state.filters.priority.length ||
                 state.filters.priority.indexOf(p) >= 0;
        });
        C.pivot(host, {
          banner: "Priority / Record Count",
          rowHead: "protocol_type",
          dash: true,
          cols: cols,
          rows: order.map(function (p) {
            var pi = D.dims.protocol.indexOf(p);
            return {
              label: p,
              values: cols.map(function (c) {
                var k = pi + ":" + D.dims.priority.indexOf(c);
                return m[k] ? m[k].n : 0;
              })
            };
          })
        });
      }
    });

    w.push({
      id: "topsvc", x: 155, y: 446, w: 371, h: 226, title: "Top 10 Service",
      render: function (host) {
        var all = sortedPairs(bySvc, D.dims.service);
        var head = all.slice(0, 9);
        var rest = all.slice(9).reduce(function (a, d) { return a + d.value; }, 0);
        var rows = head.map(function (d) {
          return { label: d.label, value: d.value, color: COLOR.blue };
        });
        if (rest > 0) rows.push({ label: "Lainnya", value: rest, color: COLOR.other,
                                  pickable: false });
        C.hbar(host, {
          rows: rows, legend: "Record Count", axisTitle: "Record Count",
          barColor: COLOR.blue,
          onPick: function (label) { toggleFilter("service", label); }
        });
      }
    });

    w.push({
      id: "bubble", x: 533, y: 446, w: 359, h: 226, title: "Top Service",
      render: function (host) {
        var byPair = agg(function (f) { return f[S] + ":" + f[CL]; });
        var stats = {};
        Object.keys(byPair).forEach(function (k) {
          var parts = k.split(":"), name = D.dims.service[parts[0]];
          var o = stats[name] || (stats[name] = { total: 0, anom: 0 });
          o.total += byPair[k].n;
          if (parts[1] === "1") o.anom += byPair[k].n;
        });
        var pts = Object.keys(stats).map(function (name) {
          return {
            label: name, x: stats[name].total,
            y: stats[name].total ? stats[name].anom / stats[name].total * 100 : 0,
            size: Math.max(stats[name].anom, 1)
          };
        }).sort(function (a, b) { return b.x - a.x; }).slice(0, 15);
        C.bubble(host, {
          points: pts, xTitle: "Total", yTitle: "Anomaly_Rate",
          legend: "service", color: COLOR.bubble,
          onPick: function (label) { toggleFilter("service", label); }
        });
      }
    });
    return w;
  }

  /* ---- page 3 -------------------------------------------------------- */
  function mlThreat() {
    var w = [];
    var rf = D.summary;
    [["Accuracy", rf.RF_Accuracy_pct], ["Precision", rf.RF_Precision_pct],
     ["Recall", rf.RF_Recall_pct], ["F1", rf.RF_F1_pct]]
      .forEach(function (kv, i) {
        w.push(kpi(178 + i * 175, 87, 149, 74, kv[0], nDec(kv[1]), COLOR.green));
      });

    w.push({
      id: "models", x: 156, y: 176, w: 354, h: 226, title: "Model Comparison",
      render: function (host) {
        var m = D.modelPerformance;
        var shorten = function (n) {
          return n.replace("K-Nearest Neighbors", "K-Nearest Neighbors");
        };
        C.groupedColumn(host, {
          categories: m.map(function (d) { return shorten(d.Model); }),
          yMin: 90, yMax: 100, ySteps: 4,
          series: [
            { name: "Accuracy", color: C.palette[0], values: m.map(function (d) { return d.Accuracy; }) },
            { name: "Precision", color: C.palette[1], values: m.map(function (d) { return d.Precision; }) },
            { name: "Recall", color: C.palette[2], values: m.map(function (d) { return d.Recall; }) },
            { name: "F1", color: C.palette[3], values: m.map(function (d) { return d.F1; }) }
          ]
        });
      }
    });

    w.push({
      id: "featimp", x: 518, y: 176, w: 370, h: 226, title: "Feature Importance",
      render: function (host) {
        var fi = D.featureImportance;
        var rows = fi.slice(0, 14).map(function (d) {
          return { label: d.Feature, value: d.Importance, color: COLOR.olive };
        });
        /* the export collapses the remainder into a "Lainnya" row */
        rows.push({ label: "Lainnya", value: fi[14].Importance, color: COLOR.other });
        C.hbar(host, {
          rows: rows, legend: "Importance", axisTitle: "Importance",
          barColor: COLOR.olive, valueLabel: "Importance",
          valueFmt: function (v) { return nDec(v); },
          tickFmt: function (v) { return nDec(v, v === 0 ? 0 : 2); }
        });
      }
    });

    w.push({
      id: "riskdist", x: 156, y: 417, w: 354, h: 248, title: "Risk Score Distribution",
      render: function (host) {
        var byB = agg(B);
        var buckets = {};
        for (var b = 0; b < 20; b++) {
          var label = b >= 10 ? "[50+)" : "[" + (b * 5) + ", " + (b * 5 + 5) + ")";
          buckets[label] = (buckets[label] || 0) + (byB[b] ? byB[b].n : 0);
        }
        /* Looker sorts this dimension as text, which is why [5, 10) sits near
           the bottom of the published chart — keep that ordering. */
        var rows = Object.keys(buckets).sort().map(function (k) {
          return { label: k, value: buckets[k], color: COLOR.teal };
        });
        C.hbar(host, {
          rows: rows, legend: "Record Count", axisTitle: "Record Count",
          barColor: COLOR.teal
        });
      }
    });

    w.push({
      id: "fxm", x: 518, y: 417, w: 370, h: 248, title: "Fitur x Model",
      render: function (host) {
        host.style.overflowY = "auto";
        C.pivot(host, {
          banner: "Model / Importance",
          rowHead: "Feature",
          metric: "Importance",
          cols: ["Gradient Boost…", "Decision Tree", "Random Forest"],
          fmt: function (v) { return v ? nDec(v) : "0"; },
          rows: D.featureModel.map(function (d) {
            return {
              label: d.Feature,
              values: [d["Gradient Boosting"], d["Decision Tree"], d["Random Forest"]]
            };
          })
        });
      }
    });
    return w;
  }

  function kpi(x, y, w, h, label, value, color) {
    return {
      id: "kpi-" + label, x: x, y: y, w: w, h: h, kpi: true,
      title: label, value: value, color: color
    };
  }

  /* ---------------------------------------------------------- rendering */

  var page = document.getElementById("page");

  function buildPage() {
    rebuildMask();
    page.innerHTML = "";

    page.appendChild(navStrip());
    page.appendChild(header());

    PAGES[state.page].widgets().forEach(function (wd) {
      page.appendChild(widgetEl(wd));
    });

    document.querySelectorAll(".rail-item").forEach(function (b, i) {
      b.classList.toggle("active", i === state.page);
    });
    document.getElementById("btnReset").disabled = !activeFilters().length;
  }

  function pos(node, wd) {
    node.style.left = wd.x + "px";
    node.style.top = wd.y + "px";
    node.style.width = wd.w + "px";
    node.style.height = wd.h + "px";
    return node;
  }

  function toolbar(wd) {
    var t = document.createElement("div");
    t.className = "tools";
    t.innerHTML =
      '<button title="Filter">' +
        '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><path d="M3 5h18l-7 8v6l-4 2v-8z"/></svg></button>' +
      '<button title="Layar penuh">' +
        '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><path d="M4 9V4h5v2H6v3zm11-5h5v5h-2V6h-3zM4 15h2v3h3v2H4zm14 3v-3h2v5h-5v-2z"/></svg></button>' +
      '<button title="Opsi lainnya">' +
        '<svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="5" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="12" cy="19" r="2"/></svg></button>';
    var btns = t.querySelectorAll("button");
    btns[1].onclick = function (e) { e.stopPropagation(); openFullscreen(wd); };
    return t;
  }

  function widgetEl(wd) {
    if (wd.kpi) {
      var k = pos(document.createElement("div"), wd);
      k.className = "kpi";
      k.innerHTML = '<div class="k-label"></div><div class="k-value"></div>';
      k.querySelector(".k-label").textContent = wd.title;
      var v = k.querySelector(".k-value");
      v.textContent = wd.value;
      v.style.color = wd.color;
      k.appendChild(toolbar(wd));
      return k;
    }
    if (wd.placeholder) {
      var ph = pos(document.createElement("div"), wd);
      ph.className = "kpi";
      return ph;
    }
    var c = pos(document.createElement("div"), wd);
    c.className = "card";
    var h = document.createElement("h3");
    h.textContent = wd.title;
    c.appendChild(h);
    var body = document.createElement("div");
    body.className = "body";
    c.appendChild(body);
    c.appendChild(toolbar(wd));
    /* charts measure their host, so paint after layout settles */
    requestAnimationFrame(function () { wd.render(body); });
    return c;
  }

  function navStrip() {
    var n = document.createElement("div");
    n.className = "nav-strip";
    n.style.cssText = "left:0;top:0;width:147px;height:675px";

    var brand = document.createElement("div");
    brand.className = "brand";
    brand.style.cssText = "position:absolute;left:0;top:0;width:147px;height:73px";
    brand.innerHTML = "<b>IDS Dashboard</b><span>Network Security<br>Analytics</span>";
    n.appendChild(brand);

    [[136, 38], [186, 38], [236, 39]].forEach(function (g, i) {
      var b = document.createElement("button");
      b.className = "navbtn" + (i === state.page ? " active" : "");
      b.style.cssText = "position:absolute;left:10px;top:" + g[0] +
                        "px;width:127px;height:" + g[1] + "px";
      b.textContent = PAGES[i].name;
      b.onclick = function () { goPage(i); };
      n.appendChild(b);
    });
    return n;
  }

  function header() {
    var h = document.createElement("div");
    h.className = "hdr";
    h.style.cssText = "left:147px;top:0;width:753px;height:73px";
    h.innerHTML =
      '<h1 style="position:absolute;left:6px;top:4px;width:330px">' +
      'NETWORK INTRUSION DETECTION DASHBOARD</h1>' +
      '<p style="position:absolute;left:6px;top:44px;width:360px">' +
      'Real-time Monitoring &amp; Security Analytics</p>';

    [["protocol", "Protocol", 338], ["service", "Service", 442],
     ["priority", "Priority", 546]].forEach(function (f) {
      var b = document.createElement("button");
      b.className = "filt" + (state.filters[f[0]].length ? " on" : "");
      b.style.cssText = "position:absolute;left:" + f[2] +
                        "px;top:28px;width:100px;height:30px";
      b.innerHTML = "<span></span><span class='caret'>▼</span>";
      b.firstChild.textContent = filterLabel(f[0], f[1]);
      b.onclick = function (e) { e.stopPropagation(); openFilter(b, f[0], f[1]); };
      h.appendChild(b);
    });

    var r = document.createElement("button");
    r.className = "btn-reset";
    r.style.cssText = "position:absolute;left:650px;top:28px;width:93px;height:30px";
    r.textContent = "Reset Filter";
    r.onclick = clearFilters;
    h.appendChild(r);
    return h;
  }

  function filterLabel(key, fallback) {
    var v = state.filters[key];
    if (!v.length) return fallback;
    if (v.length === 1) return v[0];
    return v.length + " dipilih";
  }

  /* ------------------------------------------------------------ filters */

  var openPop = null;
  function closePop() {
    if (openPop) { openPop.remove(); openPop = null; }
  }
  document.addEventListener("click", closePop);

  function dimValuesFor(key) {
    /* option list with counts, computed ignoring this filter's own selection */
    var saved = state.filters[key];
    state.filters[key] = [];
    rebuildMask();
    var col = key === "protocol" ? P : key === "service" ? S : PR;
    var names = D.dims[key];
    var m = agg(col);
    state.filters[key] = saved;
    rebuildMask();
    return names.map(function (n, i) {
      return { name: n, count: m[i] ? m[i].n : 0 };
    }).filter(function (d) { return d.count > 0 || saved.indexOf(d.name) >= 0; })
      .sort(function (a, b) { return b.count - a.count; });
  }

  function openFilter(anchor, key, title) {
    closePop();
    var pop = document.createElement("div");
    pop.className = "pop filterpop";
    var opts = dimValuesFor(key);
    var chosen = state.filters[key].slice();

    pop.innerHTML =
      '<div class="search">' +
        '<svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">' +
        '<path d="M15.5 14h-.8l-.3-.3a6.5 6.5 0 1 0-.7.7l.3.3v.8l5 5 1.5-1.5zM10 14a4 4 0 1 1 0-8 4 4 0 0 1 0 8z"/></svg>' +
        '<input placeholder="Telusuri ' + title + '" aria-label="Telusuri"></div>' +
      '<div class="opts"></div>' +
      '<div class="foot"><button data-act="clear">Hapus</button>' +
      '<button data-act="apply">Terapkan</button></div>';

    var list = pop.querySelector(".opts");
    function paint(q) {
      list.innerHTML = "";
      opts.filter(function (o) {
        return !q || o.name.toLowerCase().indexOf(q) >= 0;
      }).forEach(function (o) {
        var row = document.createElement("label");
        row.className = "opt";
        var cb = document.createElement("input");
        cb.type = "checkbox";
        cb.checked = chosen.indexOf(o.name) >= 0;
        cb.onchange = function () {
          var i = chosen.indexOf(o.name);
          if (cb.checked && i < 0) chosen.push(o.name);
          if (!cb.checked && i >= 0) chosen.splice(i, 1);
        };
        var nm = document.createElement("span");
        nm.textContent = o.name;
        var cnt = document.createElement("span");
        cnt.className = "cnt";
        cnt.textContent = nInt(o.count);
        row.appendChild(cb);
        row.appendChild(nm);
        row.appendChild(cnt);
        list.appendChild(row);
      });
    }
    paint("");

    pop.querySelector("input").oninput = function (e) {
      paint(e.target.value.trim().toLowerCase());
    };
    pop.querySelector('[data-act="clear"]').onclick = function () {
      state.filters[key] = [];
      closePop();
      resetPaging();
      buildPage();
    };
    pop.querySelector('[data-act="apply"]').onclick = function () {
      state.filters[key] = chosen;
      closePop();
      resetPaging();
      buildPage();
    };
    pop.onclick = function (e) { e.stopPropagation(); };

    document.body.appendChild(pop);
    var r = anchor.getBoundingClientRect();
    pop.style.left = Math.min(r.left, innerWidth - pop.offsetWidth - 8) + "px";
    pop.style.top = Math.min(r.bottom + 4, innerHeight - pop.offsetHeight - 8) + "px";
    openPop = pop;
    pop.querySelector("input").focus();
  }

  function toggleFilter(key, value) {
    var v = state.filters[key], i = v.indexOf(value);
    if (i >= 0) v.splice(i, 1); else v.push(value);
    resetPaging();
    buildPage();
  }

  function clearFilters() {
    state.filters = { protocol: [], service: [], priority: [] };
    resetPaging();
    buildPage();
  }

  function resetPaging() {
    Object.keys(state.tableState).forEach(function (k) {
      state.tableState[k].page = 0;
    });
  }

  /* --------------------------------------------------------- fullscreen */

  var fsLayer = document.getElementById("fsLayer");
  function openFullscreen(wd) {
    if (wd.kpi || wd.placeholder) return;
    document.getElementById("fsTitle").textContent = wd.title;
    var body = document.getElementById("fsBody");
    body.innerHTML = "";
    fsLayer.classList.add("open");
    requestAnimationFrame(function () { wd.render(body); });
  }
  document.getElementById("fsClose").onclick = function () {
    fsLayer.classList.remove("open");
  };
  fsLayer.onclick = function (e) {
    if (e.target === fsLayer) fsLayer.classList.remove("open");
  };

  /* --------------------------------------------------------- app chrome */

  function goPage(i) {
    state.page = i;
    resetPaging();
    C.hideTip();
    buildPage();
  }

  document.querySelectorAll(".rail-item").forEach(function (b) {
    b.onclick = function () { goPage(+b.dataset.page); };
  });

  document.getElementById("btnReset").onclick = clearFilters;

  document.getElementById("btnCollapse").onclick = function () {
    var rail = document.getElementById("rail");
    rail.classList.toggle("collapsed");
    this.querySelector("svg").style.transform =
      rail.classList.contains("collapsed") ? "scaleX(-1)" : "";
    fit();
  };

  /* "..." menu -> Salin laporan */
  document.getElementById("btnMore").onclick = function (e) {
    e.stopPropagation();
    closePop();
    var pop = document.createElement("div");
    pop.className = "pop";
    [["Salin laporan", "copy"], ["Download sebagai PDF", null],
     ["Muat ulang data", "refresh"], [null, null], ["Laporkan penyalahgunaan", null]]
      .forEach(function (it) {
        if (!it[0]) {
          var s = document.createElement("div");
          s.className = "menu-sep";
          pop.appendChild(s);
          return;
        }
        var m = document.createElement("div");
        m.className = "menu-item";
        m.textContent = it[0];
        m.onclick = function () {
          closePop();
          if (it[1] === "copy") document.getElementById("copyScrim").classList.add("open");
          if (it[1] === "refresh") buildPage();
        };
        pop.appendChild(m);
      });
    pop.onclick = function (ev) { ev.stopPropagation(); };
    document.body.appendChild(pop);
    var r = this.getBoundingClientRect();
    pop.style.left = (r.right - pop.offsetWidth) + "px";
    pop.style.top = (r.bottom + 6) + "px";
    openPop = pop;
  };

  document.getElementById("btnShare").onclick = function (e) {
    e.stopPropagation();
    closePop();
    var pop = document.createElement("div");
    pop.className = "pop";
    ["Bagikan dengan orang lain", "Jadwalkan pengiriman", "Salin link laporan",
     "Sematkan laporan"].forEach(function (label) {
      var m = document.createElement("div");
      m.className = "menu-item";
      m.textContent = label;
      m.onclick = closePop;
      pop.appendChild(m);
    });
    pop.onclick = function (ev) { ev.stopPropagation(); };
    document.body.appendChild(pop);
    var r = this.getBoundingClientRect();
    pop.style.left = (r.right - pop.offsetWidth) + "px";
    pop.style.top = (r.bottom + 6) + "px";
    openPop = pop;
  };

  /* the copy-report dialog, mirroring the seven data sources of the report */
  (function buildCopyDialog() {
    var sources = ["dashboard summary 1", "dashboard dataset 1", "top risk records 1",
                   "DS_ServiceStats", "DS_RiskDistribution", "DS_FeatureModelImportance",
                   "model performance 1", "feature importance 1"];
    var warn = '<svg class="warn" width="16" height="16" viewBox="0 0 24 24" ' +
               'fill="currentColor"><path d="M1 21h22L12 2z"/></svg>';
    document.getElementById("dsList").innerHTML = sources.map(function (s) {
      return '<div class="ds-row">' +
        '<div class="ds-pill">' + warn + '<span>' + s + '</span></div>' +
        '<div class="ds-pill new">' + warn + '<span>' + s + '</span>' +
        '<span class="caret">▼</span></div></div>';
    }).join("");
  })();

  document.querySelectorAll("#copyScrim [data-close]").forEach(function (b) {
    b.onclick = function () { document.getElementById("copyScrim").classList.remove("open"); };
  });
  document.getElementById("copyScrim").onclick = function (e) {
    if (e.target === this) this.classList.remove("open");
  };

  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    closePop();
    fsLayer.classList.remove("open");
    document.getElementById("copyScrim").classList.remove("open");
  });

  /* --------------------------------------------------- fit page to view */

  function fit() {
    var viewer = document.getElementById("viewer");
    var scale = Math.min((viewer.clientWidth - 24) / 900,
                         (viewer.clientHeight - 24) / 675);
    scale = Math.max(0.45, Math.min(scale, 1.9));
    var wrap = document.getElementById("pageScale");
    wrap.style.transform = "scale(" + scale + ")";
    wrap.style.width = (900 * scale) + "px";
    wrap.style.height = (675 * scale) + "px";
    wrap.style.marginTop = Math.max(12, (viewer.clientHeight - 675 * scale) / 2) + "px";
  }

  addEventListener("resize", function () { fit(); buildPage(); });

  fit();
  buildPage();
})();
