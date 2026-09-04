/* ==========================================================================
   charts.js — the handful of SVG chart types this report uses.
   No dependencies: the page has to open straight off the filesystem.
   Every renderer takes (host, spec) and paints into `host`, sizing itself to
   the host's box, so charts re-render on resize and in fullscreen.
   ========================================================================== */

(function (global) {
  "use strict";

  var NS = "http://www.w3.org/2000/svg";

  var PALETTE = ["#4185f4", "#f59d52", "#ac7ee6", "#b4c665", "#2ab8ca",
                 "#e9c33b", "#e473b0", "#6666b9", "#ddb982", "#8ac6a0",
                 "#c98b8b"];

  /* ------------------------------------------------------------ helpers */

  function el(name, attrs, parent) {
    var n = document.createElementNS(NS, name);
    for (var k in attrs) {
      if (attrs[k] !== null && attrs[k] !== undefined) n.setAttribute(k, attrs[k]);
    }
    if (parent) parent.appendChild(n);
    return n;
  }

  function text(parent, x, y, str, cls, extra) {
    var t = el("text", Object.assign({ x: x, y: y, class: cls || "" }, extra || {}), parent);
    t.textContent = str;
    return t;
  }

  function svgIn(host) {
    host.innerHTML = "";
    var w = host.clientWidth || 300, h = host.clientHeight || 200;
    var s = el("svg", { width: w, height: h, viewBox: "0 0 " + w + " " + h }, host);
    return { svg: s, w: w, h: h };
  }

  /* Indonesian formatting, matching the published report. */
  function nInt(v) {
    return Math.round(v).toLocaleString("id-ID");
  }
  function nDec(v, d) {
    return Number(v).toLocaleString("id-ID", {
      minimumFractionDigits: d === undefined ? 2 : d,
      maximumFractionDigits: d === undefined ? 2 : d
    });
  }
  /* Donut/pie slice labels in the original use a dot, and drop trailing ".0" */
  function pctDot(v) {
    var s = (Math.round(v * 10) / 10).toFixed(1);
    return (s.slice(-2) === ".0" ? s.slice(0, -2) : s) + "%";
  }
  /* Axis ticks abbreviate thousands as "rb" (ribu), as Looker does in id-ID */
  function axisNum(v) {
    if (Math.abs(v) >= 1000) {
      var k = v / 1000;
      return (Math.round(k * 10) / 10).toLocaleString("id-ID") + " rb";
    }
    return nInt(v);
  }

  function niceTicks(max, count) {
    if (max <= 0) return [0];
    var raw = max / count;
    var mag = Math.pow(10, Math.floor(Math.log10(raw)));
    var norm = raw / mag;
    var step = (norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 2.5 ? 2.5 : norm <= 5 ? 5 : 10) * mag;
    var out = [];
    for (var v = 0; v <= max + step * 0.001; v += step) out.push(Math.round(v * 1e6) / 1e6);
    return out;
  }

  /* white -> colour blend, for the heatmap cells */
  function tint(hex, t) {
    var r = parseInt(hex.slice(1, 3), 16), g = parseInt(hex.slice(3, 5), 16),
        b = parseInt(hex.slice(5, 7), 16);
    var f = function (c) { return Math.round(255 + (c - 255) * t); };
    return "rgb(" + f(r) + "," + f(g) + "," + f(b) + ")";
  }

  /* ----------------------------------------------------------- tooltip */

  var tipEl = null;
  function tip() {
    if (!tipEl) {
      tipEl = document.createElement("div");
      tipEl.className = "tip";
      document.body.appendChild(tipEl);
    }
    return tipEl;
  }
  function bindTip(node, html) {
    node.addEventListener("mousemove", function (e) {
      var t = tip();
      t.innerHTML = html;
      t.style.display = "block";
      var pad = 14;
      var x = e.clientX + pad, y = e.clientY + pad;
      var r = t.getBoundingClientRect();
      if (x + r.width > innerWidth - 8) x = e.clientX - r.width - pad;
      if (y + r.height > innerHeight - 8) y = e.clientY - r.height - pad;
      t.style.left = x + "px";
      t.style.top = y + "px";
    });
    node.addEventListener("mouseleave", function () { tip().style.display = "none"; });
  }
  function hideTip() { if (tipEl) tipEl.style.display = "none"; }

  /* -------------------------------------------------------------- donut */

  /* spec: { slices:[{label,value,color}], legend:"top"|"right",
             labelMin: hide % labels below this share, onPick(label) }        */
  function donut(host, spec) {
    var s = svgIn(host), svg = s.svg;
    var slices = spec.slices.filter(function (d) { return d.value > 0; });
    var total = slices.reduce(function (a, d) { return a + d.value; }, 0);
    if (!total) { host.innerHTML = '<div class="empty-note">Tidak ada data</div>'; return; }

    var legendRight = spec.legend === "right";
    var padTop = legendRight ? 6 : 22;
    var plotW = legendRight ? s.w - 118 : s.w;
    var plotH = s.h - padTop - 4;
    var cx = plotW / 2, cy = padTop + plotH / 2;
    var R = Math.max(18, Math.min(plotW, plotH) / 2 - 6);
    var r0 = R * 0.56;

    /* legend */
    if (legendRight) {
      var ly = padTop + 8;
      slices.forEach(function (d, i) {
        if (ly > s.h - 6) return;
        el("circle", { cx: plotW + 16, cy: ly - 3, r: 4.4, fill: d.color || PALETTE[i % 11] }, svg);
        text(svg, plotW + 26, ly, d.label, "legend-txt",
             { "font-family": "Courier New, monospace" });
        ly += 15;
      });
    } else {
      var items = slices.slice(0, 6);
      var widths = items.map(function (d) { return d.label.length * 5.4 + 24; });
      var totW = widths.reduce(function (a, b) { return a + b; }, 0);
      var lx = Math.max(4, (s.w - totW) / 2);
      items.forEach(function (d, i) {
        el("circle", { cx: lx + 6, cy: 9, r: 4.4, fill: d.color || PALETTE[i % 11] }, svg);
        text(svg, lx + 15, 12, d.label, "legend-txt",
             { "font-family": "Courier New, monospace" });
        lx += widths[i];
      });
    }

    /* arcs */
    var a0 = -Math.PI / 2;
    slices.forEach(function (d, i) {
      var frac = d.value / total;
      var a1 = a0 + frac * Math.PI * 2;
      var big = frac > 0.5 ? 1 : 0;
      var p = ["M", cx + R * Math.cos(a0), cy + R * Math.sin(a0),
               "A", R, R, 0, big, 1, cx + R * Math.cos(a1), cy + R * Math.sin(a1),
               "L", cx + r0 * Math.cos(a1), cy + r0 * Math.sin(a1),
               "A", r0, r0, 0, big, 0, cx + r0 * Math.cos(a0), cy + r0 * Math.sin(a0),
               "Z"].join(" ");
      var color = d.color || PALETTE[i % 11];
      var arc = el("path", { d: p, fill: color, stroke: "#fff", "stroke-width": 1,
                             class: "slice" }, svg);
      bindTip(arc, "<b>" + d.label + "</b><div class='row'><span>Record Count</span>" +
                   "<span>" + nInt(d.value) + "</span></div>" +
                   "<div class='row'><span>Persen</span><span>" +
                   nDec(frac * 100) + "%</span></div>");
      if (spec.onPick) arc.addEventListener("click", function () { hideTip(); spec.onPick(d.label); });

      if (frac >= (spec.labelMin === undefined ? 0.05 : spec.labelMin)) {
        var am = (a0 + a1) / 2, rm = (R + r0) / 2 + R * 0.16;
        var lab = text(svg, cx + rm * Math.cos(am), cy + rm * Math.sin(am) + 3,
                       pctDot(frac * 100), "", {
          "text-anchor": "middle", "font-size": 9.5, "font-weight": 600, fill: "#202124"
        });
        lab.style.pointerEvents = "none";
      }
      a0 = a1;
    });
  }

  /* ------------------------------------------------- horizontal bar chart */

  /* spec: { rows:[{label,value,color}], axisTitle, valueLabel, legend,
             barColor, onPick }                                              */
  function hbar(host, spec) {
    var s = svgIn(host), svg = s.svg;
    var rows = spec.rows;
    if (!rows.length) { host.innerHTML = '<div class="empty-note">Tidak ada data</div>'; return; }

    var top = spec.legend ? 20 : 6;
    var bottom = 28;
    var labW = 0;
    rows.forEach(function (r) { labW = Math.max(labW, String(r.label).length); });
    var left = Math.min(96, labW * 4.9 + 8);
    var right = 34;
    var plotW = s.w - left - right, plotH = s.h - top - bottom;

    if (spec.legend) {
      el("rect", { x: 4, y: 3, width: 12, height: 8, fill: spec.barColor || PALETTE[0] }, svg);
      text(svg, 21, 11, spec.legend, "legend-txt");
    }

    var max = Math.max.apply(null, rows.map(function (r) { return r.value; }));
    var ticks = niceTicks(max, 5);
    var axMax = ticks[ticks.length - 1] || 1;
    var x = function (v) { return left + v / axMax * plotW; };

    var g = el("g", { class: "axis" }, svg);
    ticks.forEach(function (t) {
      el("line", { x1: x(t), y1: top, x2: x(t), y2: top + plotH,
                   stroke: t === 0 ? "#bdc1c6" : "#e8eaed" }, g);
      text(g, x(t), top + plotH + 12, spec.tickFmt ? spec.tickFmt(t) : axisNum(t),
           "", { "text-anchor": "middle", "font-size": 8.5, fill: "#5f6368" });
    });
    if (spec.axisTitle) {
      text(svg, left + plotW / 2, s.h - 3, spec.axisTitle, "axis-title",
           { "text-anchor": "middle" });
    }

    var band = plotH / rows.length;
    var bh = Math.min(band * 0.66, 15);
    rows.forEach(function (r, i) {
      var cy = top + band * i + band / 2;
      text(svg, left - 5, cy + 3, r.label, "", {
        "text-anchor": "end", "font-size": 8.5, fill: "#3c4043"
      });
      var w = Math.max(0, x(r.value) - left);
      var bar = el("rect", { x: left, y: cy - bh / 2, width: w, height: bh,
                             fill: r.color || spec.barColor || PALETTE[0], class: "bar" }, svg);
      bindTip(bar, "<b>" + r.label + "</b><div class='row'><span>" +
                   (spec.valueLabel || "Record Count") + "</span><span>" +
                   (spec.valueFmt ? spec.valueFmt(r.value) : nInt(r.value)) + "</span></div>");
      if (spec.onPick && r.pickable !== false) {
        bar.addEventListener("click", function () { hideTip(); spec.onPick(r.label); });
      }
      text(svg, left + w + 3, cy + 3,
           spec.valueFmt ? spec.valueFmt(r.value) : nInt(r.value), "val-label");
    });
  }

  /* --------------------------------------------------- grouped column chart */

  /* spec: { categories:[..], series:[{name,color,values:[..]}], yMin, yMax }  */
  function groupedColumn(host, spec) {
    var s = svgIn(host), svg = s.svg;
    var top = 22, bottom = 34, left = 30, right = 6;
    var plotW = s.w - left - right, plotH = s.h - top - bottom;

    var lx = 4;
    spec.series.forEach(function (se, i) {
      el("rect", { x: lx, y: 3, width: 12, height: 8, fill: se.color || PALETTE[i % 11] }, svg);
      text(svg, lx + 17, 11, se.name, "legend-txt");
      lx += se.name.length * 5.2 + 26;
    });

    var yMin = spec.yMin, yMax = spec.yMax;
    var y = function (v) { return top + plotH - (v - yMin) / (yMax - yMin) * plotH; };

    var g = el("g", { class: "axis" }, svg);
    var steps = spec.ySteps || 4;
    for (var i = 0; i <= steps; i++) {
      var v = yMin + (yMax - yMin) * i / steps;
      el("line", { x1: left, y1: y(v), x2: left + plotW, y2: y(v), class: "gridline" }, g);
      text(g, left - 5, y(v) + 3, nDec(v, v % 1 ? 1 : 0), "",
           { "text-anchor": "end", "font-size": 8.5, fill: "#5f6368" });
    }
    el("line", { x1: left, y1: top + plotH, x2: left + plotW, y2: top + plotH,
                 stroke: "#bdc1c6" }, g);

    var band = plotW / spec.categories.length;
    var inner = band * 0.72, bw = inner / spec.series.length;
    spec.categories.forEach(function (cat, ci) {
      var x0 = left + band * ci + (band - inner) / 2;
      spec.series.forEach(function (se, si) {
        var v = se.values[ci];
        var h = Math.max(0, top + plotH - y(v));
        var bar = el("rect", { x: x0 + bw * si, y: y(v), width: bw - 1, height: h,
                               fill: se.color || PALETTE[si % 11], class: "bar" }, svg);
        bindTip(bar, "<b>" + cat + "</b><div class='row'><span>" + se.name +
                     "</span><span>" + nDec(v) + "</span></div>");
      });
      /* wrap the category label onto up to two lines, like the export */
      var words = String(cat).split(" ");
      var lines = words.length > 1 ? [words[0], words.slice(1).join(" ")] : words;
      lines.forEach(function (ln, li) {
        text(svg, left + band * ci + band / 2, top + plotH + 13 + li * 10, ln, "", {
          "text-anchor": "middle", "font-size": 8.5, fill: "#5f6368"
        });
      });
    });
  }

  /* -------------------------------------------------------- bubble chart */

  /* spec: { points:[{label,x,y,size}], xTitle, yTitle, color }               */
  function bubble(host, spec) {
    var s = svgIn(host), svg = s.svg;
    var top = 24, bottom = 32, left = 34, right = 14;
    var plotW = s.w - left - right, plotH = s.h - top - bottom;
    var color = spec.color || "#3f9c4b";

    el("circle", { cx: 10, cy: 8, r: 4.4, fill: color }, svg);
    text(svg, 20, 11, spec.legend || "service", "legend-txt");

    var xMax = niceTicks(Math.max.apply(null, spec.points.map(function (p) { return p.x; })), 4);
    var xTop = xMax[xMax.length - 1];
    var yTicks = [0, 50, 100];
    var X = function (v) { return left + v / xTop * plotW; };
    var Y = function (v) { return top + plotH - v / 100 * plotH; };

    var g = el("g", { class: "axis" }, svg);
    xMax.forEach(function (t) {
      el("line", { x1: X(t), y1: top, x2: X(t), y2: top + plotH,
                   stroke: t === 0 ? "#bdc1c6" : "#e8eaed" }, g);
      text(g, X(t), top + plotH + 12, axisNum(t), "",
           { "text-anchor": "middle", "font-size": 8.5, fill: "#5f6368" });
    });
    yTicks.forEach(function (t) {
      el("line", { x1: left, y1: Y(t), x2: left + plotW, y2: Y(t),
                   stroke: t === 0 ? "#bdc1c6" : "#e8eaed" }, g);
      text(g, left - 5, Y(t) + 3, nInt(t), "",
           { "text-anchor": "end", "font-size": 8.5, fill: "#5f6368" });
    });
    text(svg, left + plotW / 2, s.h - 2, spec.xTitle || "", "axis-title",
         { "text-anchor": "middle" });
    text(svg, 9, top + plotH / 2, spec.yTitle || "", "axis-title", {
      "text-anchor": "middle",
      transform: "rotate(-90 9 " + (top + plotH / 2) + ")"
    });

    var sMax = Math.max.apply(null, spec.points.map(function (p) { return p.size; }));
    spec.points.slice().sort(function (a, b) { return b.size - a.size; }).forEach(function (p) {
      var r = 3 + Math.sqrt(p.size / sMax) * 22;
      var c = el("circle", { cx: X(p.x), cy: Y(p.y), r: r, fill: color,
                             "fill-opacity": .88, class: "slice" }, svg);
      bindTip(c, "<b>" + p.label + "</b>" +
                 "<div class='row'><span>Total</span><span>" + nInt(p.x) + "</span></div>" +
                 "<div class='row'><span>Anomaly_Rate</span><span>" + nDec(p.y) + "%</span></div>" +
                 "<div class='row'><span>Anomaly</span><span>" + nInt(p.size) + "</span></div>");
      if (spec.onPick) c.addEventListener("click", function () { hideTip(); spec.onPick(p.label); });
    });
  }

  /* ------------------------------------------------------------ treemap */

  /* Squarified treemap with the grey "Semua" banner and the gradient key
     that Looker draws above it. spec: { items:[{label,value}] }              */
  function treemap(host, spec) {
    host.innerHTML = "";
    var w = host.clientWidth, h = host.clientHeight;
    var svg = el("svg", { width: w, height: h, viewBox: "0 0 " + w + " " + h }, host);

    var items = spec.items.filter(function (d) { return d.value > 0; })
                          .sort(function (a, b) { return b.value - a.value; });
    var total = items.reduce(function (a, d) { return a + d.value; }, 0);
    if (!total) { host.innerHTML = '<div class="empty-note">Tidak ada data</div>'; return; }

    /* gradient key */
    var gw = 116, gx = w - gw - 4;
    var defs = el("defs", {}, svg);
    var lg = el("linearGradient", { id: "tmk", x1: 0, y1: 0, x2: 1, y2: 0 }, defs);
    [["0%", "#4185f4"], ["45%", "#2ab8ca"], ["75%", "#b4c665"], ["100%", "#e9c33b"]]
      .forEach(function (st) { el("stop", { offset: st[0], "stop-color": st[1] }, lg); });
    el("rect", { x: gx, y: 2, width: gw, height: 4, fill: "url(#tmk)", rx: 2 }, svg);

    /* banner */
    var by = 12, bh = 16;
    el("rect", { x: 0, y: by, width: w, height: bh, fill: "#dfdfdf" }, svg);
    text(svg, w / 2, by + 11, "Semua : 100%", "", {
      "text-anchor": "middle", "font-size": 9, "font-weight": 700, fill: "#3c4043"
    });

    /* squarify */
    var COLORS = ["#64b4f5", "#dad93c", "#f4d648", "#ffd54e", "#ffb74d"];
    var box = { x: 0, y: by + bh + 1, w: w, h: h - (by + bh + 1) };
    var vals = items.map(function (d) { return d.value / total * box.w * box.h; });

    var placed = [];
    (function worst(list, idx, rect) {
      /* simple slice-and-dice-with-aspect-correction; good enough at this size */
      var i = idx, remaining = list.slice(idx);
      if (!remaining.length) return;
      var sum = remaining.reduce(function (a, b) { return a + b; }, 0);
      var horizontal = rect.w >= rect.h;
      var row = [], rowSum = 0, best = Infinity;
      for (var k = 0; k < remaining.length; k++) {
        var trial = rowSum + remaining[k];
        var side = horizontal ? rect.h : rect.w;
        var thick = trial / side;
        var wr = Math.max.apply(null, row.concat([remaining[k]]).map(function (v) {
          var len = v / thick;
          return Math.max(thick / len, len / thick);
        }));
        if (wr > best && row.length) break;
        best = wr; rowSum = trial; row.push(remaining[k]);
      }
      var side2 = horizontal ? rect.h : rect.w;
      var thick2 = rowSum / side2;
      var off = 0;
      row.forEach(function (v, j) {
        var len = v / thick2;
        placed.push(horizontal
          ? { x: rect.x, y: rect.y + off, w: thick2, h: len, i: i + j }
          : { x: rect.x + off, y: rect.y, w: len, h: thick2, i: i + j });
        off += len;
      });
      var next = horizontal
        ? { x: rect.x + thick2, y: rect.y, w: rect.w - thick2, h: rect.h }
        : { x: rect.x, y: rect.y + thick2, w: rect.w, h: rect.h - thick2 };
      if (next.w > 0.5 && next.h > 0.5) worst(list, i + row.length, next);
    })(vals, 0, box);

    placed.forEach(function (p) {
      var d = items[p.i];
      var pct = d.value / total * 100;
      var g = el("g", {}, svg);
      el("rect", { x: p.x + 1, y: p.y + 1, width: Math.max(0, p.w - 2),
                   height: Math.max(0, p.h - 2), fill: COLORS[p.i % COLORS.length],
                   class: "slice" }, g);
      var label = d.label + " : " + nDec(pct) + "%";
      if (p.w > label.length * 4.6 && p.h > 14) {
        text(g, p.x + p.w / 2, p.y + p.h / 2 + 3, label, "", {
          "text-anchor": "middle", "font-size": 8.5, fill: "#3c4043"
        }).style.pointerEvents = "none";
      } else if (p.w > 14 && p.h > 12) {
        text(g, p.x + p.w / 2, p.y + p.h / 2 + 3, "…", "", {
          "text-anchor": "middle", "font-size": 9, fill: "#5f6368"
        }).style.pointerEvents = "none";
      }
      bindTip(g, "<b>" + d.label + "</b>" +
                 "<div class='row'><span>Record Count</span><span>" + nInt(d.value) + "</span></div>" +
                 "<div class='row'><span>Persen</span><span>" + nDec(pct) + "%</span></div>");
      if (spec.onPick) g.addEventListener("click", function () { hideTip(); spec.onPick(d.label); });
    });
  }

  /* -------------------------------------------------------- pivot table */

  /* spec: { banner, rowHead, cols:[..], rows:[{label, values:[..]}],
             fmt, dash (render 0 as "-") }                                    */
  function pivot(host, spec) {
    host.innerHTML = "";
    var max = 0;
    spec.rows.forEach(function (r) {
      r.values.forEach(function (v) { if (v > max) max = v; });
    });

    var t = document.createElement("table");
    t.className = "lk pivot";
    var thead = document.createElement("thead");

    var trBanner = document.createElement("tr");
    var thB = document.createElement("th");
    thB.className = "banner";
    thB.colSpan = spec.cols.length + 1;
    thB.textContent = spec.banner;
    trBanner.appendChild(thB);
    thead.appendChild(trBanner);

    var trHead = document.createElement("tr");
    var thR = document.createElement("th");
    thR.textContent = spec.rowHead;
    thR.style.background = "#fff";
    thR.style.fontWeight = "400";
    trHead.appendChild(thR);
    spec.cols.forEach(function (c) {
      var th = document.createElement("th");
      th.className = "num";
      th.textContent = c;
      th.style.background = "#fff";
      th.style.fontWeight = "400";
      th.style.color = "#3c4043";
      trHead.appendChild(th);
    });
    thead.appendChild(trHead);
    t.appendChild(thead);

    var tb = document.createElement("tbody");
    spec.rows.forEach(function (r) {
      var tr = document.createElement("tr");
      var td0 = document.createElement("td");
      td0.textContent = r.label;
      tr.appendChild(td0);
      r.values.forEach(function (v, i) {
        var td = document.createElement("td");
        td.className = "num hm";
        td.textContent = (spec.dash && !v) ? "-" : (spec.fmt ? spec.fmt(v) : nInt(v));
        td.style.background = max ? tint("#f44236", Math.pow(v / max, 0.55)) : "#fff";
        if (max && v / max > 0.72) td.style.color = "#fff";
        bindTip(td, "<b>" + r.label + " · " + spec.cols[i] + "</b>" +
                    "<div class='row'><span>" + (spec.metric || "Record Count") +
                    "</span><span>" + (spec.fmt ? spec.fmt(v) : nInt(v)) + "</span></div>");
        tr.appendChild(td);
      });
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    host.appendChild(t);
  }

  /* --------------------------------------------------------- data table */

  /* spec: { columns:[{key,label,num,bar}], rows:[..], pageSize, sortKey }     */
  function table(host, spec) {
    host.innerHTML = "";
    var state = spec.state || (spec.state = { page: 0 });
    var rows = spec.rows;
    var size = spec.pageSize || 5;
    var pages = Math.max(1, Math.ceil(rows.length / size));
    if (state.page >= pages) state.page = pages - 1;

    var barCol = spec.columns.filter(function (c) { return c.bar; })[0];
    var barMax = barCol ? Math.max.apply(null, rows.map(function (r) {
      return r[barCol.key];
    }).concat([0])) : 0;

    var t = document.createElement("table");
    t.className = "lk";
    var thead = document.createElement("thead");
    var tr = document.createElement("tr");
    spec.columns.forEach(function (c) {
      var th = document.createElement("th");
      if (c.num) th.className = "num";
      th.textContent = c.label + (c.key === spec.sortKey ? " ▾" : "");
      tr.appendChild(th);
    });
    thead.appendChild(tr);
    t.appendChild(thead);

    var tb = document.createElement("tbody");
    rows.slice(state.page * size, state.page * size + size).forEach(function (r) {
      var trr = document.createElement("tr");
      spec.columns.forEach(function (c) {
        var td = document.createElement("td");
        if (c.num) td.className = "num";
        var v = r[c.key];
        td.textContent = c.fmt ? c.fmt(v) : v;
        if (c.bar && barMax) {
          var f = v / barMax;
          td.style.background = "linear-gradient(90deg,transparent " +
            (100 - f * 100) + "%, " + (f > 0.9 ? "#d32e2e" : "#de5c37") + " " +
            (100 - f * 100) + "%)";
          td.style.color = f > 0.28 ? "#fff" : "#202124";
        }
        trr.appendChild(td);
      });
      tb.appendChild(trr);
    });
    t.appendChild(tb);
    host.appendChild(t);

    if (rows.length > size || spec.alwaysPager) {
      var p = document.createElement("div");
      p.className = "pager";
      var from = rows.length ? state.page * size + 1 : 0;
      var to = Math.min(rows.length, (state.page + 1) * size);
      p.innerHTML = "<span>" + from + " - " + to + " / " + rows.length + "</span>";
      var prev = document.createElement("button");
      prev.innerHTML = "‹";
      prev.disabled = state.page === 0;
      prev.onclick = function () { state.page--; table(host, spec); };
      var next = document.createElement("button");
      next.innerHTML = "›";
      next.disabled = state.page >= pages - 1;
      next.onclick = function () { state.page++; table(host, spec); };
      p.appendChild(prev);
      p.appendChild(next);
      host.appendChild(p);
    }
  }

  global.Charts = {
    donut: donut, hbar: hbar, groupedColumn: groupedColumn, bubble: bubble,
    treemap: treemap, pivot: pivot, table: table,
    palette: PALETTE, nInt: nInt, nDec: nDec, pctDot: pctDot, axisNum: axisNum,
    hideTip: hideTip
  };
})(window);
