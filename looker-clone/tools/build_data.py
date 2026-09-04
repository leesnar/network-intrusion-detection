# -*- coding: utf-8 -*-
"""
build_data.py — builds every dataset the dashboard clone renders.

The Looker Studio report "Dashboard 2 Vinix" is fed by the CSVs that
`Script Colab.ipynb` writes to /content/. The normal path is now to generate
those for real:

    python run_notebook_pipeline.py          # runs the notebook on the raw data
    python build_data.py --from-csv ../exports

Without them this script falls back to RECONSTRUCTING a record-level table that
reproduces, exactly, every aggregate the notebook printed and the report shows:

  * 25,192 records; normal 13,449 / anomaly 11,743
  * protocol_type x class      (from notebook plot_02)
  * protocol_type x Priority   (from the report's "Protocol Priority" pivot)
  * flag distribution          (59.4% SF / 27.8% S0 / 8.8% REJ / tail)
  * service totals             (top 10 from notebook plot_03)
  * risk_score histogram       (report's "Risk Score Distribution")
  * mean risk 23.14, min 0, max 100, Security Health Index 76.86

With --from-csv the reconstruction is skipped entirely: the records, the model
scores, the feature importances and the correlations all come from the exports.

Outputs: ../data/*.csv  and  ../assets/js/data.js  (embedded, so index.html
opens straight from the filesystem with no web server).
"""

import argparse
import json
import math
import os
import random
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DATA = os.path.join(ROOT, "data")
JSDIR = os.path.join(ROOT, "assets", "js")

RNG = random.Random(42)

TOTAL = 25192

# ---------------------------------------------------------------------------
# 1. Ground truth pulled out of the notebook + the published report
# ---------------------------------------------------------------------------

# notebook cell 5
CLASS_TOTALS = {"normal": 13449, "anomaly": 11743}

# notebook plot_02 (bars are grouped anomaly-first: unstack() sorts columns)
PROTO_CLASS = {
    "tcp":  {"anomaly": 9845, "normal": 10681},
    "udp":  {"anomaly":  504, "normal":  2507},
    "icmp": {"anomaly": 1394, "normal":   261},
}
PROTO_TOTALS = {p: sum(v.values()) for p, v in PROTO_CLASS.items()}

# report page 2, "Protocol Priority" pivot
PROTO_PRIORITY = {
    "tcp":  {"P4-Low": 14667, "P3-Medium": 3781, "P2-High": 1869, "P1-Critical": 209},
    "udp":  {"P4-Low":  1687, "P3-Medium": 1108, "P2-High":  215, "P1-Critical":   1},
    "icmp": {"P4-Low":   155, "P3-Medium": 1406, "P2-High":   94, "P1-Critical":   0},
}

# report page 2 donut percentages, resolved to integers that sum to 25,192
FLAG_TOTALS = {
    "SF": 14964, "S0": 7003, "REJ": 2216, "RSTR": 442, "RSTO": 356,
    "S1": 71, "SH": 63, "RSTOS0": 42, "S2": 23, "S3": 9, "OTH": 3,
}

# 20 buckets of width 5. The first fifteen are read straight off the report's
# "Risk Score Distribution" bar chart; the [50,100) tail is split with a decay
# that respects P2-High = 2,178 and P1-Critical = 210. The very last bucket
# holds exactly 3 records because the notebook's printed top-5 (cell 31) shows
# only 100.00 / 96.32 / 95.27 at or above 95.
RISK_BUCKETS = [
    4091, 1762, 4349, 4126, 2181,   # [0,25)   -> P4-Low        16509
    1141, 1154, 1706, 1444,  850,   # [25,50)  -> P3-Medium      6295
     745,  566,  401,  291,  175,   # [50,75)  -> P2-High        2178
     108,   60,   27,   12,    3,   # [75,100) -> P1-Critical     210
]

RISK_MEAN = 23.14          # notebook cell 23
ANOMALY_PRED_COUNT = 2520  # notebook cell 22 (IsolationForest, contamination=0.10)

PRIORITY_ORDER = ["P4-Low", "P3-Medium", "P2-High", "P1-Critical"]
CATEGORY_OF = {
    "P4-Low": "Informational", "P3-Medium": "Low",
    "P2-High": "Medium", "P1-Critical": "Critical",
}

# service -> (protocol, record count, anomaly rate). Top 10 counts are exact
# (notebook plot_03); anomaly rates are read off the report's "Top Service"
# bubble chart. `private` and `other` appear under two protocols, as in NSL-KDD.
SERVICE_FIXED = [
    # (service, protocol, count, anomaly_rate)
    ("http",     "tcp",  8003, 0.060),
    ("private",  "tcp",  4101, 0.970),
    ("smtp",     "tcp",  1449, 0.050),
    ("ftp_data", "tcp",  1396, 0.280),
    ("telnet",   "tcp",   483, 0.570),
    ("finger",   "tcp",   366, 0.490),
    ("other",    "tcp",    58, 0.400),

    ("domain_u", "udp",  1820, 0.005),
    ("other",    "udp",   800, 0.480),
    ("private",  "udp",   250, 0.300),
    ("ntp_u",    "udp",   139, 0.250),
    ("tftp_u",   "udp",     2, 0.500),

    ("eco_i",    "icmp",  909, 0.900),
    ("ecr_i",    "icmp",  613, 0.940),
    ("urp_i",    "icmp",  106, 0.000),
    ("urh_i",    "icmp",   10, 0.000),
    ("tim_i",    "icmp",    9, 0.000),
    ("red_i",    "icmp",    8, 0.000),
]

# The long tail of TCP services. In NSL-KDD these rare ports show up almost
# exclusively inside neptune floods, hence the ~97% default anomaly rate.
TCP_TAIL = [
    ("ftp", 60, 0.30), ("pop_3", 25, 0.35), ("auth", 20, 0.97), ("domain", 10, 0.30),
    ("time", 25, 0.97), ("ssh", 8, 0.40), ("name", 20, 0.97), ("remote_job", 20, 0.97),
    ("whois", 22, 0.97), ("ctf", 20, 0.97), ("mtp", 20, 0.97), ("imap4", 20, 0.97),
    ("gopher", 20, 0.97), ("link", 20, 0.97), ("csnet_ns", 20, 0.97), ("uucp", 22, 0.97),
    ("uucp_path", 22, 0.97), ("nntp", 18, 0.97), ("netbios_ns", 20, 0.97),
    ("netbios_ssn", 20, 0.97), ("netbios_dgm", 20, 0.97), ("sql_net", 18, 0.97),
    ("vmnet", 18, 0.97), ("bgp", 22, 0.97), ("Z39_50", 26, 0.97), ("ldap", 18, 0.97),
    ("iso_tsap", 22, 0.97), ("hostnames", 20, 0.97), ("exec", 18, 0.97),
    ("login", 18, 0.50), ("shell", 16, 0.97), ("printer", 18, 0.97), ("efs", 20, 0.97),
    ("courier", 22, 0.97), ("klogin", 20, 0.97), ("kshell", 18, 0.97), ("echo", 16, 0.80),
    ("discard", 16, 0.97), ("systat", 16, 0.97), ("supdup", 20, 0.97),
    ("daytime", 20, 0.97), ("netstat", 18, 0.97), ("http_443", 18, 0.30),
    ("sunrpc", 18, 0.97), ("rje", 16, 0.97), ("IRC", 12, 0.35), ("X11", 6, 0.20),
    ("pm_dump", 2, 0.97), ("http_8001", 2, 0.97), ("http_2784", 1, 0.97),
    ("harvest", 2, 0.97), ("aol", 2, 0.97),
]

# notebook cell 16
MODEL_PERFORMANCE = [
    {"Model": "Random Forest",       "Accuracy": 99.80, "Precision": 99.67, "Recall": 99.96, "F1": 99.81, "Time_s": 6.00},
    {"Model": "Gradient Boosting",   "Accuracy": 99.56, "Precision": 99.52, "Recall": 99.67, "F1": 99.59, "Time_s": 5.90},
    {"Model": "K-Nearest Neighbors", "Accuracy": 99.48, "Precision": 99.33, "Recall": 99.70, "F1": 99.52, "Time_s": 0.04},
    {"Model": "Decision Tree",       "Accuracy": 99.46, "Precision": 99.52, "Recall": 99.48, "F1": 99.50, "Time_s": 0.40},
    {"Model": "Logistic Regression", "Accuracy": 95.61, "Precision": 94.94, "Recall": 96.95, "F1": 95.94, "Time_s": 1.80},
]

# notebook cell 20 (top 15 of 41)
FEATURE_IMPORTANCE = [
    ("src_bytes", 0.175810), ("dst_bytes", 0.106277), ("flag", 0.097893),
    ("dst_host_same_srv_rate", 0.070492), ("same_srv_rate", 0.066800),
    ("dst_host_srv_count", 0.060172), ("diff_srv_rate", 0.044070),
    ("logged_in", 0.042377), ("count", 0.037228), ("protocol_type", 0.037189),
    ("dst_host_diff_srv_rate", 0.033523), ("service", 0.026068),
    ("dst_host_same_src_port_rate", 0.024869),
    ("dst_host_srv_diff_host_rate", 0.021678), ("srv_serror_rate", 0.021251),
]

# report page 3, "Fitur x Model" pivot (top 10 RF features x the 3 tree models)
FEATURE_MODEL = [
    # feature, Gradient Boosting, Decision Tree, Random Forest
    ("src_bytes",              0.73, 0.75, 0.18),
    ("dst_bytes",              0.07, 0.02, 0.11),
    ("protocol_type",          0.05, 0.07, 0.04),
    ("dst_host_srv_count",     0.03, 0.05, 0.06),
    ("flag",                   0.00, 0.00, 0.10),
    ("dst_host_same_srv_rate", 0.01, 0.01, 0.07),
    ("count",                  0.03, 0.00, 0.04),
    ("same_srv_rate",          0.00, 0.00, 0.07),
    ("diff_srv_rate",          0.02, 0.01, 0.04),
    ("logged_in",              0.01, 0.02, 0.04),
]

# notebook cell 10 — |corr| of each feature with the anomaly label
CORR_TOP12 = [
    ("same_srv_rate", 0.749237), ("dst_host_srv_count", 0.719292),
    ("dst_host_same_srv_rate", 0.692212), ("logged_in", 0.688084),
    ("dst_host_srv_serror_rate", 0.653759), ("serror_rate", 0.650000),
    ("srv_serror_rate", 0.649000), ("dst_host_serror_rate", 0.647000),
    ("count", 0.541000), ("dst_host_diff_srv_rate", 0.489000),
    ("diff_srv_rate", 0.470000), ("dst_host_same_src_port_rate", 0.400000),
]

# The five highest risk_score rows the notebook printed (cell 31).
TOP5_FORCED = [
    ("tcp", "telnet", "SF",   100.000000),
    ("tcp", "telnet", "RSTO",  96.321734),
    ("tcp", "telnet", "SF",    95.274869),
    ("tcp", "IRC",    "S3",    91.397707),
    ("tcp", "ftp",    "SF",    90.834670),
]


# The four tables above are transcribed from the notebook's printed output.
# When the real exports are available (--from-csv) they are read back instead,
# so nothing on the ML page depends on a transcription any more.
AUX = {
    "model_performance": MODEL_PERFORMANCE,
    "feature_importance": FEATURE_IMPORTANCE,
    "feature_model": FEATURE_MODEL,
    "correlation": CORR_TOP12,
}


def load_aux(src):
    import csv as _csv

    def rows(name):
        path = os.path.join(src, name)
        if not os.path.exists(path):
            print("  (no %s — keeping the transcribed values)" % name)
            return None
        with open(path, encoding="utf-8") as fh:
            return list(_csv.DictReader(fh))

    r = rows("model_performance.csv")
    if r:
        AUX["model_performance"] = [
            {"Model": d["Model"], "Accuracy": float(d["Accuracy"]),
             "Precision": float(d["Precision"]), "Recall": float(d["Recall"]),
             "F1": float(d["F1"]), "Time_s": float(d["Time_s"])} for d in r]

    r = rows("feature_importance.csv")
    if r:
        AUX["feature_importance"] = [(d["Feature"], float(d["Importance"]))
                                     for d in r][:15]

    r = rows("feature_model_importance.csv")
    if r:
        by_feat = defaultdict(dict)
        for d in r:
            by_feat[d["Feature"]][d["Model"]] = float(d["Importance"])
        # keep the notebook's ordering: top RF features, most important first
        order = [f for f, _ in AUX["feature_importance"] if f in by_feat]
        AUX["feature_model"] = [(f, by_feat[f].get("Gradient Boosting", 0.0),
                                 by_feat[f].get("Decision Tree", 0.0),
                                 by_feat[f].get("Random Forest", 0.0))
                                for f in order]

    r = rows("correlation_label.csv")
    if r:
        AUX["correlation"] = [(d["Feature"], float(d["Correlation"])) for d in r]


# ---------------------------------------------------------------------------
# 2. Helpers
# ---------------------------------------------------------------------------

def largest_remainder(weights, total):
    """Split `total` across `weights` so the parts are integers summing to total."""
    s = float(sum(weights))
    if s <= 0:
        out = [0] * len(weights)
        if out:
            out[0] = total
        return out
    raw = [w / s * total for w in weights]
    out = [int(math.floor(x)) for x in raw]
    rem = total - sum(out)
    order = sorted(range(len(raw)), key=lambda i: raw[i] - out[i], reverse=True)
    for k in range(rem):
        out[order[k % len(order)]] += 1
    return out


def ipf(weights, row_margins, col_margins, iters=200):
    """Iterative proportional fitting, then integerise while holding both margins."""
    nr, nc = len(row_margins), len(col_margins)
    m = [[max(weights[r][c], 1e-9) for c in range(nc)] for r in range(nr)]
    for _ in range(iters):
        for r in range(nr):
            s = sum(m[r])
            f = (row_margins[r] / s) if s > 0 else 0.0
            for c in range(nc):
                m[r][c] *= f
        for c in range(nc):
            s = sum(m[r][c] for r in range(nr))
            f = (col_margins[c] / s) if s > 0 else 0.0
            for r in range(nr):
                m[r][c] *= f

    out = [[int(math.floor(m[r][c])) for c in range(nc)] for r in range(nr)]
    # repair rows first, then shuffle whole units between rows to fix columns
    for r in range(nr):
        deficit = row_margins[r] - sum(out[r])
        order = sorted(range(nc), key=lambda c: m[r][c] - out[r][c], reverse=True)
        i = 0
        while deficit > 0 and order:
            out[r][order[i % nc]] += 1
            deficit -= 1
            i += 1
    for _ in range(4000):
        colsum = [sum(out[r][c] for r in range(nr)) for c in range(nc)]
        over = [c for c in range(nc) if colsum[c] > col_margins[c]]
        under = [c for c in range(nc) if colsum[c] < col_margins[c]]
        if not over or not under:
            break
        co, cu = over[0], under[0]
        moved = False
        for r in sorted(range(nr), key=lambda r: -out[r][co]):
            if out[r][co] > 0:
                out[r][co] -= 1
                out[r][cu] += 1
                moved = True
                break
        if not moved:
            break
    return out


def csv_write(name, header, rows):
    path = os.path.join(DATA, name)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(",".join(header) + "\n")
        for row in rows:
            cells = []
            for v in row:
                s = "" if v is None else str(v)
                if "," in s or '"' in s:
                    s = '"' + s.replace('"', '""') + '"'
                cells.append(s)
            fh.write(",".join(cells) + "\n")
    return path


# ---------------------------------------------------------------------------
# 3. Reconstruct the record-level table
# ---------------------------------------------------------------------------

def build_records():
    # --- 3a. service / protocol / class -------------------------------------
    tcp_fixed = sum(c for _, p, c, _ in SERVICE_FIXED if p == "tcp")
    tail_total = PROTO_TOTALS["tcp"] - tcp_fixed
    tail_counts = largest_remainder([w for _, w, _ in TCP_TAIL], tail_total)

    services = [(s, p, c, r) for s, p, c, r in SERVICE_FIXED]
    services += [(name, "tcp", cnt, rate)
                 for (name, _, rate), cnt in zip(TCP_TAIL, tail_counts)]
    services = [s for s in services if s[2] > 0]

    # force anomaly counts to reproduce PROTO_CLASS exactly
    anomaly_of = {}
    for proto in ("tcp", "udp", "icmp"):
        group = [(i, s) for i, s in enumerate(services) if s[1] == proto]
        want = PROTO_CLASS[proto]["anomaly"]
        raw = [s[2] * s[3] for _, s in group]
        got = largest_remainder(raw, want) if sum(raw) > 0 else [0] * len(group)
        # never exceed a service's own record count
        for k, (i, s) in enumerate(group):
            got[k] = min(got[k], s[2])
        deficit = want - sum(got)
        k = 0
        while deficit > 0 and group:
            i, s = group[k % len(group)]
            if got[k % len(group)] < s[2]:
                got[k % len(group)] += 1
                deficit -= 1
            k += 1
        for k, (i, _) in enumerate(group):
            anomaly_of[i] = got[k]

    records = []
    for i, (svc, proto, cnt, _) in enumerate(services):
        na = anomaly_of[i]
        for j in range(cnt):
            records.append({
                "service": svc,
                "protocol_type": proto,
                "class": "anomaly" if j < na else "normal",
                "_pin": None,
            })
    assert len(records) == TOTAL, len(records)

    # --- 3a'. pin the five rows the notebook printed -------------------------
    # Claim them now, before any margin is fitted, so flag / priority / bucket
    # totals stay exact rather than being clobbered afterwards.
    pinned = []
    for proto, svc, flag, score in TOP5_FORCED:
        cand = next(r for r in records
                    if r["service"] == svc and r["protocol_type"] == proto
                    and r["class"] == "anomaly" and r["_pin"] is None)
        cand["_pin"] = (flag, score)
        cand["flag"] = flag
        cand["Priority"] = "P1-Critical"
        cand["ThreatCategory"] = "Critical"
        cand["risk_score"] = score
        cand["_bucket"] = min(19, int(score // 5))
        pinned.append(cand)
    free = [r for r in records if r["_pin"] is None]

    # --- 3b. flag -----------------------------------------------------------
    # bucket every record into a small group, IPF the group x flag matrix onto
    # the published flag margins, then hand flags back out.
    def group_of(r):
        if r["protocol_type"] == "icmp":
            return "icmp_" + r["class"]
        if r["protocol_type"] == "udp":
            return "udp_" + r["class"]
        if r["class"] == "normal":
            return "tcp_normal"
        if r["service"] in ("private", "http", "smtp", "ftp_data"):
            return "tcp_anom_common"
        if r["service"] in ("telnet", "finger", "ftp", "other"):
            return "tcp_anom_iface"
        return "tcp_anom_rare"

    flags = list(FLAG_TOTALS.keys())
    fi = {f: i for i, f in enumerate(flags)}
    #                        SF    S0   REJ  RSTR RSTO  S1   SH  RSTOS0 S2  S3  OTH
    FLAG_W = {
        "icmp_normal":      [980,   1,   8,   1,   1,   1,   4,   1,   1,  1,  1],
        "icmp_anomaly":     [980,   1,   8,   1,   1,   1,   4,   1,   1,  1,  1],
        "udp_normal":       [985,   1,   8,   1,   1,   1,   1,   1,   1,  1,  1],
        "udp_anomaly":      [900,   1,  80,   4,   4,   2,   4,   2,   1,  1,  1],
        "tcp_normal":       [930,   2,  10,   6,  14,  18,   4,   2,   8,  4,  2],
        "tcp_anom_common":  [ 90, 720, 130,  22,  22,   6,   4,   4,   1,  1,  1],
        "tcp_anom_iface":   [330, 380, 180,  40,  40,   8,  14,   6,   1,  1,  1],
        "tcp_anom_rare":    [ 60, 760, 130,  24,  20,   2,   2,   2,   1,  1,  1],
    }
    gkeys = list(FLAG_W.keys())
    gidx = {g: i for i, g in enumerate(gkeys)}
    members = defaultdict(list)
    for r in free:
        members[group_of(r)].append(r)

    flag_left = dict(FLAG_TOTALS)
    for r in pinned:
        flag_left[r["flag"]] -= 1

    row_margins = [len(members[g]) for g in gkeys]
    matrix = ipf([FLAG_W[g] for g in gkeys], row_margins,
                 [flag_left[f] for f in flags])
    for gi, g in enumerate(gkeys):
        rows = members[g]
        RNG.shuffle(rows)
        pos = 0
        for ci, f in enumerate(flags):
            for _ in range(matrix[gi][ci]):
                rows[pos]["flag"] = f
                pos += 1
        assert pos == len(rows)

    # --- 3c. priority -------------------------------------------------------
    # IsolationForest scores what looks unusual. Rank each record by a
    # suspicion proxy, then slice the ranking to hit PROTO_PRIORITY exactly.
    FLAG_SUSPICION = {"S0": 1.00, "REJ": 0.82, "RSTR": 0.78, "RSTO": 0.74,
                      "RSTOS0": 0.72, "SH": 0.66, "S3": 0.62, "S2": 0.58,
                      "S1": 0.52, "OTH": 0.50, "SF": 0.16}
    common = {"http", "smtp", "domain_u", "ftp_data", "private", "other",
              "eco_i", "ecr_i", "telnet", "finger"}
    # a per-service random effect (not just per-record noise) keeps records of
    # one service clustered in the ranking, the way a tree-based anomaly score
    # would — that is what makes the top-100 collapse to a couple of dozen rows
    svc_effect = {s: RNG.random() * 0.32 for s in {r['service'] for r in records}}
    for r in free:
        s = FLAG_SUSPICION[r["flag"]] * 0.55
        s += 0.25 if r["class"] == "anomaly" else 0.0
        s += 0.0 if r["service"] in common else 0.20
        r["_susp"] = s + svc_effect[r["service"]] + RNG.random() * 0.55

    by_proto = defaultdict(list)
    for r in free:
        by_proto[r["protocol_type"]].append(r)
    for proto, rows in by_proto.items():
        rows.sort(key=lambda r: -r["_susp"])
        pos = 0
        for prio in ("P1-Critical", "P2-High", "P3-Medium", "P4-Low"):
            n = PROTO_PRIORITY[proto][prio]
            n -= sum(1 for p in pinned
                     if p["protocol_type"] == proto and p["Priority"] == prio)
            for r in rows[pos:pos + n]:
                r["Priority"] = prio
                r["ThreatCategory"] = CATEGORY_OF[prio]
            pos += n
        assert pos == len(rows)

    # --- 3d. risk score -----------------------------------------------------
    # Buckets are 5 wide; each priority owns five of them. Within a priority,
    # split the protocol counts across its buckets with IPF so the report's
    # histogram and the pivot table agree.
    q_mean = 0.5 + (RISK_MEAN - sum(
        (b * 5 + 2.5) * RISK_BUCKETS[b] for b in range(20)) / TOTAL) / 5.0

    bucket_left = list(RISK_BUCKETS)
    for r in pinned:
        bucket_left[r["_bucket"]] -= 1

    protos = ["tcp", "udp", "icmp"]
    for pi, prio in enumerate(PRIORITY_ORDER):
        bucket_ids = list(range(pi * 5, pi * 5 + 5))
        col_margins = [bucket_left[b] for b in bucket_ids]
        row_margins = [sum(1 for r in by_proto[p] if r["Priority"] == prio)
                       for p in protos]
        w = [[max(col_margins[c], 1) for c in range(5)] for _ in protos]
        alloc = ipf(w, row_margins, col_margins)

        for ri, proto in enumerate(protos):
            pool = [r for r in by_proto[proto] if r["Priority"] == prio]
            # inside a priority, more suspicious records land in higher buckets
            pool.sort(key=lambda r: r["_susp"])
            pos = 0
            for ci, b in enumerate(bucket_ids):
                for _ in range(alloc[ri][ci]):
                    pool[pos]["_bucket"] = b
                    pos += 1
            assert pos == len(pool)

    # a bucket that holds pinned rows caps its free rows just below the lowest
    # pinned score, so the notebook's printed top-5 really is the top 5
    cap = {}
    for r in pinned:
        b = r["_bucket"]
        cap[b] = min(cap.get(b, b * 5 + 5), r["risk_score"])

    # spread scores inside each bucket around the quantile that lands the mean
    for r in free:
        b = r["_bucket"]
        lo, hi = b * 5, cap.get(b, b * 5 + 5)
        u = RNG.random()
        q = min(0.999, max(0.001, u * (2 * q_mean) if u < 0.5 else
                           1 - (1 - u) * 2 * (1 - q_mean)))
        r["_hi"] = hi
        r["risk_score"] = round(lo + q * (hi - lo), 6)

    # pin min / mean to the notebook's printed statistics (max is a pinned row)
    free.sort(key=lambda r: r["risk_score"])
    free[0]["risk_score"] = 0.0
    adjustable = free[1:]
    drift2 = RISK_MEAN * TOTAL - sum(r["risk_score"] for r in records)
    per = drift2 / len(adjustable)
    for r in adjustable:
        lo, hi = r["_bucket"] * 5, r["_hi"]
        r["risk_score"] = round(min(hi - 1e-6, max(lo, r["risk_score"] + per)), 6)
    drift2 = RISK_MEAN * TOTAL - sum(r["risk_score"] for r in records)
    for r in adjustable:
        if abs(drift2) < 1e-9:
            break
        lo, hi = r["_bucket"] * 5, r["_hi"]
        room = (hi - 1e-6 - r["risk_score"]) if drift2 > 0 else (lo - r["risk_score"])
        step = room if abs(room) < abs(drift2) else drift2
        r["risk_score"] = round(r["risk_score"] + step, 6)
        drift2 -= step

    # --- 3e. anomaly_pred + traffic volumes ---------------------------------
    records.sort(key=lambda r: -r["risk_score"])
    for k, r in enumerate(records):
        r["anomaly_pred"] = 1 if k < ANOMALY_PRED_COUNT else 0

    for r in records:
        if r["flag"] in ("S0", "REJ", "RSTOS0", "SH"):
            r["src_bytes"] = 0
            r["dst_bytes"] = 0
        elif r["class"] == "normal":
            r["src_bytes"] = int(math.expm1(RNG.uniform(3.6, 7.4)))
            r["dst_bytes"] = int(math.expm1(RNG.uniform(4.5, 8.6))) if RNG.random() < 0.8 else 0
        else:
            r["src_bytes"] = int(math.expm1(RNG.uniform(0.0, 6.0))) if RNG.random() < 0.75 \
                else int(math.expm1(RNG.uniform(6.0, 10.5)))
            r["dst_bytes"] = int(math.expm1(RNG.uniform(0.0, 5.0))) if RNG.random() < 0.6 else 0

    for r in records:
        r.pop("_susp", None)
        r.pop("_pin", None)
        r.pop("_hi", None)
    return records


# ---------------------------------------------------------------------------
# 4. Load the real CSVs instead, when they are available
# ---------------------------------------------------------------------------

def load_records(src):
    import csv as _csv
    path = os.path.join(src, "dashboard_dataset.csv")
    rows = []
    with open(path, encoding="utf-8") as fh:
        for d in _csv.DictReader(fh):
            score = float(d["risk_score"])
            rows.append({
                "protocol_type": d["protocol_type"], "service": d["service"],
                "flag": d["flag"], "class": d["class"],
                "src_bytes": int(float(d["src_bytes"])),
                "dst_bytes": int(float(d["dst_bytes"])),
                "risk_score": score, "Priority": d["Priority"],
                "ThreatCategory": d["ThreatCategory"],
                "anomaly_pred": int(float(d["anomaly_pred"])),
                "_bucket": min(19, int(score // 5)),
            })
    return rows


# ---------------------------------------------------------------------------
# 5. Aggregate into the cube the dashboard queries
# ---------------------------------------------------------------------------

def build_outputs(records):
    protos = sorted({r["protocol_type"] for r in records})
    svcs = sorted({r["service"] for r in records})
    flags = [f for f in FLAG_TOTALS if any(r["flag"] == f for r in records)]
    pi = {p: i for i, p in enumerate(protos)}
    si = {s: i for i, s in enumerate(svcs)}
    fli = {f: i for i, f in enumerate(flags)}
    pri = {p: i for i, p in enumerate(PRIORITY_ORDER)}

    cube = defaultdict(lambda: [0, 0.0])
    for r in records:
        key = (pi[r["protocol_type"]], si[r["service"]], fli[r["flag"]],
               pri[r["Priority"]], 1 if r["class"] == "anomaly" else 0,
               r["anomaly_pred"], min(19, int(r["risk_score"] // 5)))
        cell = cube[key]
        cell[0] += 1
        cell[1] += r["risk_score"]

    facts = [list(k) + [v[0], round(v[1], 4)] for k, v in sorted(cube.items())]

    # Looker aggregates the Top Risk Records table by its four dimensions and
    # shows MAX(risk_score) — 100 raw rows collapse to a couple of dozen.
    top100 = sorted(records, key=lambda r: -r["risk_score"])[:100]
    agg = {}
    for r in top100:
        k = (r["protocol_type"], r["service"], r["flag"], r["Priority"])
        agg[k] = max(agg.get(k, 0.0), r["risk_score"])
    top_rows = sorted(([*k, round(v, 3)] for k, v in agg.items()),
                      key=lambda x: -x[4])

    health = round(100 - sum(r["risk_score"] for r in records) / len(records), 2)
    mp = AUX["model_performance"]
    rf = next((m for m in mp if m["Model"] == "Random Forest"), mp[0])
    summary = {
        "TotalTraffic": len(records),
        "AnomalyCount": sum(1 for r in records if r["anomaly_pred"] == 1),
        "NormalCount": sum(1 for r in records if r["anomaly_pred"] == 0),
        "CriticalThreatCount": sum(1 for r in records if r["Priority"] == "P1-Critical"),
        "HighRiskCount": sum(1 for r in records if r["Priority"] == "P2-High"),
        "SecurityHealthIndex": health,
        "AverageRiskScore": round(sum(r["risk_score"] for r in records) / len(records), 2),
        "RF_Accuracy_pct": rf["Accuracy"], "RF_Precision_pct": rf["Precision"],
        "RF_Recall_pct": rf["Recall"], "RF_F1_pct": rf["F1"],
    }

    svc_stats = defaultdict(lambda: [0, 0])
    for r in records:
        c = svc_stats[r["service"]]
        c[0] += 1
        c[1] += 1 if r["class"] == "anomaly" else 0
    service_stats = sorted(
        ([s, t, a, t - a, round(a / t * 100, 2)] for s, (t, a) in svc_stats.items()),
        key=lambda x: -x[1])[:15]

    payload = {
        "dims": {"protocol": protos, "service": svcs, "flag": flags,
                 "priority": PRIORITY_ORDER,
                 "category": [CATEGORY_OF[p] for p in PRIORITY_ORDER]},
        "facts": facts,
        "topRisk": top_rows,
        "summary": summary,
        "modelPerformance": AUX["model_performance"],
        "featureImportance": [{"Feature": f, "Importance": round(v, 6)}
                              for f, v in AUX["feature_importance"]],
        "featureModel": [{"Feature": f, "Gradient Boosting": g,
                          "Decision Tree": d, "Random Forest": rfv}
                         for f, g, d, rfv in AUX["feature_model"]],
        "correlation": [{"Feature": f, "Correlation": round(v, 3)}
                        for f, v in AUX["correlation"]],
        "serviceStats": [{"service": s, "Total": t, "Anomaly": a,
                          "Normal": n, "Anomaly_Rate": rt}
                         for s, t, a, n, rt in service_stats],
    }
    return payload, top100, service_stats


def write_csvs(records, payload, top100, service_stats):
    csv_write("dashboard_dataset.csv",
              ["protocol_type", "service", "flag", "src_bytes", "dst_bytes",
               "class", "risk_score", "ThreatCategory", "Priority", "anomaly_pred"],
              [[r["protocol_type"], r["service"], r["flag"], r["src_bytes"],
                r["dst_bytes"], r["class"], round(r["risk_score"], 6),
                r["ThreatCategory"], r["Priority"], r["anomaly_pred"]]
               for r in records])

    csv_write("top_risk_records.csv",
              ["protocol_type", "service", "flag", "src_bytes", "dst_bytes",
               "risk_score", "ThreatCategory", "Priority", "class"],
              [[r["protocol_type"], r["service"], r["flag"], r["src_bytes"],
                r["dst_bytes"], round(r["risk_score"], 6), r["ThreatCategory"],
                r["Priority"], r["class"]] for r in top100])

    s = payload["summary"]
    csv_write("dashboard_summary.csv", list(s.keys()), [list(s.values())])

    csv_write("model_performance.csv",
              ["Model", "Accuracy", "Precision", "Recall", "F1", "Time_s"],
              [[m["Model"], m["Accuracy"], m["Precision"], m["Recall"],
                m["F1"], m["Time_s"]] for m in AUX["model_performance"]])

    csv_write("feature_importance.csv", ["Feature", "Importance"],
              [[f, round(v, 6)] for f, v in AUX["feature_importance"]])

    csv_write("service_stats.csv",
              ["service", "Total", "Anomaly", "Normal", "Anomaly_Rate"],
              service_stats)

    labels = ["[%d,%d)" % (b * 5, b * 5 + 5) for b in range(20)]
    counts = [0] * 20
    for r in records:
        counts[min(19, int(r["risk_score"] // 5))] += 1
    csv_write("risk_distribution.csv", ["Risk_Bucket", "Record_Count", "Bucket_Start"],
              [[labels[b], counts[b], b * 5] for b in range(20)])

    csv_write("feature_model_importance.csv", ["Model", "Feature", "Importance"],
              [[m, f, row[i]] for f, *row in
               [[x[0], x[1], x[2], x[3]] for x in AUX["feature_model"]]
               for i, m in enumerate(["Gradient Boosting", "Decision Tree", "Random Forest"])])

    csv_write("correlation_matrix.csv", ["Feature_A", "Correlation", "Abs_Correlation"],
              [[f, round(v, 3), round(abs(v), 3)] for f, v in AUX["correlation"]])
    return counts


def verify(records, counts):
    ok = True

    def check(label, got, want):
        nonlocal ok
        good = got == want
        ok = ok and good
        print(("  OK   " if good else "  FAIL ") + "%-34s %s" % (label, got if good else "%s (want %s)" % (got, want)))

    print("\nVerifying reconstruction against the notebook + report\n" + "-" * 62)
    check("total records", len(records), TOTAL)
    for c in ("normal", "anomaly"):
        check("class %s" % c, sum(1 for r in records if r["class"] == c), CLASS_TOTALS[c])
    for p in ("tcp", "udp", "icmp"):
        for c in ("anomaly", "normal"):
            check("%s x %s" % (p, c),
                  sum(1 for r in records if r["protocol_type"] == p and r["class"] == c),
                  PROTO_CLASS[p][c])
    for p in ("tcp", "udp", "icmp"):
        for prio in PRIORITY_ORDER:
            check("%s x %s" % (p, prio),
                  sum(1 for r in records if r["protocol_type"] == p and r["Priority"] == prio),
                  PROTO_PRIORITY[p][prio])
    for f, want in FLAG_TOTALS.items():
        check("flag %s" % f, sum(1 for r in records if r["flag"] == f), want)
    for svc, _, want, _ in SERVICE_FIXED:
        if svc in ("private", "other"):
            continue
        check("service %s" % svc, sum(1 for r in records if r["service"] == svc), want)
    for b in range(20):
        check("risk bucket [%d,%d)" % (b * 5, b * 5 + 5), counts[b], RISK_BUCKETS[b])

    mean = sum(r["risk_score"] for r in records) / len(records)
    print("  ----  mean risk %.4f (want 23.14)   min %.2f  max %.2f"
          % (mean, min(r["risk_score"] for r in records),
             max(r["risk_score"] for r in records)))
    print("  ----  Security Health Index %.2f (want 76.86)" % (100 - mean))
    print("-" * 62)
    print("ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED")
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-csv", metavar="DIR",
                    help="use the real notebook CSVs in DIR instead of reconstructing")
    args = ap.parse_args()

    os.makedirs(DATA, exist_ok=True)
    os.makedirs(JSDIR, exist_ok=True)

    if args.from_csv:
        print("Loading the real notebook CSVs from %s" % args.from_csv)
        load_aux(args.from_csv)
        records = load_records(args.from_csv)
    else:
        print("Reconstructing 25,192 records from the published aggregates")
        records = build_records()

    payload, top100, service_stats = build_outputs(records)
    counts = write_csvs(records, payload, top100, service_stats)
    if not args.from_csv:
        verify(records, counts)

    js = os.path.join(JSDIR, "data.js")
    with open(js, "w", encoding="utf-8") as fh:
        fh.write("/* Generated by tools/build_data.py — do not edit by hand. */\n")
        fh.write("window.IDS_DATA = ")
        json.dump(payload, fh, separators=(",", ":"))
        fh.write(";\n")

    print("\nWrote %d fact rows -> %s (%.0f KB)"
          % (len(payload["facts"]), js, os.path.getsize(js) / 1024))
    print("Wrote 9 CSVs -> %s" % DATA)
    print("Top Risk Records table: %d aggregated rows" % len(payload["topRisk"]))


if __name__ == "__main__":
    main()
