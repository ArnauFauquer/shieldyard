"""One report per repository, built from everything the platform knows about it.

    python report.py my-repo         (scan.py runs this at the end)

Writes reports/<repo>/report.html: a single self-contained file (no external
assets, opens offline, prints) with security findings, dependencies, code
quality, complexity, DORA metrics and the last scan run. Every number links back
to the tool that owns it. reports/<repo>/history.json keeps one line per report
so trends survive between runs.
"""

from __future__ import annotations

import argparse
import base64
import json
import statistics
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from html import escape
from pathlib import Path
from urllib.parse import quote

from common import (
    DEVLAKE_UI_URL,
    DOJO_URL,
    ROOT,
    SONAR_URL,
    HttpError,
    load_env,
    request,
)

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]

# DefectDojo test title prefix -> what a reader would call it.
CATEGORIES = [
    ("Secrets", ("gitleaks", "trufflehog")),
    ("Code", ("semgrep", "bandit")),
    ("Dependencies", ("trivy (lockfiles)", "pip-audit", "osv-scanner")),
    ("Container images", ("trivy (",)),
    ("Dependency hygiene", ("deptry", "knip")),
    ("Licenses", ("trivy licenses",)),
    ("Infrastructure", ("checkov", "kics", "hadolint", "zizmor", "poutine", "actionlint")),
    ("Personal data", ("ferret-scan",)),
    ("Supply chain", ("guarddog", "scorecard")),
    ("Complexity", ("lizard",)),
    # web.py, against the deployed site
    ("Exposed site: vulnerabilities", ("nuclei", "zap", "schemathesis", "nikto")),
    ("Exposed site: TLS", ("testssl",)),
    ("Exposed site: ports, URLs and paths", ("nmap", "httpx", "feroxbuster", "wafw00f")),
    ("Exposed site: DNS and email", ("dnsx",)),
    ("Exposed site: lookalike domains", ("dnstwist",)),
    # osint.py
    ("Public footprint", ("theharvester",)),
    ("Breached accounts", ("hibp",)),
]


def slug(text: str) -> str:
    import re
    return re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-").lower()


def category(test_title: str) -> str:
    for name, prefixes in CATEGORIES:
        if test_title.startswith(prefixes):
            return name
    return "Other"


# ── Data ──────────────────────────────────────────────────────────────────────


def dojo(env, product: str, branch: str) -> dict:
    """Active findings of the scanned branch's engagement (scan.py makes one per branch)
    and of every "exposure <target>" (web.py) and "osint" (osint.py) engagement of the product."""
    auth = {"Authorization": f"Token {env['DD_API_TOKEN']}"}
    products = request("GET", f"{DOJO_URL}/api/v2/products/?name={quote(product)}", headers=auth)["results"]
    if not products:
        return {}
    pid = products[0]["id"]
    engagements = request("GET", f"{DOJO_URL}/api/v2/engagements/?product={pid}&limit=500", headers=auth)["results"]
    ids = [e["id"] for e in engagements if e["name"] == f"branch {branch}" or e["name"].startswith(("exposure ", "osint"))]
    if not ids:
        return {}
    titles, findings, urls = {}, [], {}
    for eid in ids:
        tests = request("GET", f"{DOJO_URL}/api/v2/tests/?engagement={eid}&limit=500", headers=auth)["results"]
        titles.update({t["id"]: t.get("title") or t.get("test_type_name") or "" for t in tests})
        page = request("GET", f"{DOJO_URL}/api/v2/findings/?test__engagement={eid}&active=true&limit=5000"
                              "&prefetch=endpoints", headers=auth)
        findings += page["results"]
        urls.update((page.get("prefetch") or {}).get("endpoints") or {})
    for f in findings:
        f["tool"] = titles.get(f["test"], "")
        f["category"] = category(f["tool"])
        if not f.get("file_path") and f.get("endpoints"):  # sites have URLs, not files
            f["file_path"] = ", ".join(endpoint_url(urls.get(str(e)) or {}) for e in f["endpoints"][:3])
    # The DefectDojo link goes to the branch's engagement, or the product when there's only sites.
    branch_ids = [e["id"] for e in engagements if e["name"] == f"branch {branch}"]
    link = f"{DOJO_URL}/engagement/{branch_ids[0]}" if branch_ids else f"{DOJO_URL}/product/{pid}"
    return {"id": pid, "link": link, "findings": findings}


def endpoint_url(e: dict) -> str:
    if e.get("location_value"):  # DefectDojo 3.x: a location with its URL
        return e["location_value"]
    port = f":{e['port']}" if e.get("port") and e["port"] not in (80, 443) else ""
    path = f"/{e['path'].lstrip('/')}" if e.get("path") else ""
    return f"{e.get('protocol') + '://' if e.get('protocol') else ''}{e.get('host', '')}{port}{path}"


def sbom_inventory(run_dir: Path | None, run: dict) -> list[dict]:
    """The SBOMs the last scan saved: how many components, of which ecosystems."""
    out = []
    for entry in run.get("sboms") or []:
        path = run_dir / entry["sbom"] if run_dir else None
        if not path or not path.exists():
            continue
        components = json.loads(path.read_text(encoding="utf-8")).get("components", [])
        kinds: dict[str, int] = {}
        for c in components:
            purl = c.get("purl") or ""
            kind = purl[4:].split("/", 1)[0] if purl.startswith("pkg:") else c.get("type", "other")
            kinds[kind] = kinds.get(kind, 0) + 1
        out.append({**entry, "components": len(components), "kinds": kinds})
    return out


def sonar(env, product: str) -> dict:
    auth = {"Authorization": "Basic " + base64.b64encode((env["SONAR_TOKEN"] + ":").encode()).decode()}
    key = slug(product)
    metrics = ("ncloc,complexity,cognitive_complexity,bugs,vulnerabilities,code_smells,security_hotspots,"
               "duplicated_lines_density,coverage,sqale_rating,reliability_rating,security_rating,sqale_index")
    measures = request("GET", f"{SONAR_URL}/api/measures/component?component={key}&metricKeys={metrics}", headers=auth)
    gate = request("GET", f"{SONAR_URL}/api/qualitygates/project_status?projectKey={key}", headers=auth)
    issues = request(
        "GET", f"{SONAR_URL}/api/issues/search?components={key}&issueStatuses=OPEN,CONFIRMED"
               f"&impactSeverities=BLOCKER,HIGH&ps=10&s=SEVERITY&asc=false", headers=auth)
    everything, page = [], 1
    while True:  # every open issue, for the full list; 500 is the API's page limit
        batch = request("GET", f"{SONAR_URL}/api/issues/search?components={key}&issueStatuses=OPEN,CONFIRMED"
                               f"&ps=500&p={page}", headers=auth)
        everything += batch.get("issues", [])
        if len(everything) >= batch.get("total", 0) or not batch.get("issues"):
            break
        page += 1
    return {
        "key": key,
        "m": {m["metric"]: m.get("value") for m in measures["component"]["measures"]},
        "gate": gate["projectStatus"]["status"],
        "gate_conditions": gate["projectStatus"].get("conditions", []),
        "issues": issues.get("issues", []),
        "issues_total": issues.get("total", 0),
        "all_issues": everything,
    }


def devlake_sql(query: str) -> list[list[str]]:
    proc = subprocess.run(
        ["docker", "compose", "exec", "-T", "devlake-mysql", "sh", "-c",
         'mysql -umerico -p"$MYSQL_PASSWORD" lake -N -B 2>/dev/null'],
        input=query, cwd=ROOT, capture_output=True, text=True, check=True,
    )
    return [line.split("\t") for line in proc.stdout.splitlines() if line]


def dora(project: str) -> dict:
    """The four keys over the last 90 days, roughly as DevLake's DORA dashboard counts them."""
    p = project.replace("'", "''")
    deploys = devlake_sql(f"""
        SELECT DISTINCT cdc.cicd_deployment_id, cdc.finished_date
        FROM cicd_deployment_commits cdc
        JOIN project_mapping pm ON pm.row_id = cdc.cicd_scope_id AND pm.`table` = 'cicd_scopes'
        WHERE pm.project_name = '{p}' AND cdc.result = 'SUCCESS' AND cdc.environment = 'PRODUCTION'
          AND cdc.finished_date >= NOW() - INTERVAL 90 DAY""")
    lead = devlake_sql(f"""
        SELECT pr_cycle_time FROM project_pr_metrics
        WHERE project_name = '{p}' AND pr_cycle_time IS NOT NULL AND pr_deployed_date >= NOW() - INTERVAL 90 DAY""")
    failed = devlake_sql(f"""
        SELECT COUNT(DISTINCT deployment_id) FROM project_incident_deployment_relationships pidr
        JOIN cicd_deployment_commits cdc ON cdc.cicd_deployment_id = pidr.deployment_id
        WHERE pidr.project_name = '{p}' AND cdc.finished_date >= NOW() - INTERVAL 90 DAY""")
    restore = devlake_sql(f"""
        SELECT i.lead_time_minutes FROM incidents i
        JOIN project_incident_deployment_relationships pidr ON pidr.id = i.id
        WHERE pidr.project_name = '{p}' AND i.lead_time_minutes IS NOT NULL
          AND i.resolution_date >= NOW() - INTERVAL 90 DAY""")
    n = len({d[0] for d in deploys})
    return {
        "deploys": n,
        "per_week": n / (90 / 7),
        "lead_hours": statistics.median(int(r[0]) for r in lead) / 60 if lead else None,
        "cfr": (int(failed[0][0]) / n) if n and failed else None,
        "restore_hours": statistics.median(int(r[0]) for r in restore) / 60 if restore else None,
        "prs": len(lead),
    }


def last_run(product: str) -> tuple[Path | None, dict]:
    runs = sorted((ROOT / "reports" / slug(product)).glob("*/run.json"))
    if not runs:
        return None, {}
    return runs[-1].parent, json.loads(runs[-1].read_text(encoding="utf-8"))


def complexity_rows(run_dir: Path | None) -> list[dict]:
    path = run_dir / "lizard.jsonl" if run_dir else None
    if not path or not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_suites(run_dir: Path | None, run: dict) -> list[dict]:
    """Per suite: JUnit results plus line coverage per file, from the files scan.py left."""
    if not run_dir:
        return []
    names = {slug(t["name"].split(" (")[0].removeprefix("tests ")): t["name"].removeprefix("tests ")
             for t in run.get("tools", []) if t["name"].startswith("tests ")}
    suites = []
    for s, label in names.items():
        suite = {"name": label, "tests": 0, "failed": 0, "skipped": 0, "seconds": 0.0, "files": []}
        junit = run_dir / f"junit-{s}.xml"
        if junit.exists():
            root = ET.parse(junit).getroot()
            for ts in ([root] if root.tag == "testsuite" else root.iter("testsuite")):
                suite["tests"] += int(ts.get("tests", 0))
                suite["failed"] += int(ts.get("failures", 0)) + int(ts.get("errors", 0))
                suite["skipped"] += int(ts.get("skipped", 0))
                suite["seconds"] += float(ts.get("time", 0) or 0)
        cobertura, lcov = run_dir / f"coverage-{s}.xml", run_dir / f"lcov-{s}.info"
        if cobertura.exists():
            root = ET.parse(cobertura).getroot()
            base = (root.findtext("sources/source") or "/usr/src").removeprefix("/usr/src").strip("/")
            for cls in root.iter("class"):
                lines = [int(line.get("hits", 0)) for line in cls.iter("line")]
                path = f"{base}/{cls.get('filename')}".strip("/")
                suite["files"].append((path, len(lines), sum(h > 0 for h in lines)))
        elif lcov.exists():
            path, total, hit = None, 0, 0
            for line in lcov.read_text(encoding="utf-8").splitlines():
                if line.startswith("SF:"):
                    path = line[3:].removeprefix("/usr/src/")
                elif line.startswith("LF:"):
                    total = int(line[3:])
                elif line.startswith("LH:"):
                    hit = int(line[3:])
                elif line == "end_of_record" and path:
                    suite["files"].append((path, total, hit))
                    path, total, hit = None, 0, 0
        suite["lines"] = sum(f[1] for f in suite["files"])
        suite["covered"] = sum(f[2] for f in suite["files"])
        if suite["tests"] or suite["files"]:
            suites.append(suite)
    return suites


def safely(fn, *args):
    try:
        return fn(*args), None
    except (OSError, HttpError, KeyError, ValueError, IndexError, subprocess.CalledProcessError) as e:
        return None, str(e)[:200] or type(e).__name__


# ── Rendering ─────────────────────────────────────────────────────────────────

CSS = """
:root{--bg:#f6f7f8;--surface:#fff;--ink:#16191d;--muted:#5d6670;--line:#e2e5e9;--soft:#eef0f2;
--accent:#0f6fcf;--crit:#b4232a;--high:#d1560f;--med:#a87b00;--low:#3b6ea8;--info:#6b7480;--ok:#1f7a4d;
--mono:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,monospace;
--sans:"Segoe UI Variable","Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif}
@media (prefers-color-scheme:dark){:root{--bg:#111316;--surface:#181b1f;--ink:#e7e9ec;--muted:#9aa3ad;
--line:#2a2f35;--soft:#20242a;--accent:#5aa2ef;--crit:#f06a6f;--high:#f28c4b;--med:#e0b43c;--low:#7aa7dc;
--info:#8b949e;--ok:#4cc18a}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 var(--sans)}
main{max-width:1240px;margin:0 auto;padding:28px 20px 64px}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
h1{font-size:26px;letter-spacing:-.02em;margin:0;font-weight:650}
h2{font-size:17px;margin:0 0 4px;font-weight:650;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:13px}
header{display:flex;flex-wrap:wrap;gap:12px 32px;align-items:flex-end;justify-content:space-between;margin-bottom:22px}
header nav{display:flex;flex-wrap:wrap;gap:6px}
header nav a{border:1px solid var(--line);background:var(--surface);border-radius:8px;padding:5px 10px;font-size:13px;color:var(--ink)}
.kpis{display:grid;grid-template-columns:repeat(8,minmax(0,1fr));gap:1px;background:var(--line);border:1px solid var(--line);border-radius:10px;overflow:hidden;margin-bottom:28px}
.kpi{background:var(--surface);padding:14px 16px}
.kpi .v{font:600 26px/1.15 var(--mono);letter-spacing:-.02em}
.kpi .l{color:var(--muted);font-size:12.5px;margin-top:4px}
.kpi .d{font:12px var(--mono);color:var(--muted)}
section{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:20px 22px;margin-bottom:18px}
section>header{margin-bottom:14px;align-items:baseline}
.grid2{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(0,1fr);gap:28px;align-items:start}
table{width:100%;border-collapse:collapse;font-size:13px}
.tw{overflow-x:auto}
th{text-align:left;font-weight:600;color:var(--muted);font-size:12px;padding:6px 8px;border-bottom:1px solid var(--line)}
td{padding:6px 8px;vertical-align:top}
tbody tr:nth-child(even) td{background:var(--soft)}
td.n,th.n{text-align:right;font-family:var(--mono);white-space:nowrap}
td.z{color:var(--muted);opacity:.55}
.loc{font-family:var(--mono);font-size:12px;color:var(--muted);word-break:break-all}
.sev{display:inline-block;min-width:62px;font:600 11.5px/1 var(--sans);padding:4px 7px;border-radius:5px;color:#fff;text-align:center}
.s-Critical{background:var(--crit)}.s-High{background:var(--high)}.s-Medium{background:var(--med)}
.s-Low{background:var(--low)}.s-Info{background:var(--info)}
.c-Critical{color:var(--crit)}.c-High{color:var(--high)}.c-Medium{color:var(--med)}.c-Low{color:var(--low)}
.rating{display:inline-grid;place-items:center;width:30px;height:30px;border-radius:7px;font:700 15px var(--sans);color:#fff}
.r-A{background:var(--ok)}.r-B{background:#6b9b2e}.r-C{background:var(--med)}.r-D{background:var(--high)}.r-E{background:var(--crit)}
.qual{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px 18px;margin-bottom:18px}
.qual div{display:flex;gap:10px;align-items:center}
.qual b{display:block;font:600 18px var(--mono)}
.qual span:not(.rating){color:var(--muted);font-size:12.5px}
.gate{font:600 12px var(--sans);padding:4px 9px;border-radius:6px;border:1px solid}
.gate.OK{color:var(--ok);border-color:var(--ok)}.gate.ERROR{color:var(--crit);border-color:var(--crit)}.gate.NONE{color:var(--muted);border-color:var(--line)}
.dora{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:18px}
.dora .v{font:600 22px var(--mono)}
.dora .lvl{font-size:12px;font-weight:600}
.lvl.Elite{color:var(--ok)}.lvl.High{color:#6b9b2e}.lvl.Medium{color:var(--med)}.lvl.Low{color:var(--crit)}
.empty{border:1px dashed var(--line);border-radius:8px;padding:16px;color:var(--muted)}
.empty code,code{font-family:var(--mono);font-size:12.5px;background:var(--soft);padding:1px 5px;border-radius:4px;color:var(--ink)}
.bar{display:flex;height:8px;border-radius:4px;overflow:hidden;background:var(--soft);margin-top:6px}
.bar i{display:block}
.sub code{word-break:break-all}
.ok{color:var(--ok)}.bad{color:var(--crit)}
svg.trend{width:100%;height:64px;display:block}
details{border-top:1px solid var(--line);padding:10px 0}
details:first-of-type{border-top:0}
summary{cursor:pointer;font-size:14px;list-style-position:outside;margin-left:14px}
details table{margin-top:10px;table-layout:fixed}
details col.c-sev{width:92px}details col.c-tool{width:24%}details col.c-fix{width:96px}details col.c-found{width:104px}
details td{overflow-wrap:anywhere}
@media (max-width:560px){details col.c-tool,details col.c-fix,details col.c-found{width:0}}
@media print{details{break-inside:auto}details:not([open]) table{display:none}}
footer{color:var(--muted);font-size:12px;margin-top:24px}
@media (max-width:1100px){.kpis{grid-template-columns:repeat(4,minmax(0,1fr))}}
@media (max-width:960px){.grid2{grid-template-columns:minmax(0,1fr)}.dora,.qual{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:560px){main{padding:18px 12px 48px}.kpis{grid-template-columns:repeat(2,minmax(0,1fr))}section{padding:16px 14px}td.hide,th.hide{display:none}}
@media print{body{background:#fff}section,.kpis{break-inside:avoid}header nav{display:none}}
"""


def sev(s: str) -> str:
    return f'<span class="sev s-{escape(s)}">{escape(s)}</span>'


def num(v, digits=0, empty="-") -> str:
    if v is None or v == "":
        return empty
    try:
        f = float(v)
    except ValueError:
        return escape(str(v))
    return f"{f:,.{digits}f}"


def unavailable(name: str, error: str | None, hint: str) -> str:
    detail = f" ({escape(error)})" if error else ""
    return f'<div class="empty">{escape(name)} has no data for this repository yet{detail}. {hint}</div>'


def trend_svg(history: list[dict]) -> str:
    points = [h for h in history if "open" in h][-20:]
    if len(points) < 2:
        return '<p class="sub">The trend appears after the second scan.</p>'
    w, h, pad = 600, 64, 6
    top = max(1, *(p["open"] for p in points))

    def line(key: str, color: str) -> str:
        coords = " ".join(
            f"{pad + i * (w - 2 * pad) / (len(points) - 1):.1f},{h - pad - p.get(key, 0) / top * (h - 2 * pad):.1f}"
            for i, p in enumerate(points))
        return f'<polyline fill="none" stroke="{color}" stroke-width="2" points="{coords}" vector-effect="non-scaling-stroke"/>'

    first, last = points[0], points[-1]
    return (f'<svg class="trend" viewBox="0 0 {w} {h}" preserveAspectRatio="none" role="img" '
            f'aria-label="Open findings across the last {len(points)} reports">'
            f'{line("open", "var(--muted)")}{line("crit_high", "var(--crit)")}</svg>'
            f'<p class="sub">Last {len(points)} reports: open {first["open"]} to {last["open"]}, '
            f'critical + high {first["crit_high"]} to {last["crit_high"]}. '
            f'<span style="color:var(--crit)">Red</span> is critical + high.</p>')


def dora_level(metric: str, value) -> str:
    if value is None:
        return ""
    bands = {  # (elite, high, medium) upper bounds, after the DORA report's ranges
        "per_week": None,
        "lead_hours": (24, 24 * 7, 24 * 30),
        "cfr": (0.05, 0.10, 0.15),
        "restore_hours": (1, 24, 24 * 7),
    }
    if metric == "per_week":
        level = "Elite" if value >= 7 else "High" if value >= 1 else "Medium" if value >= 0.25 else "Low"
    else:
        e, hi, m = bands[metric]
        level = "Elite" if value <= e else "High" if value <= hi else "Medium" if value <= m else "Low"
    return f'<div class="lvl {level}">{level}</div>'


SONAR_SEVERITY = {"BLOCKER": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Info"}


def all_findings(findings: list[dict], sq: dict | None) -> str:
    """Every open finding from every tool, one table per area, most severe first."""
    rows: dict[str, list[tuple]] = {}  # area -> (severity, title html, where, tool, found, fix)

    for f in findings:
        where = f.get("file_path") or ""
        if f.get("line"):
            where += f':{f["line"]}'
        if f.get("component_name"):
            where = f'{f["component_name"]} {f.get("component_version") or ""} {where}'.strip()
        fix = (f.get("mitigation") or "").strip().splitlines()
        fix = fix[0] if fix and len(fix[0]) <= 40 else ""
        rows.setdefault(f["category"], []).append((
            f["severity"], f'<a href="{DOJO_URL}/finding/{f["id"]}">{escape(f["title"])}</a>',
            where, f["tool"], f.get("date") or "", fix))

    for issue in (sq or {}).get("all_issues", []):
        impacts = issue.get("impacts") or []
        worst = min((SEVERITIES.index(SONAR_SEVERITY.get(i["severity"], "Info")) for i in impacts), default=4)
        quality = ", ".join(sorted({i["softwareQuality"].lower() for i in impacts}))
        rows.setdefault("Code quality (SonarQube)", []).append((
            SEVERITIES[worst],
            f'<a href="{SONAR_URL}/project/issues?id={sq["key"]}&open={issue["key"]}">{escape(issue["message"])}</a>',
            f'{issue["component"].split(":", 1)[-1]}:{issue.get("line", "")}', f'sonar {issue["rule"]} ({quality})',
            (issue.get("creationDate") or "")[:10], ""))

    total = sum(len(r) for r in rows.values())
    if not total:
        return ('<section id="all-findings"><h2>All findings</h2>'
                '<div class="empty">No open findings in any tool.</div></section>')

    order = [c for c, _ in CATEGORIES] + ["Other", "Code quality (SonarQube)"]
    groups = []
    for area in sorted(rows, key=lambda a: order.index(a) if a in order else len(order)):
        items = sorted(rows[area], key=lambda r: (SEVERITIES.index(r[0]), r[2]))
        counts = ", ".join(f"{n} {s.lower()}" for s in SEVERITIES if (n := sum(r[0] == s for r in items)))
        body = "".join(
            f'<tr><td>{sev(s)}</td><td>{title}<div class="loc">{escape(where[:160])}</div></td>'
            f'<td class="hide loc">{escape(tool)}</td><td class="hide loc">{escape(fix)}</td>'
            f'<td class="n hide">{escape(found)}</td></tr>'
            for s, title, where, tool, found, fix in items)
        # Big groups start closed so one noisy tool doesn't bury the rest.
        groups.append(
            f'<details{" open" if len(items) <= 50 else ""}><summary><b>{escape(area)}</b> '
            f'<span class="sub">{len(items)}: {counts}</span></summary><div class="tw"><table>'
            '<colgroup><col class="c-sev"><col><col class="c-tool"><col class="c-fix"><col class="c-found"></colgroup>'
            '<thead><tr><th>Severity</th><th>Finding</th><th class="hide">Tool</th><th class="hide">Fixed in</th>'
            f'<th class="n hide">Found</th></tr></thead><tbody>{body}</tbody></table></div></details>')
    return ('<section id="all-findings"><header><div><h2>All findings</h2><div class="sub">'
            f'{total} open: every DefectDojo finding plus every SonarQube issue.</div></div></header>'
            + "".join(groups) + "</section>")


def render(product: str, data: dict) -> str:
    dd, dd_err = data["dojo"]
    sboms = data["sboms"]
    sq, sq_err = data["sonar"]
    dl, dl_err = data["dora"]
    run_dir, run = data["run"]
    lizard = data["lizard"]
    history = data["history"]

    findings = (dd or {}).get("findings", [])
    by_sev = {s: sum(f["severity"] == s for f in findings) for s in SEVERITIES}
    sbom_titles = {s["test_title"] for s in sboms}
    dep_findings = [f for f in findings if f["tool"] in sbom_titles]
    vulnerable = len({(f["tool"], f.get("component_name"), f.get("component_version")) for f in dep_findings})
    components = sum(s["components"] for s in sboms)
    over15 = sum(r["ccn"] > 15 for r in lizard)
    avg_ccn = statistics.mean(r["ccn"] for r in lizard) if lizard else None
    gate = (sq or {}).get("gate", "NONE")
    suites = data["tests"]
    tests_total = sum(s["tests"] for s in suites)
    tests_failed = sum(s["failed"] for s in suites)
    lines_total = sum(s["lines"] for s in suites)
    coverage = sum(s["covered"] for s in suites) / lines_total if lines_total else None

    # Header + KPI strip
    commit = run.get("commit", "")[:12]
    parts = [
        f"<header><div><h1>{escape(product)}</h1>"
        f'<div class="sub">{escape(run.get("branch", "?"))} at <code>{escape(commit)}</code>, '
        f'scanned {escape(run.get("finished", "never"))}, report built {datetime.now():%Y-%m-%d %H:%M}</div></div>'
        f'<nav><a href="#all-findings">All findings</a>'
        f'<a href="{(dd or {}).get("link", DOJO_URL)}">DefectDojo</a>'
        f'<a href="{SONAR_URL}/dashboard?id={slug(product)}">SonarQube</a>'
        f'<a href="{DEVLAKE_UI_URL}/grafana/d/qNo8_0M4z/dora">DORA</a></nav></header>',
        '<div class="kpis">',
        f'<div class="kpi"><div class="v c-Critical">{by_sev["Critical"]}</div><div class="l">Critical findings</div></div>',
        f'<div class="kpi"><div class="v c-High">{by_sev["High"]}</div><div class="l">High findings</div></div>',
        f'<div class="kpi"><div class="v">{len(findings)}</div><div class="l">Open findings, all tools</div></div>',
        f'<div class="kpi"><div class="v">{vulnerable}<span class="d"> / {components}</span></div><div class="l">Vulnerable components</div></div>',
        f'<div class="kpi"><div class="v {"ok" if gate == "OK" else "bad" if gate == "ERROR" else ""}">{ {"OK": "Passed", "ERROR": "Failed"}.get(gate, "None")}</div><div class="l">Sonar quality gate</div></div>',
        f'<div class="kpi"><div class="v {"bad" if tests_failed else "ok" if tests_total else ""}">'
        + (f'{tests_total - tests_failed}<span class="d"> / {tests_total}</span>' if tests_total else "-")
        + '</div><div class="l">Tests passing</div></div>',
        f'<div class="kpi"><div class="v">{f"{coverage:.1%}" if coverage is not None else "-"}</div>'
        f'<div class="l">Line coverage, all suites</div></div>',
        f'<div class="kpi"><div class="v">{over15}</div><div class="l">Functions over CCN 15'
        + (f', avg {avg_ccn:.1f}' if avg_ccn else "") + '</div></div>',
        "</div>",
    ]

    # Findings matrix + trend
    if dd:
        cats = [c for c, _ in CATEGORIES] + (["Other"] if any(f["category"] == "Other" for f in findings) else [])
        rows = []
        for c in cats:
            cells = [sum(f["category"] == c and f["severity"] == s for f in findings) for s in SEVERITIES]
            tools = sorted({f["tool"].split(" (")[0] for f in findings if f["category"] == c})
            rows.append(f'<tr><td>{c}<div class="loc">{escape(", ".join(tools)) or "clean"}</div></td>'
                        + "".join(f'<td class="n{"" if v else " z"}">{v}</td>' for v in cells)
                        + f'<td class="n"><b>{sum(cells)}</b></td></tr>')
        matrix = ('<div class="tw"><table><thead><tr><th>Area</th>' + "".join(f'<th class="n">{s}</th>' for s in SEVERITIES)
                  + '<th class="n">Total</th></tr></thead><tbody>' + "".join(rows) + "</tbody></table></div>")
        parts.append(f'<section><header><div><h2>Security findings</h2><div class="sub">Active in DefectDojo, deduplicated per tool. '
                     f'False positives and accepted risks are already excluded.</div></div></header>'
                     f'<div class="grid2"><div>{matrix}</div><div>{trend_svg(history)}</div></div></section>')

        order = {s: i for i, s in enumerate(SEVERITIES)}
        top = sorted((f for f in findings if f["severity"] in ("Critical", "High")),
                     key=lambda f: (order[f["severity"]], f["category"], f["title"]))[:30]
        if top:
            rows = []
            for f in top:
                where = f.get("file_path") or ""
                if f.get("line"):
                    where += f':{f["line"]}'
                if f.get("component_name"):
                    where = f'{f["component_name"]} {f.get("component_version") or ""} {where}'.strip()
                rows.append(f'<tr><td>{sev(f["severity"])}</td><td><a href="{DOJO_URL}/finding/{f["id"]}">{escape(f["title"][:110])}</a>'
                            f'<div class="loc">{escape(where[:140])}</div></td><td class="hide">{escape(f["category"])}</td>'
                            f'<td class="hide loc">{escape(f["tool"])}</td></tr>')
            more = by_sev["Critical"] + by_sev["High"] - len(top)
            parts.append('<section><header><div><h2>Fix first</h2><div class="sub">Critical and high, grouped by area'
                         + (f", {more} more in DefectDojo" if more > 0 else "") + '.</div></div></header>'
                         '<table><thead><tr><th>Severity</th><th>Finding</th><th class="hide">Area</th><th class="hide">Tool</th></tr></thead><tbody>'
                         + "".join(rows) + "</tbody></table></section>")
    else:
        parts.append('<section><h2>Security findings</h2>' + unavailable("DefectDojo", dd_err, "Run <code>python scan.py &lt;repo&gt;</code>.") + "</section>")

    # Dependencies: the stored SBOMs, and the DefectDojo findings trivy made from each
    if sboms:
        rows = []
        for s in sboms:
            mine = [f for f in dep_findings if f["tool"] == s["test_title"]]
            counts = {k: sum(f["severity"] == k for f in mine) for k in ("Critical", "High", "Medium", "Low")}
            total = sum(counts.values())
            bar = "".join(f'<i style="width:{n / total * 100:.1f}%;background:var(--{c})"></i>'
                          for n, c in zip(counts.values(), ("crit", "high", "med", "low"), strict=False)) if total else ""
            kinds = ", ".join(f"{n} {k}" for k, n in sorted(s["kinds"].items(), key=lambda kv: -kv[1])[:4])
            rows.append(f'<tr><td>{escape(s["label"])}<div class="loc">{escape(kinds)}</div>'
                        f'{f"<div class=bar>{bar}</div>" if bar else ""}</td>'
                        f'<td class="n">{s["components"]:,}</td>'
                        f'<td class="n">{len({(f.get("component_name"), f.get("component_version")) for f in mine})}</td>'
                        + "".join(f'<td class="n{"" if n else " z"}">{n}</td>' for n in counts.values()) + "</tr>")
        parts.append('<section><header><div><h2>Dependencies</h2><div class="sub">One SBOM per source tree and image, '
                     'kept with each scan; trivy finds the CVEs in it, as of the scan. '
                     'Find a component in all of them with <code>python inventory.py &lt;name&gt;</code>.</div></div></header>'
                     '<div class="tw"><table><thead><tr><th>SBOM</th><th class="n">Components</th><th class="n">Vulnerable</th>'
                     '<th class="n">Crit</th><th class="n">High</th><th class="n">Med</th><th class="n">Low</th></tr></thead><tbody>'
                     + "".join(rows) + "</tbody></table></div></section>")
    else:
        parts.append('<section><h2>Dependencies</h2>' + unavailable("The last scan", None, "Rescan with <code>scan.py</code> to save SBOMs.") + "</section>")

    # Code quality
    if sq:
        m = sq["m"]
        letter = lambda v: "ABCDE"[int(float(v)) - 1] if v else "-"  # noqa: E731

        def rating(label, key, count_key, count_label):
            r = letter(m.get(key))
            return (f'<div><span class="rating r-{r}">{r}</span><div><b>{num(m.get(count_key))}</b>'
                    f'<span>{label}: {count_label}</span></div></div>')

        debt_days = float(m.get("sqale_index") or 0) / 60 / 8
        qual = (
            '<div class="qual">'
            + rating("Reliability", "reliability_rating", "bugs", "bugs")
            + rating("Security", "security_rating", "vulnerabilities", "vulnerabilities")
            + rating("Maintainability", "sqale_rating", "code_smells", f"code smells, {debt_days:.1f} days of debt")
            + f'<div><div><b>{num(m.get("security_hotspots"))}</b><span>security hotspots to review</span></div></div>'
            + f'<div><div><b>{num(m.get("duplicated_lines_density"), 1)}%</b><span>duplicated lines</span></div></div>'
            # Sonar reports 0.0 when it was never given a coverage report.
            + (f'<div><div><b>{num(m.get("coverage"), 1)}%</b><span>test coverage</span></div></div>'
               if float(m.get("coverage") or 0) > 0 else
               '<div><div><b>not measured</b><span>test coverage (no coverage report sent)</span></div></div>')
            + f'<div><div><b>{num(m.get("ncloc"))}</b><span>lines of code</span></div></div>'
            + f'<div><div><b>{num(m.get("complexity"))}</b><span>cyclomatic complexity, total</span></div></div>'
            + f'<div><div><b>{num(m.get("cognitive_complexity"))}</b><span>cognitive complexity, total</span></div></div>'
            + "</div>"
        )
        irows = "".join(
            f'<tr><td>{sev("High" if any(i["severity"] in ("HIGH", "BLOCKER") for i in issue.get("impacts", [])) else "Medium")}</td>'
            f'<td><a href="{SONAR_URL}/project/issues?id={sq["key"]}&open={issue["key"]}">{escape(issue["message"][:120])}</a>'
            f'<div class="loc">{escape(issue["component"].split(":", 1)[-1])}:{issue.get("line", "")}</div></td></tr>'
            for issue in sq["issues"])
        failed = [c for c in sq["gate_conditions"] if c.get("status") == "ERROR"]
        gate_note = (", failing on " + ", ".join(escape(c["metricKey"].replace("_", " ")) for c in failed)) if failed else ""
        parts.append(f'<section><header><div><h2>Code quality</h2><div class="sub">SonarQube, main branch'
                     f'{gate_note}.</div></div><span class="gate {gate}">Quality gate { {"OK": "passed", "ERROR": "failed"}.get(gate, "not computed")}</span></header>'
                     + qual
                     + (f'<h2>Highest-impact issues</h2><div class="sub" style="margin-bottom:8px">{sq["issues_total"]} with high or blocker impact.</div>'
                        f'<table><tbody>{irows}</tbody></table>' if irows else "")
                     + "</section>")
    else:
        parts.append('<section><h2>Code quality</h2>' + unavailable("SonarQube", sq_err, "sonar-scanner runs with each scan.") + "</section>")

    # Tests and coverage
    if suites:
        def pct(covered, total):
            return covered / total if total else 0.0

        def bar(p):
            tone = "ok" if p >= 0.8 else "med" if p >= 0.5 else "crit"
            return f'<div class="bar"><i style="width:{p * 100:.1f}%;background:var(--{tone})"></i></div>'

        rows = "".join(
            f'<tr><td>{escape(s["name"])}</td>'
            f'<td class="n">{s["tests"]}</td><td class="n{" bad" if s["failed"] else " z"}">{s["failed"]}</td>'
            f'<td class="n hide{"" if s["skipped"] else " z"}">{s["skipped"]}</td><td class="n hide">{s["seconds"]:.0f}s</td>'
            f'<td class="n">{pct(s["covered"], s["lines"]):.1%}{bar(pct(s["covered"], s["lines"]))}</td>'
            f'<td class="n hide">{s["covered"]:,} / {s["lines"]:,}</td></tr>'
            for s in suites)
        # Ranked by lines nobody tests, not by percentage: a 2-line file at 0% matters less.
        files = sorted(((f, s["name"]) for s in suites for f in s["files"] if f[1]),
                       key=lambda t: t[0][1] - t[0][2], reverse=True)[:12]
        frows = "".join(
            f'<tr><td><span class="loc">{escape(path)}</span></td><td class="n">{total - hit:,}</td>'
            f'<td class="n">{pct(hit, total):.0%}{bar(pct(hit, total))}</td></tr>'
            for (path, total, hit), _ in files)
        parts.append(
            '<section><header><div><h2>Tests and coverage</h2><div class="sub">Every pytest and vitest/jest suite, run in '
            "the runtime its Dockerfile uses. Line coverage also goes to SonarQube.</div></div></header>"
            '<div class="grid2"><div class="tw"><table><thead><tr><th>Suite</th><th class="n">Tests</th><th class="n">Failed</th>'
            '<th class="n hide">Skipped</th><th class="n hide">Time</th><th class="n">Coverage</th><th class="n hide">Lines</th></tr></thead>'
            f"<tbody>{rows}</tbody></table></div>"
            '<div class="tw"><table><thead><tr><th>Least covered files</th><th class="n">Untested lines</th><th class="n">Coverage</th></tr></thead>'
            f"<tbody>{frows}</tbody></table></div></div></section>")
    else:
        parts.append('<section><h2>Tests and coverage</h2>'
                     + unavailable("The scan", None, "Suites are found by <code>test_*.py</code> files or a vitest/jest dependency.")
                     + "</section>")

    # Complexity
    if lizard:
        ccns = sorted(r["ccn"] for r in lizard)
        n = len(ccns)
        over = lambda k: sum(c > k for c in ccns)  # noqa: E731
        top = sorted(lizard, key=lambda r: r["ccn"], reverse=True)[:12]
        sev_for = lambda c: "High" if c > 50 else "Medium" if c > 25 else "Low" if c > 15 else "Info"  # noqa: E731
        rows = "".join(
            f'<tr><td class="n c-{sev_for(r["ccn"])}"><b>{r["ccn"]}</b></td><td><code>{escape(r["function"])}</code>'
            f'<div class="loc">{escape(r["file"])}:{r["start"]}</div></td><td class="n hide">{r["nloc"]}</td><td class="n hide">{r["params"]}</td></tr>'
            for r in top)
        dist = "".join(f'<tr><td>over {k}</td><td class="n">{over(k)}</td><td class="n">{over(k) / n:.1%}</td></tr>' for k in (10, 15, 25, 50))
        parts.append(f'<section><header><div><h2>Cyclomatic complexity</h2><div class="sub">lizard, per function. '
                     f'{n:,} functions, average {statistics.mean(ccns):.1f}, median {ccns[n // 2]}, max {ccns[-1]}. '
                     f'Above 15 a function is hard to test exhaustively.</div></div></header>'
                     f'<div class="grid2"><table><thead><tr><th class="n">CCN</th><th>Function</th><th class="n hide">Lines</th><th class="n hide">Params</th></tr></thead>'
                     f'<tbody>{rows}</tbody></table><table><thead><tr><th>CCN</th><th class="n">Functions</th><th class="n">Share</th></tr></thead>'
                     f'<tbody>{dist}</tbody></table></div></section>')

    # DORA
    if dl and (dl["deploys"] or dl["prs"]):
        cells = [
            ("Deployment frequency", f'{dl["per_week"]:.1f}/week', f'{dl["deploys"]} production deployments', dora_level("per_week", dl["per_week"])),
            ("Lead time for changes", f'{dl["lead_hours"]:.0f} h' if dl["lead_hours"] is not None else "-", f'median of {dl["prs"]} PRs, first commit to deploy', dora_level("lead_hours", dl["lead_hours"])),
            ("Change failure rate", f'{dl["cfr"]:.0%}' if dl["cfr"] is not None else "-", "deployments followed by an incident", dora_level("cfr", dl["cfr"])),
            ("Time to restore", f'{dl["restore_hours"]:.1f} h' if dl["restore_hours"] is not None else "no incidents", "median incident open to close", dora_level("restore_hours", dl["restore_hours"])),
        ]
        body = '<div class="dora">' + "".join(
            f'<div><div class="sub">{t}</div><div class="v">{v}</div>{lvl}<div class="sub">{d}</div></div>' for t, v, d, lvl in cells) + "</div>"
    else:
        body = unavailable("DevLake", dl_err, f"Add <code>GITHUB_TOKEN</code> to <code>.env</code> and run <code>python devlake.py owner/{escape(product)}</code>.")
    parts.append('<section><header><div><h2>Delivery (DORA)</h2><div class="sub">Last 90 days, from DevLake. '
                 'Levels follow the DORA report\'s elite / high / medium / low ranges.</div></div></header>' + body + "</section>")

    parts.append(all_findings(findings, sq))

    # Scan run
    if run:
        rows = "".join(
            f'<tr><td>{escape(t["name"])}</td><td class="{"ok" if t["ok"] else "bad"}">{"ok" if t["ok"] else "failed"}</td>'
            f'<td class="n">{t["seconds"]:.0f}s</td><td class="loc">{escape(t.get("result") or t.get("note") or "")}</td></tr>'
            for t in run.get("tools", []))
        parts.append(f'<section><header><div><h2>Last scan</h2><div class="sub">{len(run.get("tools", []))} scanners, '
                     f'raw output in <code>{escape(str(run_dir))}</code>.</div></div></header>'
                     f'<div class="tw"><table><thead><tr><th>Tool</th><th>Status</th><th class="n">Time</th><th>Result</th></tr></thead><tbody>{rows}</tbody></table></div></section>')

    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{escape(product)} report</title><style>{CSS}</style></head><body><main>{"".join(parts)}'
            f'<footer>Generated by shieldyard/report.py. Numbers are live from each tool at build time.</footer></main></body></html>')


def build(product: str) -> Path:
    env = load_env()
    run_dir, run = last_run(product)
    branch = run.get("branch", "")
    data = {
        "dojo": safely(dojo, env, product, branch),
        "sboms": sbom_inventory(run_dir, run),
        "sonar": safely(sonar, env, product),
        "dora": safely(dora, product),
        "run": (run_dir, run),
        "lizard": complexity_rows(run_dir),
        "tests": safely(test_suites, run_dir, run)[0] or [],
    }

    base = ROOT / "reports" / slug(product)
    base.mkdir(parents=True, exist_ok=True)
    hist_path = base / "history.json"
    history = json.loads(hist_path.read_text(encoding="utf-8")) if hist_path.exists() else []
    dd = data["dojo"][0]
    if dd:
        findings = dd["findings"]
        entry = {"at": datetime.now().isoformat(timespec="seconds"), "commit": run.get("commit", "")[:12],
                 "open": len(findings), "crit_high": sum(f["severity"] in ("Critical", "High") for f in findings)}
        lines = sum(s["lines"] for s in data["tests"])
        if lines:
            entry["coverage"] = round(sum(s["covered"] for s in data["tests"]) / lines, 4)
        if not history or history[-1].get("commit") != entry["commit"] or history[-1]["open"] != entry["open"]:
            history.append(entry)
            hist_path.write_text(json.dumps(history, indent=1), encoding="utf-8")
    data["history"] = history

    page = render(product, data)
    out = base / "report.html"
    out.write_text(page, encoding="utf-8")
    if run_dir:
        (run_dir / "report.html").write_text(page, encoding="utf-8")
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("product", help="the name scan.py used (the repo folder name by default)")
    args = parser.parse_args()
    print(f"[ok] {build(args.product)}")


if __name__ == "__main__":
    main()
