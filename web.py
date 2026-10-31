"""Scan exposed sites from the outside, the way an attacker first sees them.

    python web.py https://app.example.com --product my-repo
    python web.py example.com --subdomains                # also every subdomain subfinder knows
    python web.py http://localhost:8080 --no-upload       # a local app (reached as host.docker.internal)
    python web.py example.com --active                    # attacks too: only on what you're allowed to test
    python web.py https://app.example.com --auth --auth-check /api/auth/me --openapi openapi.json
                                                          # logged in, plus a ZAP + Schemathesis API scan

Only scan sites you own or have written permission to test.

What runs, all in pinned containers:

    discovery    subfinder (passive subdomains, --subdomains), httpx (which hosts answer
                 on which ports, titles, servers, technologies), katana (crawls each
                 site, JavaScript included, for every URL it links to), wafw00f (whether a
                 WAF/CDN sits in front, so a filtered scan isn't mistaken for a clean app)
    vulns        nuclei (known CVEs, exposed panels/files/.git/.env, misconfigurations,
                 subdomain takeovers, DNS records like SPF/DMARC); nuclei again over
                 katana's URLs for API keys and tokens left in pages and scripts
    web app      OWASP ZAP baseline: spiders and reports passively (headers, cookies, CSP,
                 information leaks); --active runs ZAP's full active scan instead. Nikto:
                 web-server misconfigurations, dangerous/default files, outdated software
    API          with --openapi: a ZAP API scan and Schemathesis (property-based fuzzing
                 from the spec -- unhandled 500s, off-spec responses, and logged in, auth
                 gaps); both touch GET operations only unless --active
    TLS          testssl.sh (protocols, ciphers, certificate, known TLS vulnerabilities)
    DNS          dnsx: the records each host publishes, and whether the domain has SPF and
                 DMARC (their absence lets anyone spoof mail from it); lookups only
    ports        nmap: open ports and service versions on the top 1000 TCP ports, with its
                 default (safe) NSE scripts
    lookalikes   dnstwist: registered domains one typo away (phishing, brand abuse);
                 DNS lookups only, the site itself isn't contacted
    --active     also feroxbuster (hidden paths and files from a wordlist) and nuclei's
                 DAST templates (XSS, SQLi, SSRF...) on every crawled URL with parameters;
                 Nikto's injection tests, and nmap over all 65535 ports with the vuln scripts

By default nothing is attacked: nuclei leaves out its intrusive, fuzzing, brute-force
and DoS templates and ZAP only looks at what the spider fetched. --active lifts that
(DoS stays out) and asks for confirmation first.

Findings go to DefectDojo with reimport, into the product given by --product (the
repo's, so report.py shows code and site together) or one named after the site,
in an engagement "exposure <target>" per target. Raw output lands in
reports/<product>/web/<timestamp>/.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import shlex
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import report
from common import DOJO_URL, ROOT, HttpError, load_env, request
from scan import CACHES, PYTHON, Result, Tool, last_timings, run, run_parallel, slug, upload_dojo, upload_parallel

NUCLEI = "projectdiscovery/nuclei:v3.11.1"
HTTPX = "projectdiscovery/httpx:v1.12.0"
SUBFINDER = "projectdiscovery/subfinder:v2.17.0"
KATANA = "projectdiscovery/katana:v1.8.0"
NMAP = "instrumentisto/nmap:7.98"
TESTSSL = "drwetter/testssl.sh:3.2"
ZAP = "zaproxy/zap-stable:2.17.0"
SCHEMATHESIS = "schemathesis/schemathesis:4.32.7"
# The author's image, with SecLists' raft-medium-directories as its wordlist.
FEROXBUSTER = "epi052/feroxbuster:2.13.0"
WORDLIST = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
# Pinned by digest: the official Nikto image ships only rolling (master) and dated tags.
NIKTO = "ghcr.io/sullo/nikto@sha256:0bb37022ebfadc38d6a9a2755c03bfd1f9e079e01e8946fe548153d9ba0c2012"  # 2.5.0
DNSX = "projectdiscovery/dnsx:v1.2.2"

# Crawled URLs worth nothing to a scanner: images, fonts, styles.
STATIC = "png,jpg,jpeg,gif,svg,webp,ico,woff,woff2,ttf,eot,otf,css,mp4,webm,mp3,pdf"
# Paths feroxbuster finds that are worth a look beyond "it exists".
SENSITIVE = re.compile(r"(\.git|\.env|\.svn|\.hg|\.ds_store|backup|\.bak|\.old|\.sql|\.zip|\.tar|dump|config|"
                       r"admin|debug|actuator|phpinfo|server-status|\.htpasswd|swagger|graphql|console)", re.I)

# How long after a release --after-release waits, so ArgoCD has rolled it out.
RELEASE_SETTLE = timedelta(minutes=30)
# Templates kept between runs; nuclei updates them once per run, before scanning.
NUCLEI_HOME = "scaner-nuclei:/root"
# Ports httpx probes for web servers, besides the defaults.
WEB_PORTS = "http:80,8000,8080,8888,https:443,8443,9443"
# Never, not even with --active: they can take a site down.
ALWAYS_EXCLUDED = ["dos"]
# Left out unless --active: they send attacks, guess passwords or fuzz parameters.
INTRUSIVE = ["intrusive", "fuzz", "fuzzing", "bruteforce", "brute-force", "default-login"]
# Nikto test categories to leave out (its -Tuning, where a leading "x" means "exclude").
# 6 is denial of service, never run; 0, 4, 8 and 9 are file-upload, XSS/injection,
# command-execution and SQL-injection tests, kept out unless --active.
NIKTO_TUNING = {"passive": "x04689", "active": "x6"}


def parse_target(target: str) -> tuple[str, str]:
    """(host, what httpx should probe) for a domain or URL. localhost becomes the
    Docker host, since the scanners run in containers."""
    parts = urlsplit(target if "://" in target else f"//{target}")
    host = parts.hostname or target
    if host in ("localhost", "127.0.0.1", "::1"):
        host = "host.docker.internal"
    netloc = host + (f":{parts.port}" if parts.port else "")
    probe = f"{parts.scheme}://{netloc}{parts.path}" if parts.scheme else netloc
    return host, probe


def discover(target: str, subdomains: bool, out: Path, rate: int, auth: str | None = None) -> list[dict]:
    """Every live web endpoint of a target: one httpx JSON record per URL."""
    host, probe = parse_target(target)
    s = slug(host)
    candidates = [probe]
    if subdomains and host != "host.docker.internal":
        r = run(Tool(f"subfinder {host}", SUBFINDER, ["-d", host, "-silent", "-all", "-o", f"/out/subdomains-{s}.txt"],
                     f"subdomains-{s}.txt"), None, None, out)
        print(f"    {'ok ' if r.ok else 'ERR'} {r.tool.name:<40} {r.seconds:6.0f}s {r.note}", flush=True)
        if r.ok:
            candidates += sorted({line.strip() for line in (out / r.tool.output).read_text().splitlines() if line.strip()})
    (out / f"hosts-{s}.txt").write_text("\n".join(candidates) + "\n", encoding="utf-8")

    # A bare host is probed on the usual web ports; a URL exactly as given.
    ports = [] if "://" in probe and len(candidates) == 1 else ["-ports", WEB_PORTS]
    r = run(Tool(f"httpx {host}", HTTPX, ["-l", f"/out/hosts-{s}.txt", "-json", "-o", f"/out/httpx-{s}.json", "-silent",
                                          "-nc", "-sc", "-title", "-server", "-td", "-ip", "-fr", *ports],
                 f"httpx-{s}.json"), None, None, out)
    print(f"    {'ok ' if r.ok else 'ERR'} {r.tool.name:<40} {r.seconds:6.0f}s {r.note}", flush=True)
    if not r.ok:
        return []
    records = [json.loads(line) for line in (out / r.tool.output).read_text(encoding="utf-8").splitlines() if line.strip()]
    seen, live = set(), []
    for rec in records:  # the same site on :80 and :443 after redirects counts once
        key = rec.get("final_url") or rec["url"]
        if key not in seen:
            seen.add(key)
            live.append(rec)
    if not live:
        return live

    # Every URL the sites link to, in pages and in their JavaScript, staying on the
    # target's domain (its exact host when logged in: the session goes nowhere else).
    # Plain browsing, so it runs in passive mode too.
    (out / f"live-{s}.txt").write_text("\n".join(rec["url"] for rec in live) + "\n", encoding="utf-8")
    session = ["-H", auth, "-fs", "fqdn"] if auth else []
    r = run(Tool(f"katana {host}", KATANA, ["-list", f"/out/live-{s}.txt", "-d", "3", "-jc", "-kf", "all", "-ct", "5m",
                                            "-rl", str(rate), "-ef", STATIC, "-duc", "-silent", "-nc", *session,
                                            "-o", f"/out/katana-{s}.txt"],
                 f"katana-{s}.txt"), None, None, out)
    crawled = len((out / r.tool.output).read_text(encoding="utf-8").splitlines()) if r.ok else 0
    print(f"    {'ok ' if r.ok else 'ERR'} {r.tool.name:<40} {r.seconds:6.0f}s {r.note or f'{crawled} URLs'}", flush=True)
    return live


def plan(target: str, live: list[dict], active: bool, out: Path, rate: int, auth: str | None = None,
         openapi: dict | None = None) -> list[Tool]:
    """auth: a header line ("Cookie: session=...") every web scanner sends, so they see the
    app as a logged-in user. Those results get their own DefectDojo tests ("... as user"),
    so a run without it doesn't close them."""
    excluded = ",".join(ALWAYS_EXCLUDED + ([] if active else INTRUSIVE))
    as_user = " as user" if auth else ""
    header = f"-H {shlex.quote(auth)} " if auth else ""
    tools = []
    for rec in live:
        url = rec["url"]
        s = slug(url.split("://", 1)[1]) + ("-user" if auth else "")
        host, port = rec.get("host") or urlsplit(url).hostname, urlsplit(url).port or (443 if url.startswith("https") else 80)
        label = url.split("://", 1)[1]
        # ZAP adds the header itself to every request to that host, whatever its spider does.
        zap_auth = {"ZAP_AUTH_HEADER": auth.split(":", 1)[0].strip(), "ZAP_AUTH_HEADER_VALUE": auth.split(":", 1)[1].strip(),
                    "ZAP_AUTH_HEADER_SITE": host} if auth else {}
        # -ni: no interactsh, so nothing about the target is sent to projectdiscovery's OAST servers.
        tools.append(Tool(f"nuclei {label}{as_user}", NUCLEI, ["-c", f"""
            nuclei -u '{url}' {header}-duc -ni -silent -nc -jsonl -o /out/nuclei-{s}.jsonl -etags {excluded} -rl {rate} -c 50 -mhe 100 -timeout 15
            [ -s /out/nuclei-{s}.jsonl ] || echo '[]' > /out/nuclei-{s}.jsonl  # nothing found still reimports, so fixed findings close
        """], f"nuclei-{s}.jsonl", "Nuclei Scan", entrypoint="sh", volumes=[NUCLEI_HOME], title=f"nuclei ({label}){as_user}"))

        zap = "zap-full-scan.py -m 5" if active else "zap-baseline.py -m 2"
        tools.append(Tool(f"zap {label}{as_user}", ZAP, ["sh", "-c", f"""
            {zap} -t '{url}' -x zap-{s}.xml -I || test -s /zap/wrk/zap-{s}.xml
        """], f"zap-{s}.xml", "ZAP Scan", volumes=[f"{out}:/zap/wrk"], env=zap_auth, title=f"zap ({label}){as_user}"))

        if openapi is not None and rec is live[0]:
            spec = api_spec(openapi, url, active)
            (out / f"openapi-{s}.json").write_text(json.dumps(spec), encoding="utf-8")
            ops = sum(len([m for m in p if m in HTTP_METHODS]) for p in spec["paths"].values())
            # -S: requests every operation and rules on the answers, but sends no attacks.
            tools.append(Tool(f"zap api {label}{as_user} ({ops} ops)", ZAP, ["sh", "-c", f"""
                zap-api-scan.py -t /zap/wrk/openapi-{s}.json -f openapi -O '{url}' -x zapapi-{s}.xml -I {'' if active else '-S'} \\
                  || test -s /zap/wrk/zapapi-{s}.xml
            """], f"zapapi-{s}.xml", "ZAP Scan", volumes=[f"{out}:/zap/wrk"], env=zap_auth,
                title=f"zap api ({label}){as_user}"))

            # Property-based fuzzing: generates requests from each operation's schema (valid,
            # invalid and boundary values) and checks the answers. Finds unhandled 500s,
            # responses that don't match the spec, and -- logged in -- auth gaps. It reads the
            # same filtered spec as ZAP, so in passive mode it only touches GET operations.
            phases = "examples,fuzzing,stateful" if active else "examples,fuzzing"
            max_time = 900 if active else 600
            tools.append(Tool(f"schemathesis {label}{as_user} ({ops} ops)", SCHEMATHESIS, ["-c", f"""
                schemathesis run /out/openapi-{s}.json -u '{url}' {header}-c all -m all --phases {phases} \\
                  -n 20 -w 2 --rate-limit {rate}/s --request-timeout 15 --max-time {max_time} --max-failures 300 \\
                  --suppress-health-check all --no-color \\
                  --report junit --report-junit-path /out/schemathesis-{s}.xml || test -s /out/schemathesis-{s}.xml
                [ -s /out/schemathesis-{s}.xml ] || echo '<testsuites tests="0"></testsuites>' > /out/schemathesis-{s}.xml
            """], f"schemathesis-{s}.xml", entrypoint="sh", title=f"schemathesis ({label}){as_user}",
                convert=schemathesis_findings))

        if url.startswith("https://") and not auth:  # the same TLS logged in or not
            tools.append(Tool(f"testssl {label}", TESTSSL,
                              ["--quiet", "--color", "0", "--warnings", "off", "--openssl-timeout", "10",
                               "--csvfile", f"/out/testssl-{s}.csv", f"{host}:{port}"],
                              f"testssl-{s}.csv", "Testssl Scan", title=f"testssl ({label})", convert=testssl_problems))

        # Nikto and wafw00f don't take a session header cleanly, and neither gains much from
        # one, so like testssl they run once per site, unauthenticated.
        if not auth:
            # Nikto: web-server misconfigurations, dangerous and default files, outdated
            # software, insecure headers. Writes a <niktoscans> XML the "Nikto Scan" parser reads.
            tuning = NIKTO_TUNING["active"] if active else NIKTO_TUNING["passive"]
            tools.append(Tool(f"nikto {label}", NIKTO, ["-c", f"""
                /opt/nikto/nikto.pl -h '{url}' -Format xml -output /out/nikto-{s}.xml \\
                  -Tuning {tuning} -maxtime {900 if active else 600} -timeout 10 -nointeractive -ask no || true
                [ -s /out/nikto-{s}.xml ] || : > /out/nikto-{s}.xml
            """], f"nikto-{s}.xml", "Nikto Scan", entrypoint="sh", title=f"nikto ({label})"))

            # wafw00f: is there a WAF or CDN in front? A clean scan through one isn't proof the
            # app is clean, only that the filter answered first; recorded as Info for context.
            tools.append(Tool(f"wafw00f {label}", PYTHON, ["sh", "-c", f"""
                pip install -q --root-user-action=ignore wafw00f==2.4.2
                wafw00f '{url}' -a -f json -o /out/wafw00f-{s}.json || true
                [ -s /out/wafw00f-{s}.json ] || echo '[]' > /out/wafw00f-{s}.json
            """], f"wafw00f-{s}.json", env=CACHES, title=f"wafw00f ({label})", convert=wafw00f_findings))

        if active:
            # --auto-bail stops when the site starts failing; --time-limit caps a huge tree.
            tools.append(Tool(f"feroxbuster {label}{as_user}", FEROXBUSTER, ["-c", f"""
                feroxbuster -u '{url}' {header}-w {WORDLIST} --json -o /out/ferox-{s}.json --silent --no-state \\
                  -d 2 -t 20 --rate-limit {rate} --time-limit 10m --auto-bail -k -C 404 >/dev/null
                touch /out/ferox-{s}.json
            """], f"ferox-{s}.json", entrypoint="sh", title=f"feroxbuster ({label}){as_user}",
                convert=ferox_findings))

    host, _ = parse_target(target)
    s = slug(host)
    crawled = out / f"katana-{s}.txt"
    s += "-user" if auth else ""
    if crawled.exists() and crawled.stat().st_size:
        # Token templates read the body of whatever URL they get, so over the crawl they find
        # keys hardcoded in JavaScript bundles and pages, not just on the home page.
        dast = (f"nuclei -l /out/katana-{slug(host)}.txt {header}-duc -ni -silent -nc -jsonl -o /tmp/dast.jsonl -dast -etags dos -rl {rate} -c 50 -mhe 100 -timeout 15\n"
                f"            cat /tmp/dast.jsonl >> /out/nuclei-crawl-{s}.jsonl 2>/dev/null") if active else ""
        tools.append(Tool(f"nuclei crawl {host}{as_user}", NUCLEI, ["-c", f"""
            nuclei -l /out/katana-{slug(host)}.txt {header}-duc -ni -silent -nc -jsonl -o /out/nuclei-crawl-{s}.jsonl -tags token,tokens -etags dos -rl {rate} -c 50 -mhe 100 -timeout 15
            {dast}
            [ -s /out/nuclei-crawl-{s}.jsonl ] || echo '[]' > /out/nuclei-crawl-{s}.jsonl  # nothing found still reimports, so fixed findings close
        """], f"nuclei-crawl-{s}.jsonl", "Nuclei Scan", entrypoint="sh", volumes=[NUCLEI_HOME],
            title=f"nuclei crawl ({host}){as_user}"))

    if auth:  # lookalike domains and open ports don't depend on being logged in
        return tools

    domain = registrable(host)
    if "." in domain and host != "host.docker.internal" and not is_ip(host):
        tools.append(Tool(f"dnstwist {domain}", PYTHON, ["sh", "-c", f"""
            pip install -q --root-user-action=ignore dnstwist==20250130 dnspython==2.8.0
            dnstwist --registered --format json {domain} > /out/dnstwist-{slug(domain)}.json
        """], f"dnstwist-{slug(domain)}.json", env=CACHES, title=f"dnstwist ({domain})",
            convert=lambda path, domain=domain: dnstwist_findings(path, domain)))

    # DNS footprint and email spoofing protection: the records each live host publishes, and
    # whether the domain has SPF and DMARC (without them anyone can forge mail from it).
    # DNS lookups only, the site itself isn't contacted.
    if host != "host.docker.internal" and not is_ip(host):
        names = sorted({urlsplit(r["url"]).hostname for r in live if urlsplit(r["url"]).hostname}
                       | {domain, f"_dmarc.{domain}"})
        (out / f"dnsx-hosts-{slug(host)}.txt").write_text("\n".join(names) + "\n", encoding="utf-8")
        tools.append(Tool(f"dnsx {domain}", DNSX,
                          ["-l", f"/out/dnsx-hosts-{slug(host)}.txt", "-json", "-a", "-aaaa", "-cname",
                           "-mx", "-ns", "-txt", "-silent", "-o", f"/out/dnsx-{slug(host)}.json"],
                          f"dnsx-{slug(host)}.json", title=f"dnsx ({domain})",
                          convert=lambda path, domain=domain: dnsx_findings(path, domain)))

    # Ports per host, not per URL: one host often serves several of them. Not for local
    # apps: host.docker.internal is this whole machine, not the app.
    # The address comes from httpx, which resolves through public DNS: the system resolver
    # may answer with a LAN address (split DNS at home or in an office), and the internet
    # never sees that one.
    addresses = {}
    for rec in live:
        name = urlsplit(rec["url"]).hostname
        addresses.setdefault(name, (rec.get("a") or [rec.get("host") or name])[0])
    # Default NSE scripts always (safe service/version probes, banners); the full TCP range
    # and the "vuln" script category only with --active, since both are slow and noisier.
    # The dos category is never in either, so nothing here can take a host down.
    scripts = "default,vuln" if active else "default"
    ports = ["-p-"] if active else ["--top-ports", "1000"]
    for host in sorted(set(addresses) - {"host.docker.internal"}):
        s = slug(host)
        tools.append(Tool(f"nmap {host} ({addresses[host]})", NMAP,
                          ["-sT", "-sV", "-Pn", *ports, "-T4", "--open", "--script", scripts,
                           "--script-timeout", "90s", "-oX", f"/out/nmap-{s}.xml", addresses[host]],
                          f"nmap-{s}.xml", "Nmap Scan", title=f"nmap ({host})"))
    return tools


HTTP_METHODS = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}
# Operations a scan must not call: they'd end the session or start a login elsewhere.
AUTH_FLOW = re.compile(r"/(login|logout|signin|signout|callback|oauth)", re.I)


def api_spec(spec: dict, base_url: str, active: bool) -> dict:
    """The OpenAPI spec as ZAP should get it. ZAP's import calls every operation once, so
    in passive mode only GETs stay in: on a live site, POST/PUT/PATCH/DELETE with made-up
    values would create, change and delete real data. Login/logout routes always go."""
    keep = HTTP_METHODS if active else {"get", "head", "options"}
    paths = {}
    for path, item in spec.get("paths", {}).items():
        if AUTH_FLOW.search(path):
            continue
        ops = {k: v for k, v in item.items() if k not in HTTP_METHODS or k in keep}
        if any(k in HTTP_METHODS for k in ops):
            paths[path] = ops
    return {**spec, "paths": paths, "servers": [{"url": base_url.rstrip("/")}]}


def load_spec(source: str, auth: str | None) -> dict:
    if "://" in source:
        headers = dict([[x.strip() for x in auth.split(":", 1)]]) if auth else {}
        return request("GET", source, headers=headers)
    return json.loads(Path(source).read_text(encoding="utf-8"))


def check_session(base_url: str, path: str, auth: str) -> None:
    """Stops before scanning if the session doesn't work: an expired cookie would
    otherwise make the authenticated tests look clean."""
    name, value = (x.strip() for x in auth.split(":", 1))
    url = base_url.rstrip("/") + "/" + path.lstrip("/")

    def fetch(headers: dict) -> str:
        try:
            return json.dumps(request("GET", url, headers=headers, timeout=30), sort_keys=True)
        except HttpError as e:
            return f"HTTP {e.status}"

    # "Who am I" endpoints often answer 200 to anyone, so the proof is a different answer.
    if fetch({name: value}) == fetch({}) or fetch({name: value}).startswith("HTTP "):
        raise SystemExit(f"[!!] {url} answers the same with and without WEB_AUTH_HEADER: the session "
                         "isn't accepted (expired?). Log in again and update .env")
    print(f"[ok] logged in: {url} answers differently with the session")


def new_release(env: dict[str, str], repo: str, product: str) -> str | None:
    """The latest release's tag if it hasn't been scanned yet and has had time to deploy."""
    headers = {"Accept": "application/vnd.github+json"}
    if env.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {env['GITHUB_TOKEN']}"
    try:
        latest = request("GET", f"https://api.github.com/repos/{repo}/releases/latest", headers=headers)
    except HttpError as e:
        raise SystemExit(f"[!!] can't read {repo}'s releases: {e}") from None
    tag = latest["tag_name"]
    seen = ROOT / "reports" / slug(product) / "web" / "last-release.txt"
    if seen.exists() and seen.read_text(encoding="utf-8").strip() == tag:
        print(f"[ok] {repo} {tag} already scanned")
        return None
    age = datetime.now(timezone.utc) - datetime.fromisoformat(latest["published_at"].replace("Z", "+00:00"))
    if age < RELEASE_SETTLE:
        print(f"[..] {repo} {tag} is {age.seconds // 60} min old; scanning once it's deployed (next run)")
        return None
    print(f"[*] new release {repo} {tag}")
    return tag


def testssl_problems(path: Path) -> Path:
    """testssl's CSV without its OK and INFO rows (about 160 per site, every check it
    passed or merely describes) and its own WARN notes about the scanning machine."""
    with path.open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    out = path.with_name(path.stem + "-problems.csv")
    with out.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]) if rows else ["id"], quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(r for r in rows if r.get("severity") in ("LOW", "MEDIUM", "HIGH", "CRITICAL"))
    return out


def registrable(host: str) -> str:
    """The domain someone would typosquat: app.example.com -> example.com, shop.example.co.uk
    -> example.co.uk. A heuristic, not the public suffix list."""
    labels = host.split(".")
    keep = 3 if len(labels) > 2 and len(labels[-1]) == 2 and labels[-2] in ("co", "com", "org", "net", "ac", "gov", "edu") else 2
    return ".".join(labels[-keep:])


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def ferox_findings(path: Path) -> Path:
    """feroxbuster's JSON lines as DefectDojo generic findings: every path that answered,
    Info unless its name suggests something that shouldn't be public."""
    findings, seen = [], set()
    for line in path.read_text(encoding="utf-8").splitlines():
        hit = json.loads(line) if line.strip() else {}
        if hit.get("type") != "response" or hit.get("wildcard") or hit["url"] in seen:
            continue
        seen.add(hit["url"])
        status = hit.get("status", 0)
        if status not in (200, 204, 301, 302, 307, 308, 401, 403):
            continue
        sensitive = bool(SENSITIVE.search(urlsplit(hit["url"]).path))
        # Readable and sensitive-sounding is the one that matters; behind 401/403 it's only a hint.
        severity = ("Medium" if status in (200, 204) else "Low") if sensitive else "Info"
        findings.append({
            "title": f"{'Sensitive-looking path' if sensitive else 'Discovered path'}: {urlsplit(hit['url']).path} ({status})",
            "severity": severity,
            "description": f"`{hit['url']}` answered {status} ({hit.get('content_length', 0)} bytes) to a wordlist guess. "
                           + ("Its name suggests configuration, backups, source control or an admin/debug surface: "
                              "check it isn't meant to be private." if sensitive else
                              "Not linked from the site, but reachable."),
            "static_finding": False,
            "dynamic_finding": True,
            "unique_id_from_tool": f"feroxbuster:{hit['url']}",
        })
    out = path.with_name(path.stem + "-findings.json")
    out.write_text(json.dumps({"findings": findings}, indent=1), encoding="utf-8")
    return out


def dnstwist_findings(path: Path, domain: str) -> Path:
    """dnstwist's registered lookalikes as DefectDojo generic findings. One that can receive
    mail (has MX) is the phishing risk, so it ranks higher."""
    findings = []
    for d in json.loads(path.read_text(encoding="utf-8") or "[]"):
        if d.get("fuzzer") == "*original" or d["domain"] == domain:
            continue
        records = "\n".join(f"- {kind}: {', '.join(d[key])}" for kind, key in
                            (("A", "dns_a"), ("AAAA", "dns_aaaa"), ("MX", "dns_mx"), ("NS", "dns_ns")) if d.get(key))
        findings.append({
            "title": f"Lookalike domain registered: {d['domain']}",
            "severity": "Medium" if d.get("dns_mx") else "Low",
            "description": f"`{d['domain']}` is registered and one typo away from `{domain}` "
                           f"(dnstwist fuzzer: {d['fuzzer']}).\n\n{records}\n\n"
                           "It may be harmless (yours, or parked), or set up for phishing. If it isn't yours, "
                           "consider a takedown request or registering such variants defensively.",
            "static_finding": False,
            "dynamic_finding": True,
            "unique_id_from_tool": f"dnstwist:{d['domain']}",
        })
    out = path.with_name(path.stem + "-findings.json")
    out.write_text(json.dumps({"findings": findings}, indent=1), encoding="utf-8")
    return out


def wafw00f_findings(path: Path) -> Path:
    """wafw00f's JSON as DefectDojo generic findings, one Info per URL: which WAF/CDN is in
    front, or that none was detected. Context for the other scanners, not a problem in itself."""
    data = json.loads(path.read_text(encoding="utf-8") or "[]")
    findings = []
    for d in data if isinstance(data, list) else [data]:
        url = d.get("url", "")
        if d.get("detected"):
            waf = d.get("firewall") or "a WAF/CDN"
            vendor = f" ({d['manufacturer']})" if d.get("manufacturer") and d.get("manufacturer") != d.get("firewall") else ""
            title, detail = f"WAF detected: {waf}{vendor}", (
                f"`{url}` sits behind {waf}{vendor}. Scanner results can be filtered or rate-limited "
                "by it, so a clean scan through a WAF isn't proof the application itself is clean.")
        else:
            title, detail = "No WAF detected", (
                f"`{url}` doesn't appear to sit behind a WAF or CDN, so the application's own input "
                "handling is the only line of defence in front of it.")
        findings.append({
            "title": title, "severity": "Info", "description": detail,
            "static_finding": False, "dynamic_finding": True,
            "unique_id_from_tool": f"wafw00f:{url}",
        })
    out = path.with_name(path.stem + "-findings.json")
    out.write_text(json.dumps({"findings": findings}, indent=1), encoding="utf-8")
    return out


def dnsx_findings(path: Path, domain: str) -> Path:
    """dnsx's JSON as DefectDojo generic findings: the public DNS records of each host (Info),
    and -- for the domain itself -- a Low finding when it publishes no SPF or no DMARC, since
    their absence lets anyone spoof mail from it."""
    by_host = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rec = json.loads(line)
            if rec.get("host"):
                by_host[rec["host"]] = rec
    clean = lambda values: [v for v in (values or []) if v and v.strip()]  # noqa: E731
    findings = []
    for host, rec in sorted(by_host.items()):
        if host.startswith("_dmarc."):
            continue
        parts = [f"- {label}: " + ", ".join(clean(rec.get(key))[:8])
                 for label, key in (("A", "a"), ("AAAA", "aaaa"), ("CNAME", "cname"),
                                    ("MX", "mx"), ("NS", "ns"), ("TXT", "txt")) if clean(rec.get(key))]
        if not parts:
            continue
        findings.append({
            "title": f"DNS records: {host}",
            "severity": "Info",
            "description": f"Public DNS footprint of `{host}`:\n\n" + "\n".join(parts),
            "static_finding": False, "dynamic_finding": True,
            "unique_id_from_tool": f"dnsx:records:{host}",
        })
    if domain in by_host:  # only judge SPF/DMARC once the domain itself resolved
        if not any(t.lower().startswith("v=spf1") for t in clean(by_host[domain].get("txt"))):
            findings.append({
                "title": f"No SPF record: {domain}",
                "severity": "Low",
                "description": f"`{domain}` publishes no SPF TXT record (`v=spf1 ...`). Without one, a "
                               "receiver can't tell which servers may send mail as this domain, which makes "
                               "spoofing and phishing in its name easier.",
                "static_finding": False, "dynamic_finding": True,
                "unique_id_from_tool": f"dnsx:spf:{domain}",
            })
        if not any("v=dmarc1" in t.lower() for t in clean(by_host.get(f"_dmarc.{domain}", {}).get("txt"))):
            findings.append({
                "title": f"No DMARC record: {domain}",
                "severity": "Low",
                "description": f"`_dmarc.{domain}` publishes no DMARC policy (`v=DMARC1 ...`). Without one, a "
                               "receiver has no instruction to reject or quarantine spoofed mail from this "
                               "domain, so SPF and DKIM failures are ignored.",
                "static_finding": False, "dynamic_finding": True,
                "unique_id_from_tool": f"dnsx:dmarc:{domain}",
            })
    out = path.with_name(path.stem + "-findings.json")
    out.write_text(json.dumps({"findings": findings}, indent=1), encoding="utf-8")
    return out


# Schemathesis' own check titles that mean an auth gap: the API answered when it shouldn't have.
SCHEMA_AUTHZ = re.compile(r"without auth|ignored auth|authoriz|unauthenti|not require auth", re.I)


def schemathesis_findings(path: Path) -> Path:
    """Schemathesis' JUnit XML as DefectDojo generic findings: one per API operation that failed
    a check. A 5xx answer is an unhandled crash (Medium); an endpoint that answered without the
    credentials it should demand is an auth gap (High); an undocumented status or content-type is
    only documentation drift (Info); anything else (off-spec responses, rejected valid input) is Low."""
    findings = []
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        root = None
    for case in (root.iter("testcase") if root is not None else []):
        problems = case.findall("failure") + case.findall("error")
        if not problems:
            continue
        op = case.get("name", "")  # e.g. "GET /api/characters/{id}"
        text = "\n\n".join((p.text or "").strip() for p in problems)
        codes = sorted({c.strip() for p in problems for c in (p.get("message") or "").split(",") if c.strip()})
        titles = sorted(set(re.findall(r"- (ST\d+ [^\n]+)", text))) or codes
        if SCHEMA_AUTHZ.search(text):
            severity = "High"
        elif re.search(r"server error|Received:\s*5\d\d", text, re.I):
            severity = "Medium"
        elif codes and set(codes) <= {"ST103", "ST105"}:  # undocumented status / content-type only
            severity = "Info"
        else:
            severity = "Low"
        findings.append({
            "title": f"API fuzzing {op}: {'; '.join(titles)[:150]}",
            "severity": severity,
            "description": f"Schemathesis generated requests for `{op}` from the OpenAPI spec and the "
                           f"answers failed {len(codes) or 1} check(s): {', '.join(codes) or 'see below'}.\n\n"
                           f"```\n{text[:6000]}\n```",
            "static_finding": False,
            "dynamic_finding": True,
            "unique_id_from_tool": f"schemathesis:{op}:{','.join(codes)}",
        })
    out = path.with_name(path.stem + "-findings.json")
    out.write_text(json.dumps({"findings": findings}, indent=1), encoding="utf-8")
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("targets", nargs="+", help="domains or URLs")
    parser.add_argument("--product", help="DefectDojo product, e.g. the repo's name (default: the first target's host)")
    parser.add_argument("--subdomains", action="store_true", help="also scan every subdomain subfinder finds")
    parser.add_argument("--active", action="store_true", help="active attacks: ZAP full scan, intrusive nuclei templates")
    parser.add_argument("--yes", action="store_true", help="don't ask before an --active scan")
    parser.add_argument("--no-upload", action="store_true", help="only write files under reports/")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 6, help="containers at once (default: CPU count)")
    # Sites behind Cloudflare and the like start dropping a scanner well before 50 req/s.
    parser.add_argument("--rate", type=int, default=100, help="requests per second per crawler/scanner (default 100)")
    parser.add_argument("--auth", action="store_true",
                        help="scan logged in, sending WEB_AUTH_HEADER from .env (e.g. 'Cookie: session=...')")
    parser.add_argument("--auth-check", metavar="PATH",
                        help="with --auth: a path that only answers 200 to a logged-in user, checked first")
    parser.add_argument("--openapi", metavar="FILE|URL",
                        help="OpenAPI spec of the first target's API, for a ZAP API scan and Schemathesis "
                             "fuzzing (GET operations only unless --active)")
    parser.add_argument("--after-release", metavar="OWNER/REPO",
                        help="scan only if this repo has a GitHub release not scanned yet (for a scheduled task)")
    args = parser.parse_args()

    env = load_env()
    upload = not args.no_upload
    if upload and not env.get("DD_API_TOKEN"):
        raise SystemExit("No DD_API_TOKEN in .env: run `python bootstrap.py` first, or pass --no-upload.")
    product = args.product or parse_target(args.targets[0])[0]
    auth = env.get("WEB_AUTH_HEADER") if args.auth else None
    if args.auth and (not auth or ":" not in auth):
        raise SystemExit("--auth needs WEB_AUTH_HEADER in .env, e.g. WEB_AUTH_HEADER=Cookie: session=...")
    openapi = load_spec(args.openapi, auth) if args.openapi else None
    release = new_release(env, args.after_release, product) if args.after_release else None
    if args.after_release and not release:
        return
    out = ROOT / "reports" / slug(product) / "web" / datetime.now().strftime("%Y%m%d-%H%M%S")
    (out / "logs").mkdir(parents=True)
    print(f"[*] {product}: {', '.join(args.targets)} ({'ACTIVE' if args.active else 'passive'}"
          f"{', logged in' if auth else ''}); output in {out}")

    print("[*] discovery")
    subprocess.run(["docker", "run", "--rm", "-v", NUCLEI_HOME, NUCLEI, "-ut", "-silent"], capture_output=True, check=False)
    jobs: list[tuple[Tool, str]] = []  # (tool, engagement)
    endpoints = []
    with ThreadPoolExecutor(max_workers=len(args.targets)) as pool:  # targets are independent: discover them together
        discovered = list(pool.map(lambda t: discover(t, args.subdomains, out, args.rate, auth), args.targets))
    for target, live in zip(args.targets, discovered):
        if auth and args.auth_check and live:
            check_session(live[0]["url"], args.auth_check, auth)
        endpoints += [{"target": target, "url": r["url"], "status": r.get("status_code"), "title": r.get("title", ""),
                       "server": r.get("webserver", ""), "tech": r.get("tech") or []} for r in live]
        for rec in live:
            print(f"    {rec['url']:<50} {rec.get('status_code', '')} {', '.join(rec.get('tech') or [])[:60]}")
        jobs += [(t, f"exposure {target}") for t in plan(target, live, args.active, out, args.rate, auth,
                                                          openapi if target == args.targets[0] else None)]
        if live and not auth:
            # The inventory itself: one Info finding per exposed URL, closed when it stops answering.
            jobs.append((Tool("httpx", HTTPX, [], f"httpx-{slug(parse_target(target)[0])}.json", "httpx Scan",
                              title="httpx (exposed URLs)"), f"exposure {target}"))
    if not endpoints:
        raise SystemExit("[!!] nothing answered on any web port; check the targets (and that they resolve from Docker)")

    if args.active and not args.yes:
        answer = input(f"Active scan of {len(endpoints)} URLs sends real attacks. Authorized to test all of them? [y/N] ")
        if answer.strip().lower() != "y":
            raise SystemExit("cancelled")

    scans = [(t, e) for t, e in jobs if t.args]
    print(f"[*] running {len(scans)} scanners, {args.jobs} at a time")
    history = last_timings(ROOT / "reports" / slug(product) / "web")
    ran = run_parallel([t for t, _ in scans], args.jobs, None, None, out, history, width=40)
    results: list[tuple[Result, str]] = [(r, e) for r, (_, e) in zip(ran, scans)]
    results += [(Result(t, True, 0), e) for t, e in jobs if not t.args]  # httpx ran during discovery
    for r, _ in results:
        if r.ok and r.tool.convert:
            r.tool.output = r.tool.convert(out / r.tool.output).name
            r.tool.dojo_scan_type = r.tool.dojo_scan_type or "Generic Findings Import"

    if upload:
        print("[*] uploading")
        product_type = "Repositories" if args.product else "Sites"
        def push(item: tuple[Result, str]) -> None:
            r, engagement = item
            file = out / r.tool.output
            try:
                if file.stat().st_size == 0:
                    r.dojo = "nothing found"  # DefectDojo rejects empty files
                else:
                    r.dojo = upload_dojo(env, file, r.tool.dojo_scan_type, r.tool.test_title, product, engagement,
                                         product_type=product_type)
            except HttpError as e:
                r.dojo = f"upload failed: {e}"
            print(f"    {r.tool.name:<40} {r.dojo}", flush=True)

        upload_parallel([x for x in results if x[0].ok], push)

    lines = [
        f"# {product} exposure scan", "", f"{', '.join(args.targets)}, {'active' if args.active else 'passive'}, "
        f"{datetime.now():%Y-%m-%d %H:%M}", "",
        "| URL | status | title | technologies |", "|---|---:|---|---|",
        *[f"| {e['url']} | {e['status']} | {e['title']} | {', '.join(e['tech'])} |" for e in endpoints], "",
        "| tool | status | time | result |", "|---|---|---:|---|",
        *[f"| {r.tool.name} | {'ok' if r.ok else 'failed: ' + r.note} | {r.seconds:.0f}s | {r.dojo or r.note} |"
          for r, _ in results],
        "", f"- Findings: {DOJO_URL}", "",
    ]
    (out / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    (out / "run.json").write_text(json.dumps({
        "product": product, "targets": args.targets, "active": args.active,
        "finished": f"{datetime.now():%Y-%m-%d %H:%M}", "endpoints": endpoints,
        "tools": [{"name": r.tool.name, "ok": r.ok, "seconds": r.seconds, "note": r.note, "result": r.dojo}
                  for r, _ in results],
    }, indent=1), encoding="utf-8")
    if release:
        (ROOT / "reports" / slug(product) / "web" / "last-release.txt").write_text(release, encoding="utf-8")
    if upload:
        print(f"[ok] report: {report.build(product)}")
    else:
        print(f"[ok] done: {out / 'summary.md'}")


if __name__ == "__main__":
    main()
