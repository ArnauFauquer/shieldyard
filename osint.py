"""What the internet already knows about you: leaked secrets and breached accounts.

    python osint.py --github my-org --domain example.com --product my-repo
    python osint.py --github my-org --no-upload

    secrets      trufflehog over every public repo of a GitHub user or organization:
                 full history, forks, wikis and gists; with GITHUB_TOKEN in .env also
                 issue, pull request and gist comments, where keys get pasted in passing.
                 Verified (still live) keys are the ones to rotate today.
    footprint    theHarvester over each --domain: emails, subdomains and hosts from public
                 sources (certificate transparency, passive DNS, search engines) -- the
                 external surface someone profiling you would start from. Keyless sources only.
    breaches     Have I Been Pwned: which addresses at your domain appear in known
                 breaches, and whether passwords leaked with them. Needs HIBP_API_KEY in
                 .env and the domain verified at haveibeenpwned.com/DomainSearch.

Only what the services report about your own accounts and domain: no breach dumps
are downloaded or searched. Findings go to DefectDojo with reimport, into the product
given by --product (or one named after the first account or domain), engagement "osint".
"""

from __future__ import annotations

import argparse
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

import report
from common import DOJO_URL, ROOT, HttpError, load_env, request
from scan import Result, Tool, run, slug, upload_dojo

TRUFFLEHOG = "trufflesecurity/trufflehog:3.99.7"
HIBP = "https://haveibeenpwned.com/api/v3"
# Pinned by digest: the image publishes only a rolling :latest tag.
THEHARVESTER = "ghcr.io/laramies/theharvester@sha256:64d13691649a97e9b36223bc0ad379b0e032487704328a6e1c4e5f42c94b8115"
# Passive sources that need no API key; theHarvester skips any that fail.
THEHARVESTER_SOURCES = "crtsh,certspotter,hackertarget,rapiddns,otx,urlscan,anubis,duckduckgo"


def trufflehog_github(owner: str, token: str | None) -> Tool:
    # Comments come from the API, which allows 60 requests an hour without a token:
    # without one only the git history (clones don't count) is scanned.
    comments = ["--issue-comments", "--pr-comments", "--gist-comments"] if token else []
    return Tool(f"trufflehog github {owner}", TRUFFLEHOG,
                ["github", f"--org={owner}", "--include-forks", "--include-wikis", *comments,
                 "--json", "--no-update", "--results=verified,unknown"],
                f"trufflehog-github-{slug(owner)}.json", "Trufflehog Scan", stdout_to_output=True,
                env={"GITHUB_TOKEN": token} if token else {}, title=f"trufflehog (github {owner})")


def theharvester(domain: str) -> Tool:
    """theHarvester over a domain: emails, subdomains and hosts from public sources
    (certificate transparency, passive DNS, search engines). The image's entrypoint is a
    web UI, so the CLI is called directly; -f writes <name>.json next to an .xml."""
    s = slug(domain)
    return Tool(f"theharvester {domain}", THEHARVESTER, ["-c", f"""
        /opt/venv/bin/theHarvester -d '{domain}' -b {THEHARVESTER_SOURCES} -l 500 -f /out/theharvester-{s} || true
        [ -s /out/theharvester-{s}.json ] || echo '{{}}' > /out/theharvester-{s}.json
    """], f"theharvester-{s}.json", entrypoint="sh", title=f"theharvester ({domain})",
        convert=lambda path, domain=domain: theharvester_findings(path, domain))


def theharvester_findings(path: Path, domain: str) -> Path:
    """theHarvester's JSON as DefectDojo generic findings: the emails found for the domain
    (where phishing and credential-stuffing start), and a summary of the hosts/subdomains
    public sources expose. Passive reconnaissance, so everything here is Info."""
    data = json.loads(path.read_text(encoding="utf-8") or "{}")
    findings = []
    for email in sorted({e.strip().lower() for e in data.get("emails", []) if e and "@" in e}):
        findings.append({
            "title": f"Public email address: {email}",
            "severity": "Info",
            "description": f"`{email}` is discoverable from public sources for `{domain}` (theHarvester). "
                           "Addresses like this are where phishing and credential-stuffing campaigns begin; "
                           "make sure the account behind it has a second factor.",
            "static_finding": False, "dynamic_finding": True,
            "unique_id_from_tool": f"theharvester:email:{email}",
        })
    hosts = sorted({h.strip().lower().split(":")[0] for h in data.get("hosts", []) if h and "." in h})
    if hosts:
        shown = "\n".join(f"- {h}" for h in hosts[:100])
        more = f"\n\n...and {len(hosts) - 100} more." if len(hosts) > 100 else ""
        findings.append({
            "title": f"Public hosts/subdomains for {domain}: {len(hosts)}",
            "severity": "Info",
            "description": f"theHarvester found {len(hosts)} host(s) for `{domain}` in public sources "
                           f"(certificate transparency, passive DNS, search engines):\n\n{shown}{more}\n\n"
                           "Each is a reachable surface worth confirming is meant to be public; scan them with web.py.",
            "static_finding": False, "dynamic_finding": True,
            "unique_id_from_tool": f"theharvester:hosts:{domain}",
        })
    out = path.with_name(path.stem + "-findings.json")
    out.write_text(json.dumps({"findings": findings}, indent=1), encoding="utf-8")
    return out


def hibp_findings(domain: str, key: str, out: Path) -> Path:
    """HIBP's breached addresses at a domain as DefectDojo generic findings. An address
    whose breach included passwords is High: that password may still be in use."""
    headers = {"hibp-api-key": key, "user-agent": "shieldyard-osint"}
    breached = request("GET", f"{HIBP}/breacheddomain/{domain}", headers=headers) or {}
    catalog = {b["Name"]: b for b in request("GET", f"{HIBP}/breaches", headers={"user-agent": "shieldyard-osint"})}
    findings = []
    for alias, names in sorted(breached.items()):
        breaches = [catalog.get(n, {"Name": n, "Title": n, "BreachDate": "?", "DataClasses": []}) for n in names]
        passwords = [b for b in breaches if "Passwords" in b["DataClasses"]]
        lines = "\n".join(f"- {b['Title']} ({b['BreachDate']}): {', '.join(b['DataClasses'])}" for b in breaches)
        findings.append({
            "title": f"{alias}@{domain} in {len(breaches)} breach{'es' if len(breaches) != 1 else ''}"
                     + (" with passwords" if passwords else ""),
            "severity": "High" if passwords else "Low",
            "description": f"`{alias}@{domain}` appears in:\n\n{lines}\n\n"
                           + ("A password leaked with it: make sure it isn't used anywhere anymore, and that the "
                              "account has a second factor." if passwords else
                              "No password leaked with it, but the address is on phishing and spam lists."),
            "static_finding": False,
            "dynamic_finding": True,
            "unique_id_from_tool": f"hibp:{alias}@{domain}",
        })
    path = out / f"hibp-{slug(domain)}-findings.json"
    path.write_text(json.dumps({"findings": findings}, indent=1), encoding="utf-8")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--github", action="append", default=[], metavar="OWNER", help="GitHub user or org (repeatable)")
    parser.add_argument("--domain", action="append", default=[], help="email domain to check in HIBP (repeatable)")
    parser.add_argument("--product", help="DefectDojo product (default: the first account or domain)")
    parser.add_argument("--no-upload", action="store_true", help="only write files under reports/")
    args = parser.parse_args()
    if not args.github and not args.domain:
        parser.error("give at least one --github or --domain")

    env = load_env()
    upload = not args.no_upload
    if upload and not env.get("DD_API_TOKEN"):
        raise SystemExit("No DD_API_TOKEN in .env: run `python bootstrap.py` first, or pass --no-upload.")
    product = args.product or (args.github + args.domain)[0]
    out = ROOT / "reports" / slug(product) / "osint" / datetime.now().strftime("%Y%m%d-%H%M%S")
    (out / "logs").mkdir(parents=True)
    print(f"[*] {product}: {', '.join(args.github + args.domain)}; output in {out}")

    token = env.get("GITHUB_TOKEN") or None
    tools = [trufflehog_github(owner, token) for owner in args.github]
    tools += [theharvester(domain) for domain in args.domain]
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda t: run(t, None, None, out), tools))
    for r in results:  # theHarvester's JSON becomes generic findings
        if r.ok and r.tool.convert:
            r.tool.output = r.tool.convert(out / r.tool.output).name
            r.tool.dojo_scan_type = r.tool.dojo_scan_type or "Generic Findings Import"

    for domain in args.domain:
        tool = Tool(f"hibp {domain}", "", [], "", "Generic Findings Import", title=f"hibp ({domain})")
        if not env.get("HIBP_API_KEY"):
            results.append(Result(tool, False, 0, "no HIBP_API_KEY in .env"))
            continue
        try:
            tool.output = hibp_findings(domain, env["HIBP_API_KEY"], out).name
            results.append(Result(tool, True, 0))
        except HttpError as e:
            # 403 here means the domain isn't verified for this key yet.
            results.append(Result(tool, False, 0, f"HIBP: HTTP {e.status} {e.body[:120]}"))
    for r in results:
        print(f"    {'ok ' if r.ok else 'ERR'} {r.tool.name:<40} {r.seconds:6.0f}s {r.note}", flush=True)

    if upload:
        print("[*] uploading")
        product_type = "Repositories" if args.product else "Organization"
        for r in results:
            if not r.ok:
                continue
            file = out / r.tool.output
            try:
                if file.stat().st_size == 0:
                    r.dojo = "nothing found"  # trufflehog prints no lines; DefectDojo rejects empty files
                else:
                    r.dojo = upload_dojo(env, file, r.tool.dojo_scan_type, r.tool.test_title, product, "osint",
                                         product_type=product_type)
            except HttpError as e:
                r.dojo = f"upload failed: {e}"
            print(f"    {r.tool.name:<40} {r.dojo}", flush=True)

    lines = [
        f"# {product} OSINT", "", f"{', '.join(args.github + args.domain)}, {datetime.now():%Y-%m-%d %H:%M}", "",
        "| check | status | time | result |", "|---|---|---:|---|",
        *[f"| {r.tool.name} | {'ok' if r.ok else 'failed: ' + r.note} | {r.seconds:.0f}s | {r.dojo or r.note} |"
          for r in results],
        "", f"- Findings: {DOJO_URL}", "",
    ]
    (out / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    (out / "run.json").write_text(json.dumps({
        "product": product, "github": args.github, "domains": args.domain,
        "finished": f"{datetime.now():%Y-%m-%d %H:%M}",
        "tools": [{"name": r.tool.name, "ok": r.ok, "seconds": r.seconds, "note": r.note, "result": r.dojo}
                  for r in results],
    }, indent=1), encoding="utf-8")
    if upload:
        print(f"[ok] report: {report.build(product)}")
    else:
        print(f"[ok] done: {out / 'summary.md'}")


if __name__ == "__main__":
    main()
