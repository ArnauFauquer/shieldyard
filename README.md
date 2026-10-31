# shieldyard

A self-hosted, open-source take on Snyk / Aikido / SonarQube, plus DORA metrics.
Scanners run in pinned containers; their results go to platforms that keep history,
deduplicate findings and remember triage decisions. One command per job, Python
standard library only.

| Need | Tool | Where |
|---|---|---|
| All findings in one place: dedup, triage, SLAs, history | DefectDojo | http://localhost:8180 |
| Code quality, cyclomatic & cognitive complexity, duplication | SonarQube | http://localhost:9100 |
| DORA metrics (deploy frequency, lead time, CFR, MTTR) | DevLake | http://localhost:4000 |

| Command | What it does |
|---|---|
| `python bootstrap.py` | Starts the platform and configures it (first run) |
| `python scan.py <repo>` | Scans a repository: code, dependencies, images, IaC, CI, tests |
| `python web.py <url>` | Scans a deployed site and its API |
| `python osint.py` | Looks for what is already public: leaked secrets, breached accounts |
| `python devlake.py <owner/repo>` | Loads a GitHub repo into DevLake for DORA metrics |
| `python report.py <product>` | Rebuilds the single offline HTML report |
| `python inventory.py <component>` | Finds a component in every stored SBOM |

Needs Docker and Python 3.10+. Everything listens on 127.0.0.1 only.

## Start

```bash
python bootstrap.py
```

Generates secrets into `.env`, starts the stack (`docker compose up -d`), changes
every default admin password and mints the API keys the scripts need. Run it again
any time; finished steps are skipped. Every login is `admin`; the passwords are in
`.env` (`*_ADMIN_PASSWORD`, `DEVLAKE_GRAFANA_PASSWORD`). See `.env.example` for the
optional keys.

## Scan a repository

```bash
python scan.py ../my-repo
python scan.py ../my-repo --image ghcr.io/my-org/my-repo/backend:latest --image ghcr.io/my-org/my-repo/frontend:latest
python scan.py ../my-repo --no-upload      # files only, no platform needed
```

| Area | Tools | Goes to |
|---|---|---|
| Secrets | gitleaks (full git history), trufflehog (verified live secrets; every layer of each `--image`) | DefectDojo |
| Personal data | ferret-scan: card numbers, IBANs, SSNs, passports, driver's licenses, medical IDs (emails, names and dates are off: they only match fixtures) | DefectDojo (SARIF) |
| SAST | semgrep, bandit | DefectDojo |
| Dependencies | trivy (an SBOM of the source tree, then its CVEs), pip-audit, osv-scanner (OSV database, a second opinion on every lockfile) | DefectDojo |
| Images (`--image`) | trivy: an SBOM of each image, then its fixable CVEs | DefectDojo |
| IaC | checkov (Dockerfile, Kubernetes, GitHub Actions, Terraform, Helm, including manifests in hidden folders like `.argocd/`), kics (a second engine that also reads docker-compose), hadolint | DefectDojo |
| CI workflows | zizmor (credentials left by checkout, injection, permissions, unpinned actions), poutine (untrusted actions, injectable triggers, self-hosted runners), actionlint (bad expressions, typos in `github.*`, shell errors) | DefectDojo (SARIF, generic findings) |
| Malicious packages | GuardDog: downloads every dependency in `requirements.txt` / `package.json` and looks for typosquats, install scripts, obfuscation, exfiltration (threat rules only) | DefectDojo (SARIF) |
| Repository protection | OpenSSF Scorecard: one finding per check under 10/10, at Scorecard's own risk level (needs `GITHUB_TOKEN`) | DefectDojo (generic findings) |
| Dependency hygiene | deptry (Python), knip (npm): declared but unused, used but undeclared, unused files | DefectDojo (generic findings) |
| Licenses | trivy: reciprocal, restricted, forbidden or unknown licenses; for images, libraries only | DefectDojo |
| SBOM | the CycloneDX files trivy writes, kept per scan | the report + `inventory.py` |
| Complexity | lizard, functions with CCN > 15 (over 15 Low, over 25 Medium, over 50 High) | DefectDojo + `complexity.md` |
| Tests | every pytest and vitest/jest suite, with line coverage and JUnit results | SonarQube + the report |
| Quality | sonar-scanner, run last so it gets the coverage | SonarQube |

Test suites are found by `test_*.py` files next to a `requirements.txt` /
`pyproject.toml`, or a `vitest`/`jest` dependency in a `package.json`. Each runs on
the Python/Node version its folder's Dockerfile builds on, without writing into the
scanned tree.

**What is scanned** is the committed `HEAD` (`git archive`): no `node_modules`,
venvs or build output, only what would ship. History scanners read the real `.git`.

**Reimport.** Each run updates the same DefectDojo tests (product = repo, engagement
= branch): fixed findings close, new ones open, false positives and risk acceptances
stay. Reports also land in `reports/<repo>/<timestamp>/` with a `summary.md`.

**Suppressions as code.** Accepted risks can live in the scanned repo, with a reason
and an expiry, and the scanner honors them on the next run. Checked:
`osv-scanner.toml` next to a lockfile (`[[IgnoredVulns]]` with `id`, `ignoreUntil`,
`reason`) drops the CVE. The same idea is native to `.trivyignore.yaml`
(`expired_at`), `zizmor.yml`, `.gitleaksignore`, `.semgrepignore` and ferret-scan's
`.ferret-scan-suppressions.yaml`; those were not tested here.

## Scan a deployed site

Only scan sites you own or have written permission to test.

```bash
python web.py https://app.example.com --product my-repo
python web.py example.com --subdomains
```

| Area | Tools | Goes to |
|---|---|---|
| Attack surface | subfinder (`--subdomains`), httpx, katana (crawls, JavaScript included), wafw00f | DefectDojo (Info findings) + `summary.md` |
| Known vulnerabilities | nuclei: CVEs, exposed panels, `.git`/`.env`/backups, misconfigurations, subdomain takeovers, SPF/DMARC | DefectDojo |
| Leaked keys | nuclei's token templates over every crawled URL, so keys hardcoded in JS bundles show up | DefectDojo |
| Web app | OWASP ZAP baseline (spider plus passive rules), Nikto | DefectDojo |
| API (`--openapi`) | ZAP API scan, plus Schemathesis property-based fuzzing from the spec | DefectDojo |
| TLS | testssl.sh (HTTPS URLs) | DefectDojo |
| DNS and email | dnsx: records, and a finding when the domain has no SPF or DMARC | DefectDojo (generic findings) |
| Ports | nmap: top 1000 TCP ports, service versions, default safe NSE scripts, on the address public DNS gives | DefectDojo |
| Lookalike domains | dnstwist: registered domains one typo away; those with MX can send phishing mail | DefectDojo (generic findings) |
| Hidden paths (`--active`) | feroxbuster with SecLists' raft-medium-directories | DefectDojo (generic findings) |
| Injection (`--active`) | nuclei DAST templates (XSS, SQLi, SSRF...) on crawled URLs with parameters; nmap over all 65535 ports with `vuln` scripts | DefectDojo |

**Passive by default.** Nothing is attacked: nuclei leaves out intrusive, fuzzing,
brute-force and default-login templates, ZAP only reports on what its spider fetched,
Nikto skips injection tests. `--active` adds ZAP's full active scan, every nuclei
template but DoS, nuclei DAST, feroxbuster, Nikto's injection tests and the full nmap
run, after asking for confirmation. The DoS category never runs. nuclei runs with
interactsh off, so no callbacks go to a third-party server.

**Products.** With `--product` the findings join that repository's product, in an
`exposure <target>` engagement next to `branch <name>`, and `report.html` shows code
and site together. Without it, the product is named after the site. `localhost`
targets are scanned as `host.docker.internal`, without nmap. Raw output:
`reports/<product>/web/<timestamp>/`.

### Logged in

An anonymous scan only sees the login page and public routes. `--auth` sends the
header in `WEB_AUTH_HEADER` (`.env`) with every request from nuclei, katana, ZAP and
feroxbuster; `--openapi` adds a ZAP scan and Schemathesis fuzzing of every operation:

```bash
python web.py https://app.example.com --product my-repo --auth --auth-check /api/me --openapi openapi.json
```

- **The session.** Use a dedicated test account, never your own. Sign in as it and
  copy the session cookie from DevTools into `.env`, e.g.
  `WEB_AUTH_HEADER=Cookie: session=...`. `--auth-check` stops the run if the cookie no
  longer works, rather than reporting a clean scan of the login page.
- **The spec.** Export it from a running backend if it doesn't publish one.
- **What it may call.** ZAP's API import calls every operation once, and Schemathesis
  generates many requests per operation. Passive runs give them only the GET
  operations and send no attacks. `--active` sends everything, POST/PUT/DELETE
  included, with made-up values and attack payloads: run that against a staging copy,
  never production, or it will create and delete real data.
- Logged-in results go to their own tests ("zap (...) as user"), so an anonymous run
  doesn't close them. testssl, nmap and dnstwist don't change with a session and are
  skipped.

### After every release

`--after-release owner/repo` scans only when the repo has a GitHub release that hasn't
been scanned yet and is at least 30 minutes old, so a deploy has rolled out (it uses
`GITHUB_TOKEN`). Schedule it hourly, for example as a Windows scheduled task:

```bash
schtasks /Create /SC HOURLY /TN "shieldyard web" /TR "cmd /c cd /d C:\path\to\shieldyard && python web.py https://app.example.com --product my-repo --after-release my-org/my-repo >> reports\web-schedule.log 2>&1"
```

The last tag scanned is in `reports/<product>/web/last-release.txt`; delete it to scan
the current release again.

### Deep pentest (Shannon)

[Shannon](https://github.com/KeygraphHQ/shannon) is an AI agent that reads the source,
looks for injection, XSS, SSRF and broken authentication/authorization, then *tries to
exploit* what it finds and reports only what it could prove. It is **not wired into
`web.py`**: it runs by hand, before a big release or after an auth change.

- **It really attacks.** It creates users and changes data. Run it against a local
  stack with disposable data only, never production.
- **It costs money.** Free software (AGPL), but you bring a model API key; a full run
  is about 1-1.5 hours of model calls.
- **It needs Linux.** On Windows that means a WSL2 distro with Node 18+ and Docker
  usable without sudo.
- **Results aren't repeatable**, so they don't fit DefectDojo's reimport model. Keep
  its SARIF in its own engagement.

```bash
# inside WSL2, as a non-root user with Docker access
npx @keygraph/shannon@latest setup
npx @keygraph/shannon@latest start -u http://localhost:8000 -r /path/to/repo
```

## What's already out there

```bash
python osint.py --github my-org --domain example.com --product my-repo
```

| Check | Tool | Goes to |
|---|---|---|
| Secrets in public code | trufflehog over every public repo of the account: full history, forks, wikis, gists; with `GITHUB_TOKEN`, issue/PR/gist comments too | DefectDojo |
| Public footprint | theHarvester over each `--domain`: emails, subdomains and hosts from certificate transparency, passive DNS and search engines (keyless sources) | DefectDojo (generic findings) |
| Breached accounts | Have I Been Pwned: addresses at the domain found in breaches, High when passwords leaked with them (`HIBP_API_KEY`, domain verified at haveibeenpwned.com) | DefectDojo (generic findings) |

`scan.py --image` also runs trufflehog over every layer of each image, which catches
secrets that never reached git (build args, a copied `.env`, a file deleted in a later
layer). Unverified hits inside installed libraries are dropped: their docstrings are
full of example `user:pass@host` URLs. Verified ones are kept wherever they are.

Only what these services report about your own accounts: no breach dumps are
downloaded or searched. Findings land in the product's `osint` engagement.

## One report

Every scan ends by writing `reports/<repo>/report.html`, a single offline file built
live from DefectDojo, SonarQube, DevLake and the scan's own files: headline numbers,
findings by area and severity with a trend over runs, what to fix first, dependencies
per SBOM, Sonar ratings, the most complex functions, DORA, and every open finding with
a link to the tool that owns it. Rebuild it without scanning (for example after
triaging in DefectDojo):

```bash
python report.py my-repo
```

Which repositories and images contain a component, from the SBOMs of each repo's last
scan:

```bash
python inventory.py openssl
```

## DORA metrics

```bash
python devlake.py my-org/my-repo
```

Needs `GITHUB_TOKEN` in `.env`: a fine-grained, read-only token for the repo (metadata,
contents, pull requests, issues, actions). The defaults assume a release pipeline whose
deploy jobs have "deploy" or "release" in their name; adjust them per repo:

| Metric | Derived from | Flag |
|---|---|---|
| Deployment frequency | successful Actions jobs matching the regex | `--deploy-job` |
| Lead time for changes | first commit of a merged PR, to the deployment that shipped it | |
| Change failure rate | deployments followed by an issue with a matching label | `--incident-label` |
| Time to restore | that issue's open-to-close time | |

Dashboard: http://localhost:4000/grafana/d/qNo8_0M4z/dora, refreshed every 6 hours.

## Layout

```
docker-compose.yml   the platform (one Postgres for DefectDojo and SonarQube)
bootstrap.py         first run: secrets, passwords, API keys
scan.py              repository scanners -> platform
web.py               deployed sites -> platform (DAST)
osint.py             public repos and breached accounts -> platform
devlake.py           GitHub repo -> DORA project
report.py            all of it -> reports/<repo>/report.html
inventory.py         find a component in every stored SBOM
common.py            .env, HTTP, waiting
postgres/init.sh     one database + owner per tool
```

`.env`, `reports/` and `work/` are git-ignored: they hold secrets and scan output.

## Next steps

- Run `scan.py` from a CI job on every PR; the platform URLs and keys would come from
  env vars instead of `.env`.
- Deploy the platform to a cluster (all three tools have Helm charts).
- Incidents straight from Grafana alerts: DevLake's webhook plugin accepts them, so
  CFR/MTTR don't depend on someone labelling an issue.
