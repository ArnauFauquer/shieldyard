"""Scan one repository and report everything to the platform.

    python scan.py ../my-repo
    python scan.py ../my-repo --image ghcr.io/my-org/my-repo/backend:latest
    python scan.py ../my-repo --no-upload        # files only, no platform needed

What runs, all in pinned containers and in parallel:

    secrets      gitleaks (whole git history), trufflehog (live-verified secrets, and every
                 layer of each --image)
    SAST         semgrep, bandit (Python)
    SCA          trivy: an SBOM of the source tree and of each --image, then the
                 CVEs in that SBOM; pip-audit; osv-scanner (OSV database, a second opinion)
    IaC          checkov (Dockerfiles, Kubernetes, GitHub Actions), kics (also docker-compose), hadolint
    CI           zizmor (GitHub Actions workflow security), poutine (pipeline supply chain),
                 actionlint (workflows that are wrong: expressions, shell)
    personal data ferret-scan (cards, IBANs, SSNs, passports committed to the repo)
    supply chain GuardDog (malicious packages among the dependencies), OpenSSF Scorecard
                 (branch protection, pinned actions, signed releases...; needs GITHUB_TOKEN)
    hygiene      deptry (Python), knip (npm): unused or undeclared dependencies
    licenses     trivy: reciprocal, restricted or unknown licenses, source and images
    complexity   lizard (cyclomatic complexity per function) -> DefectDojo + complexity.md
    tests        every pytest / vitest / jest suite with coverage, in its Dockerfile's runtime
    quality      sonar-scanner, after the tests so it gets their coverage -> SonarQube

Findings go to DefectDojo with reimport, so each run updates the same tests:
fixed findings close, new ones open, and triage decisions stay.

The code scanned is the committed HEAD (git archive), not the working tree:
no node_modules, venvs or build output, and what's scanned is what would ship.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import subprocess
import tarfile
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import report
from common import DOJO_URL, ROOT, SONAR_URL, HttpError, load_env, request

PYTHON = "python:3.13-slim"
NETWORK = "scaner_default"  # the compose project's network, so sonar-scanner reaches SonarQube

# Cyclomatic complexity thresholds (McCabe). 10 is the classic "simple";
# above 15 a function is hard to test; above 25 and 50 it's a refactor target.
CCN_SEVERITY = [(50, "High"), (25, "Medium"), (15, "Low")]

# Paths no tool should report on, even when committed.
EXCLUDE_DIRS = ["node_modules", "dist", "build", "vendor", ".venv", "venv", "__pycache__"]

# lizard's CLI aborts the whole run when one file trips its parser, so this
# drives it file by file and skips what it can't read. One JSON line per function.
LIZARD_DRIVER = """
import json, os, sys, lizard
exclude = set(os.environ["EXCLUDE"].split(","))
skipped = 0
with open("/out/lizard.jsonl", "w") as out:
    for root, dirs, files in os.walk("/src"):
        dirs[:] = [d for d in dirs if d not in exclude and not d.startswith(".")]
        for name in files:
            path = os.path.join(root, name)
            if not lizard.get_reader_for(path):
                continue
            try:
                info = lizard.analyze_file(path)
            except Exception:
                skipped += 1
                continue
            for f in info.function_list:
                out.write(json.dumps({"file": path[5:], "function": f.name, "ccn": f.cyclomatic_complexity,
                                      "nloc": f.nloc, "params": f.parameter_count, "start": f.start_line}) + "\\n")
print(f"skipped {skipped} unparseable files", file=sys.stderr)
"""


@dataclass
class Tool:
    name: str
    image: str
    args: list[str]
    output: str  # file the tool leaves in /out
    dojo_scan_type: str | None = None  # DefectDojo parser; None = not imported there
    stdout_to_output: bool = False
    mount_repo: bool = False  # needs .git (history scanners): mount the real repo at /repo
    docker_socket: bool = False
    network: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    entrypoint: str | None = None
    volumes: list[str] = field(default_factory=list)  # extra -v mounts
    title: str | None = None
    sbom: str | None = None  # the CycloneDX file it also writes, for the report and inventory.py
    # Turns the tool's own output into DefectDojo generic findings, for tools it has no parser for.
    convert: Callable[[Path], Path] | None = None

    @property
    def test_title(self) -> str:
        return self.title or self.name


@dataclass
class Result:
    tool: Tool
    ok: bool
    seconds: float
    note: str = ""
    dojo: str = ""


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout.strip()


def snapshot(repo: Path, dest: Path) -> None:
    """Extracts HEAD into dest, replacing what was there."""
    if dest.exists():
        subprocess.run(["docker", "run", "--rm", "-v", f"{dest.parent}:/w", "alpine:3.22", "rm", "-rf", f"/w/{dest.name}"], check=True)
    dest.mkdir(parents=True)
    archive = subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", "HEAD"], capture_output=True, check=True).stdout
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(dest, filter="data")


def slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-").lower()


def plan(src: Path, images: list[str], repo_url: str = "", github_token: str = "") -> list[Tool]:
    files = [p.relative_to(src).as_posix() for p in src.rglob("*") if p.is_file()]
    has = lambda pattern: any(re.search(pattern, f) for f in files)  # noqa: E731
    git_safe = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_VALUE_0": "*"}

    tools = [
        # Personal data committed to the repo (cards, IBANs, SSNs, passports...). The checks for
        # emails, names, dates, phones and "business" terms are left out: on real code they
        # match test fixtures and docs (200 hits, none real, on a sample app). API keys are
        # gitleaks' and trufflehog's job. Its container is `scratch`, so there is no shell.
        Tool("ferret-scan", "public.ecr.aws/awslabs/ferret-scan:2.5.5",
             ["--file", "/src", "--recursive", "--format", "sarif", "--output", "/out/ferret-scan.sarif", "--quiet",
              "--checks", "BANK_ACCOUNT,CREDIT_CARD,DRIVERS_LICENSE,MEDICAL_ID,PASSPORT,SSN", "--confidence", "high,medium"],
             "ferret-scan.sarif", "SARIF", title="ferret-scan (personal data)"),
        Tool("gitleaks", "zricethezav/gitleaks:v8.30.1",
             ["git", "/repo", "--report-format", "json", "--report-path", "/out/gitleaks.json", "--exit-code", "0", "--no-banner"],
             "gitleaks.json", "Gitleaks Scan", mount_repo=True, env=git_safe),
        Tool("trufflehog", "trufflesecurity/trufflehog:3.99.7",
             ["git", "file:///repo", "--json", "--no-update", "--results=verified,unknown"],
             "trufflehog.json", "Trufflehog Scan", stdout_to_output=True, mount_repo=True, env=git_safe),
        Tool("semgrep", "semgrep/semgrep:1.183.0",
             ["semgrep", "scan", "--config", "p/default", "--metrics", "off", "--json", "--output", "/out/semgrep.json",
              *[a for d in EXCLUDE_DIRS for a in ("--exclude", d)], "/src"],
             "semgrep.json", "Semgrep JSON Report"),
        sbom_tool("trivy-fs", "fs /src", "sbom-source.cdx.json", "trivy-fs.json", "trivy (lockfiles)", ignore_unfixed=False),
        # The OSV database differs from trivy's, so each catches CVEs the other misses; DefectDojo
        # keeps them as separate tests. It exits 1 when it finds something, hence the `||`.
        Tool("osv-scanner", "ghcr.io/google/osv-scanner:v2.7.0",
             ["-c", "/osv-scanner scan source -r --format sarif --output-file /out/osv-scanner.sarif /src || test -s /out/osv-scanner.sarif"],
             "osv-scanner.sarif", "SARIF", entrypoint="sh", title="osv-scanner (lockfiles)"),
        Tool("lizard", PYTHON,
             ["sh", "-c", "pip install -q --root-user-action=ignore lizard==1.24.3 && python -c \"$LIZARD\""],
             "lizard.jsonl", env={"LIZARD": LIZARD_DRIVER, "EXCLUDE": ",".join(EXCLUDE_DIRS)}),
    ]

    if has(r"\.py$"):
        tools.append(Tool("bandit", PYTHON,
                          ["sh", "-c", "pip install -q --root-user-action=ignore bandit==1.9.4 && bandit -q -r /src -f json -o /out/bandit.json --exit-zero "
                           # asserts in tests are how tests work, not a finding
                           "-x '" + ",".join(f"*/{d}/*" for d in [*EXCLUDE_DIRS, "tests", "test"]) + "'"],
                          "bandit.json", "Bandit Scan"))
    for req in [f for f in files if re.search(r"(^|/)requirements[^/]*\.txt$", f)]:
        out = f"pip-audit-{slug(req)}.json"
        tools.append(Tool(f"pip-audit {req}", PYTHON,
                          ["sh", "-c", f"pip install -q --root-user-action=ignore pip-audit==2.10.1 && pip-audit -r '/src/{req}' -f json -o /out/{out} || true"],
                          out, "pip-audit Scan", title=f"pip-audit ({req})"))

    if has(r"(^|/)(Dockerfile[^/]*|.*\.ya?ml|.*\.tf)$"):
        # `checkov -d` skips hidden folders, and with -d it ignores -f too, so manifests in
        # .argocd/, .k8s/ and the like get a second pass by file and the two reports merge.
        # (.github is the exception: the github_actions framework finds it on its own.)
        hidden = [f for f in files if re.match(r"\.(?!github/)[^/]+/", f) and re.search(r"(\.ya?ml|(^|/)Dockerfile[^/]*)$", f)]
        common = "-o json --soft-fail --quiet"
        second = (f"checkov {' '.join(f'-f /src/{f}' for f in hidden)} {common} --output-file-path /tmp/b "
                  "--framework kubernetes dockerfile helm && " if hidden else "")
        tools.append(Tool("checkov", "bridgecrew/checkov:3.4.0", ["-c", f"""
            set -e
            checkov -d /src {common} --output-file-path /tmp/a --framework dockerfile kubernetes github_actions terraform helm
            {second}python3 -c "{CHECKOV_MERGE}"
        """], "results_json.json", "Checkov Scan", entrypoint="sh"))
        # A second engine: it also reads docker-compose files, which checkov's frameworks above
        # don't, so the privileged/unbounded-port/secrets-in-env checks reach the compose stack.
        tools.append(Tool("kics", "checkmarx/kics:v2.2.0",
                          ["scan", "-p", "/src", "-o", "/out", "--report-formats", "sarif", "--output-name", "kics",
                           "--no-progress", "--ignore-on-exit", "results"],
                          "kics.sarif", "SARIF", title="kics (IaC)"))
    dockerfiles = [f for f in files if re.search(r"(^|/)Dockerfile[^/]*$", f)]
    if dockerfiles:
        tools.append(Tool("hadolint", "hadolint/hadolint:v2.15.1",
                          ["hadolint", "-f", "json", "--no-fail", *[f"/src/{d}" for d in dockerfiles]],
                          "hadolint.json", "Hadolint Dockerfile check", stdout_to_output=True))

    for image in images:
        s = slug(image)
        # Only CVEs with a fix go to DefectDojo, where someone has to act on them;
        # the SBOM keeps every package, for the report and inventory.py.
        tools.append(sbom_tool(f"trivy {image}", f"image {image}", f"sbom-image-{s}.cdx.json",
                               f"trivy-image-{s}.json", f"trivy ({image})", ignore_unfixed=True))
        # What shipped can hold secrets the repo doesn't: build args, copied .env files, layers
        # deleted later (still in the image). Read from the registry, every layer.
        tools.append(Tool(f"trufflehog {image}", "trufflesecurity/trufflehog:3.99.7",
                          ["docker", f"--image={image}", "--json", "--no-update", "--results=verified,unknown"],
                          f"trufflehog-image-{s}.json", "Trufflehog Scan", stdout_to_output=True,
                          title=f"trufflehog (image {image})", convert=image_secrets))

    return (tools + hygiene_tools(src, files, images) + supply_chain_tools(src, files, repo_url, github_token)
            + test_suites(src, files))


TRIVY = "aquasec/trivy:0.76.1"


def sbom_tool(name: str, target: str, sbom: str, output: str, title: str, ignore_unfixed: bool) -> Tool:
    """trivy writes the SBOM, then finds the vulnerabilities in that SBOM, so the findings
    in DefectDojo and the inventory in the report describe exactly the same packages."""
    kind, what = target.split(" ", 1)
    command = (f"trivy {kind} -q --cache-dir /cache --format cyclonedx --output /out/{sbom} {what}"
               f" && trivy sbom -q --cache-dir /cache --scanners vuln {'--ignore-unfixed ' if ignore_unfixed else ''}"
               f"--format json --output /out/{output} /out/{sbom}")
    return Tool(name, TRIVY, ["-c", command], output, "Trivy Scan", entrypoint="sh",
                docker_socket=kind == "image", title=title, sbom=sbom)


def runtime_version(src: Path, folder: str, image: str, default: str) -> str:
    """The python:/node: version that folder's Dockerfile builds on, so tests run like production."""
    dockerfile = src / folder / "Dockerfile"
    if dockerfile.exists():
        m = re.search(rf"^FROM\s+(?:--\S+\s+)*(?:\S+/)?{image}:(\d+(?:\.\d+)?)", dockerfile.read_text(encoding="utf-8", errors="replace"), re.M)
        if m:
            return m.group(1)
    return default


def test_suites(src: Path, files: list[str]) -> list[Tool]:
    """Every pytest and vitest/jest suite in the repo, run with coverage.

    The snapshot stays read-only: pytest keeps its cache and coverage data in
    /tmp, and npm installs into a copy. Failing tests still produce coverage;
    the JUnit file says what failed.
    """
    tools = []

    for folder, install in python_projects(files):
        prefix = f"{folder}/" if folder else ""
        if not any(re.match(rf"{re.escape(prefix)}(tests?/)?(.*/)?test_[^/]*\.py$", f) for f in files):
            continue
        name = folder or "root"
        s = slug(name)
        version = runtime_version(src, folder, "python", "3.12")
        tools.append(Tool(f"tests {name} (pytest)", f"python:{version}-slim", ["sh", "-c", f"""
            set -e
            apt-get update -qq >/dev/null && apt-get install -y -qq git >/dev/null
            cd /usr/src/{folder}
            pip install -q --root-user-action=ignore {install} pytest pytest-cov
            printf '[run]\\nomit = */tests/*\\n    */test_*.py\\n' > /tmp/coveragerc
            python -m pytest -q -p no:cacheprovider --cov=. --cov-config=/tmp/coveragerc \\
              --cov-report=xml:/out/coverage-{s}.xml --junitxml=/out/junit-{s}.xml || true
        """], f"coverage-{s}.xml", env={**CACHES, "COVERAGE_FILE": "/tmp/.coverage", "PYTHONDONTWRITEBYTECODE": "1"}))

    for folder, manifest, install in node_projects(src, files):
        deps = {**manifest.get("dependencies", {}), **manifest.get("devDependencies", {})}
        name = folder or "root"
        s = slug(name)
        version = runtime_version(src, folder, "node", "22")
        dest = f"/usr/src/{folder}/".replace("//", "/")
        if "vitest" in deps:
            run_tests = (
                'V=$(node -p "require(\'vitest/package.json\').version") && '
                "npm i --no-save --no-audit --no-fund --loglevel=error @vitest/coverage-v8@$V && "
                f"(npx vitest run --coverage.enabled --coverage.provider=v8 --coverage.reporter=lcov "
                f"--coverage.reportsDirectory=/tmp/cov --coverage.include='src/**' "
                f"--reporter=default --reporter=junit --outputFile.junit=/out/junit-{s}.xml || true)"
            )
        elif "jest" in deps:
            run_tests = (
                "npm i --no-save --no-audit --no-fund --loglevel=error jest-junit && "
                f"(JEST_JUNIT_OUTPUT_FILE=/out/junit-{s}.xml npx jest --ci --coverage --coverageReporters=lcov "
                f"--coverageDirectory=/tmp/cov --reporters=default --reporters=jest-junit || true)"
            )
        else:
            continue
        tools.append(Tool(f"tests {name} ({'vitest' if 'vitest' in deps else 'jest'})", f"node:{version}-alpine", ["sh", "-c", f"""
            set -e
            # the whole repo, not just the package: tests may read sibling folders' fixtures
            cp -r /usr/src /tmp/repo && cd /tmp/repo/{folder}
            {install}
            {run_tests}
            # paths as sonar-scanner sees them (/usr/src/...), whether lcov wrote them relative or absolute
            sed -E -e 's#^SF:/tmp/repo/#SF:/usr/src/#' -e 's#^SF:([^/])#SF:{dest}\\1#' /tmp/cov/lcov.info > /out/lcov-{s}.info
        """], f"lcov-{s}.info", env=CACHES))
    return tools


GUARDDOG = "ghcr.io/datadog/guarddog:v3.2.0"
# GuardDog's capability-* rules flag what a package can do (network, files, processes),
# which is half of all legitimate packages; its threat-* and metadata rules flag what
# malware does. Only the latter go to DefectDojo, minus three threat rules that fire on
# ordinary libraries too (python-dotenv reads .env files, authlib reads env vars, PyYAML
# loads classes dynamically).
GUARDDOG_NOISY = [
    "capability-network-download", "capability-process-schedule", "capability-network-lolbas",
    "capability-process-hooks", "capability-filesystem-delete", "capability-network-outbound",
    "capability-filesystem-write-executable", "capability-filesystem-browser", "capability-runtime-clipboard",
    "capability-process-spawn", "capability-filesystem-read",
    "threat-filesystem-read", "threat-runtime-environment-read", "threat-runtime-dynamic-loader",
]


def supply_chain_tools(src: Path, files: list[str], repo_url: str, github_token: str) -> list[Tool]:
    """Malicious packages among the dependencies (GuardDog), and how well the repository
    itself is protected against tampering (OpenSSF Scorecard)."""
    tools = []
    exclude = [a for rule in GUARDDOG_NOISY for a in ("-x", rule)]
    # GuardDog downloads each declared package and reads its code: typosquats, install
    # scripts, obfuscated payloads, exfiltration. CVE scanners don't look for any of that.
    for ecosystem, pattern in (("pypi", r"(^|/)requirements\.txt$"), ("npm", r"(^|/)package\.json$")):
        for manifest in [f for f in files if re.search(pattern, f) and "node_modules/" not in f]:
            name = manifest.rsplit("/", 1)[0] if "/" in manifest else "root"
            s = slug(f"{ecosystem}-{name}")
            # Converted: DefectDojo's SARIF parser fails on GuardDog's rule ids.
            tools.append(Tool(f"guarddog {ecosystem} {name}", GUARDDOG,
                              [ecosystem, "verify", f"/src/{manifest}", "--output-format", "sarif", *exclude],
                              f"guarddog-{s}.sarif", stdout_to_output=True, title=f"guarddog ({ecosystem} {name})",
                              convert=lambda path, manifest=manifest, src=src: guarddog_findings(path, src, manifest)))

    github = re.match(r"https://github\.com/([^/]+/[^/]+)$", repo_url)
    if github and github_token:
        tools.append(Tool("scorecard", "ghcr.io/ossf/scorecard:v5.6.0",
                          [f"--repo=github.com/{github.group(1)}", "--format", "json", "--show-details",
                           "--output", "/out/scorecard.json"],
                          "scorecard.json", env={"GITHUB_AUTH_TOKEN": github_token}, title="scorecard (repository)",
                          convert=scorecard_findings))
    return tools


def guarddog_findings(path: Path, src: Path, manifest: str) -> Path:
    """GuardDog's SARIF as DefectDojo generic findings, one per package, version and rule.
    Obfuscation inside a published bundle (dist/, *.min.js, vendored decoders) is how
    big front-end libraries ship, so it ranks Low; anything else Medium. A new version
    of a package is a new finding: what was fine in 7.9.0 isn't vouched for in 7.9.1."""
    lines = (src / manifest).read_text(encoding="utf-8").splitlines()
    findings = []
    for run_ in json.loads(path.read_text(encoding="utf-8") or '{"runs": []}').get("runs", []):
        for result in run_.get("results", []):
            rule, text = result["ruleId"], result["message"]["text"].strip()
            m = re.match(r"On package: (\S+) version: (\S+)\s*(.*)", text, re.S)
            if m:
                package, version, detail = m.groups()
            else:  # metadata rules name no package: the manifest line they point at does
                line = (result.get("locations") or [{}])[0].get("physicalLocation", {}).get("region", {}).get("startLine", 0)
                found = re.search(r'"([^"]+)"\s*:', lines[line - 1]) if 0 < line <= len(lines) else None
                package, version, detail = (found.group(1) if found else "?"), "", text
            bundled = rule == "threat-runtime-obfuscation" and re.search(r"(/dist/|/build/|\.min\.js|/libs?/|/vendor/)", detail)
            findings.append({
                "title": f"{rule}: {package}{' ' + version if version else ''}",
                "severity": "Low" if bundled or rule == "metadata_mismatch" else "Medium",
                "description": f"GuardDog rule `{rule}` matched `{package}` {version}:\n\n{detail}\n\n"
                               "A heuristic: check the file it names before trusting or removing the package. "
                               "Once reviewed, mark it as a false positive and it stays closed for this version.",
                "file_path": manifest,
                "component_name": package,
                "component_version": version or None,
                "static_finding": True,
                "dynamic_finding": False,
                "unique_id_from_tool": f"guarddog:{rule}:{package}:{version}",
            })
    out = path.with_name(path.stem + "-findings.json")
    out.write_text(json.dumps({"findings": findings}, indent=1), encoding="utf-8")
    return out


ACTIONLINT_SEVERITY = {"credentials": "High", "permissions": "Medium", "shellcheck": "Low", "pyflakes": "Low"}


def actionlint_findings(path: Path) -> Path:
    """actionlint's JSON as DefectDojo generic findings. The id leaves the line out so editing
    the file above an error doesn't close and reopen it."""
    findings = []
    for e in json.loads(path.read_text(encoding="utf-8") or "null") or []:
        kind, file = e.get("kind", "?"), e.get("filepath", "")
        findings.append({
            "title": f"actionlint {kind}: {e['message'].splitlines()[0][:120]}",
            "severity": ACTIONLINT_SEVERITY.get(kind, "Medium"),
            "description": f"{e['message']}\n\n```\n{e.get('snippet', '')}\n```",
            "file_path": file,
            "line": e.get("line"),
            "static_finding": True,
            "dynamic_finding": False,
            "unique_id_from_tool": f"actionlint:{kind}:{file}:{e['message']}",
        })
    out = path.with_name(path.stem + "-findings.json")
    out.write_text(json.dumps({"findings": findings}, indent=1), encoding="utf-8")
    return out


# Scorecard's own risk level per check (docs/checks.md), the severity when it scores low.
SCORECARD_RISK = {
    "Dangerous-Workflow": "Critical",
    "Binary-Artifacts": "High", "Branch-Protection": "High", "Code-Review": "High", "Dependency-Update-Tool": "High",
    "Maintained": "High", "Signed-Releases": "High", "Token-Permissions": "High", "Vulnerabilities": "High",
    "Fuzzing": "Medium", "Packaging": "Medium", "Pinned-Dependencies": "Medium", "SAST": "Medium",
    "Security-Policy": "Medium", "Webhooks": "Medium",
    "CI-Tests": "Low", "CII-Best-Practices": "Low", "Contributors": "Low", "License": "Low",
}


def scorecard_findings(path: Path) -> Path:
    """Scorecard's checks as DefectDojo generic findings: one per check under 10/10, at the
    check's risk when it scores 0-4, a step lower at 5-7, Info at 8-9. Checks it couldn't
    decide (-1, e.g. no permission to read branch protection) are left out."""
    order = ["Critical", "High", "Medium", "Low", "Info"]
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = []
    for check in data.get("checks", []):
        score = check.get("score", -1)
        if score < 0 or score >= 10:
            continue
        risk = SCORECARD_RISK.get(check["name"], "Low")
        severity = risk if score <= 4 else order[min(order.index(risk) + 1, 4)] if score <= 7 else "Info"
        details = "\n".join(f"- {d}" for d in (check.get("details") or [])[:30])
        findings.append({
            "title": f"Scorecard {check['name']}: {score}/10",
            "severity": severity,
            "description": f"{check.get('reason', '')}\n\n{details}\n\n{(check.get('documentation') or {}).get('short', '')}",
            "mitigation": (check.get("documentation") or {}).get("url", ""),
            "static_finding": True,
            "dynamic_finding": False,
            "unique_id_from_tool": f"scorecard:{check['name']}",
        })
    out = path.with_name(path.stem + "-findings.json")
    out.write_text(json.dumps({"findings": findings}, indent=1), encoding="utf-8")
    return out


def hygiene_tools(src: Path, files: list[str], images: list[str]) -> list[Tool]:
    """Dependencies declared but unused (or used but undeclared), CI workflow security, licenses."""
    tools = []
    for folder, install in python_projects(files):
        name = folder or "root"
        s = slug(name)
        reqs = "--requirements-files requirements.txt " if install == "-r requirements.txt" else ""
        # The project's own packages are installed so deptry maps distributions to the
        # modules they provide (python-frontmatter -> frontmatter) instead of guessing.
        tools.append(Tool(f"deptry {name}", f"python:{runtime_version(src, folder, 'python', '3.12')}-slim", ["sh", "-c", f"""
            cd /usr/src/{folder}
            pip install -q --root-user-action=ignore {install} deptry==0.25.1
            deptry . {reqs}--no-ansi --json-output /out/deptry-{s}.json || test -f /out/deptry-{s}.json
        """], f"deptry-{s}.json", env={**CACHES, "PYTHONDONTWRITEBYTECODE": "1"}, title=f"deptry ({name})",
            convert=lambda path, folder=folder: deptry_findings(path, folder)))

    for folder, _, install in node_projects(src, files):
        name = folder or "root"
        s = slug(name)
        # Dependencies and files only: unused exports are noisy and SonarQube already flags dead code.
        tools.append(Tool(f"knip {name}", f"node:{runtime_version(src, folder, 'node', '22')}-alpine", ["sh", "-c", f"""
            set -e
            cp -r /usr/src /tmp/repo && cd /tmp/repo/{folder}
            {install}
            npx -y knip@6.44.0 --reporter json --no-exit-code \\
              --include dependencies,unlisted,unresolved,binaries,files > /out/knip-{s}.json
        """], f"knip-{s}.json", env=CACHES, title=f"knip ({name})",
            convert=lambda path, folder=folder: knip_findings(path, folder)))

    if any(f.startswith(".github/workflows/") for f in files):
        # --offline: the audits that need the GitHub API (impostor commits, known-vulnerable
        # action versions) are skipped; the rest read only the workflow files.
        tools.append(Tool("zizmor", PYTHON, ["sh", "-c", """
            pip install -q --root-user-action=ignore zizmor==1.31.1
            cd /usr/src && zizmor --offline --no-progress --format sarif . > /out/zizmor.sarif || test -s /out/zizmor.sarif
        """], "zizmor.sarif", "SARIF", env=CACHES, title="zizmor (GitHub Actions)"))
        # What zizmor and poutine don't look at: workflows that are wrong rather than unsafe
        # (bad expressions, typos in `github.*`, shell errors in `run:` via shellcheck). It needs
        # a git root unless the files are named, hence the glob.
        tools.append(Tool("actionlint", "rhysd/actionlint:1.7.12",
                          ["-c", "cd /src && actionlint -format '{{json .}}' .github/workflows/*.y*ml || true"],
                          "actionlint.json", stdout_to_output=True, entrypoint="sh",
                          title="actionlint (GitHub Actions)", convert=actionlint_findings))
        # Where zizmor audits single workflows, poutine follows the pipeline's trust: untrusted
        # actions, injectable triggers, self-hosted runners. The SARIF goes to stdout.
        tools.append(Tool("poutine", "ghcr.io/boostsecurityio/poutine:1.1.6",
                          ["analyze_local", "/src", "-f", "sarif", "--disable-version-check"],
                          "poutine.sarif", "SARIF", stdout_to_output=True, title="poutine (CI pipelines)"))

    # Licenses that need a decision (reciprocal, restricted, forbidden) or that trivy
    # couldn't classify; MIT/BSD/Apache stay out. Images: libraries only, since every
    # distro ships GPL system packages and that isn't what this is about.
    licenses = "--scanners license --severity UNKNOWN,MEDIUM,HIGH,CRITICAL --format json"
    tools.append(Tool("trivy licenses", TRIVY, ["fs", "-q", "--cache-dir", "/cache", *licenses.split(),
                                                "--output", "/out/licenses-source.json", "/src"],
                      "licenses-source.json", title="trivy licenses (source)", convert=license_findings))
    for image in images:
        s = slug(image)
        tools.append(Tool(f"trivy licenses {image}", TRIVY,
                          ["image", "-q", "--cache-dir", "/cache", *licenses.split(), "--pkg-types", "library",
                           "--output", f"/out/licenses-image-{s}.json", image],
                          f"licenses-image-{s}.json", docker_socket=True, title=f"trivy licenses ({image})",
                          convert=license_findings))
    return tools


def license_findings(path: Path) -> Path:
    """trivy's license JSON as DefectDojo generic findings. A license is information, not a
    vulnerability, so they are all Info whatever trivy's severity (which still picks what is listed)."""
    findings = []
    for result in json.loads(path.read_text(encoding="utf-8")).get("Results") or []:
        for lic in result.get("Licenses") or []:
            file = lic.get("FilePath") or result.get("Target", "")
            pkg = lic.get("PkgName", "")
            findings.append({
                "title": f"{lic['Name']}: {pkg or file}" + (f" ({file})" if pkg and file else ""),
                "severity": "Info",
                "description": f"{lic.get('Category', 'unknown')} license `{lic['Name']}` (trivy: {lic.get('Severity', '')}) "
                               f"in `{pkg or file}`.\n\n{lic.get('Link', '')}",
                "file_path": file,
                "static_finding": True,
                "dynamic_finding": False,
                "unique_id_from_tool": f"license:{file}:{pkg}:{lic['Name']}",
            })
    out = path.with_name(path.stem + "-findings.json")
    out.write_text(json.dumps({"findings": findings}, indent=1), encoding="utf-8")
    return out


# Installed libraries: their docstrings are full of example credentials (user:pass@host).
LIBRARY_PATHS = re.compile(r"/(site-packages|dist-packages|node_modules|usr/lib|usr/share|usr/local/lib/node)/")


def image_secrets(path: Path) -> Path:
    """trufflehog's image results without unverified hits inside installed libraries.
    A verified (live) key stays wherever it is."""
    kept = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        hit = json.loads(line)
        file = ((hit.get("SourceMetadata") or {}).get("Data") or {}).get("Docker", {}).get("file", "")
        if hit.get("Verified") or not LIBRARY_PATHS.search(file):
            kept.append(line)
    out = path.with_name(path.stem + "-app.json")
    out.write_text("".join(f"{line}\n" for line in kept), encoding="utf-8")
    return out


def deptry_findings(path: Path, folder: str) -> Path:
    """deptry's JSON as DefectDojo generic findings."""
    kinds = {
        "DEP001": ("Imported but not declared", "Medium",
                   "is imported but no requirements file declares it, so a clean install can miss it."),
        "DEP002": ("Declared but never imported", "Low",
                   "is declared but nothing imports it. Packages used only at runtime (a server, a driver, a "
                   "plugin) show up here too: mark those as false positives once and they stay closed."),
        "DEP003": ("Transitive dependency imported directly", "Low",
                   "is imported directly but only installed because another package depends on it. Declare it, "
                   "or an upgrade of that other package can remove it."),
        "DEP004": ("Development dependency used in production code", "Medium",
                   "is a development dependency but production code imports it."),
        "DEP005": ("Standard library module declared as a dependency", "Info",
                   "is part of the standard library; the requirement can go."),
    }
    findings = []
    for item in json.loads(path.read_text(encoding="utf-8")):
        code = item["error"]["code"]
        title, severity, why = kinds.get(code, (item["error"]["message"], "Low", ""))
        loc = item.get("location") or {}
        file = f"{folder}/{loc.get('file', '')}".strip("/")
        findings.append({
            "title": f"{title}: {item['module']}",
            "severity": severity,
            "description": f"`{item['module']}` {why}\n\ndeptry {code}: {item['error']['message']}",
            "file_path": file,
            "line": loc.get("line") or None,
            "static_finding": True,
            "dynamic_finding": False,
            "unique_id_from_tool": f"deptry:{code}:{file}:{item['module']}",
        })
    out = path.with_name(path.stem + "-findings.json")
    out.write_text(json.dumps({"findings": findings}, indent=1), encoding="utf-8")
    return out


def knip_findings(path: Path, folder: str) -> Path:
    """knip's JSON reporter output as DefectDojo generic findings."""
    kinds = {
        "dependencies": ("Unused dependency", "Low", "is in `dependencies` but nothing imports it."),
        "devDependencies": ("Unused devDependency", "Low", "is in `devDependencies` but no code, config or script uses it."),
        "optionalPeerDependencies": ("Unused optional peer dependency", "Info", "is declared but unused."),
        "unlisted": ("Used but not in package.json", "Medium",
                     "is imported but not declared, so it only works while another package pulls it in."),
        "unresolved": ("Unresolved import", "Medium", "is imported but can't be resolved to a file or package."),
        "binaries": ("Binary from an undeclared package", "Low", "is run by a script but no declared package provides it."),
        "files": ("Unused file", "Info", "isn't reachable from any entry point. Config files a tool reads by name can show up here."),
    }
    findings = []
    for issue in json.loads(path.read_text(encoding="utf-8")).get("issues", []):
        base = f"{folder}/{issue.get('file', '')}".strip("/")
        for key, (title, severity, why) in kinds.items():
            for item in issue.get(key) or []:
                name = item.get("name", issue.get("file", ""))
                findings.append({
                    "title": f"{title}: {name}",
                    "severity": severity,
                    "description": f"`{name}` {why}",
                    "file_path": base,
                    "line": item.get("line") or None,
                    "static_finding": True,
                    "dynamic_finding": False,
                    "unique_id_from_tool": f"knip:{key}:{base}:{name}",
                })
    out = path.with_name(path.stem + "-findings.json")
    out.write_text(json.dumps({"findings": findings}, indent=1), encoding="utf-8")
    return out


CACHES = {"PIP_CACHE_DIR": "/cache/pip", "npm_config_cache": "/cache/npm"}

# checkov writes one report per run (a dict for one framework, a list for several);
# DefectDojo takes the list form, so both passes become one list.
CHECKOV_MERGE = (
    "import json, os; parts = []; "
    "[parts.extend(r if isinstance(r, list) else [r]) for r in "
    "(json.load(open(p)) for p in ('/tmp/a/results_json.json', '/tmp/b/results_json.json') if os.path.exists(p))]; "
    "json.dump(parts, open('/out/results_json.json', 'w'))"
)


def python_projects(files: list[str]) -> list[tuple[str, str]]:
    """(folder, pip install argument) for every requirements.txt or pyproject.toml project."""
    projects = {}
    for marker in sorted(f for f in files if re.search(r"(^|/)(requirements\.txt|pyproject\.toml)$", f)):
        folder = marker.rsplit("/", 1)[0] if "/" in marker else ""
        prefix = f"{folder}/" if folder else ""
        projects[folder] = "-r requirements.txt" if f"{prefix}requirements.txt" in files else "."
    return list(projects.items())


def node_projects(src: Path, files: list[str]) -> list[tuple[str, dict, str]]:
    """(folder, package.json, install command) for every npm project."""
    quiet = "--no-audit --no-fund --loglevel=error"
    projects = []
    for pkg in [f for f in files if re.search(r"(^|/)package\.json$", f) and "node_modules/" not in f]:
        folder = pkg.rsplit("/", 1)[0] if "/" in pkg else ""
        manifest = json.loads((src / pkg).read_text(encoding="utf-8"))
        # A lockfile written by a newer npm than the image ships can fail `npm ci`;
        # CI pipelines upgrade npm first for the same reason.
        install = (f"(npm ci {quiet} || (npm install -g --loglevel=error npm@11 && npm ci {quiet}))"
                   if (src / folder / "package-lock.json").exists() else f"npm install {quiet}")
        projects.append((folder, manifest, install))
    return projects


def sonar_tool(product: str, version: str, env: dict[str, str], out: Path) -> Tool:
    """sonar-scanner, given whatever coverage the test suites left in out/."""
    tests = ["**/tests/**", "**/test/**", "**/test_*.py", "**/*.test.*", "**/*.spec.*"]
    coverage = []
    if python := [f"/out/{p.name}" for p in out.glob("coverage-*.xml")]:
        coverage.append("-Dsonar.python.coverage.reportPaths=" + ",".join(python))
    if js := [f"/out/{p.name}" for p in out.glob("lcov-*.info")]:
        coverage.append("-Dsonar.javascript.lcov.reportPaths=" + ",".join(js))
    return Tool("sonar-scanner", "sonarsource/sonar-scanner-cli:12.3.0.4285_8.1.0",
                [f"-Dsonar.projectKey={slug(product)}", f"-Dsonar.projectName={product}",
                 f"-Dsonar.projectVersion={version}", "-Dsonar.sources=.", "-Dsonar.tests=.",
                 "-Dsonar.exclusions=" + ",".join([*(f"**/{d}/**" for d in EXCLUDE_DIRS), *tests]),
                 "-Dsonar.test.inclusions=" + ",".join(tests),
                 *coverage,
                 # Kubernetes manifests are checkov's: this SonarQube edition indexes them as plain
                 # YAML and runs no Kubernetes rules on them, hidden folder or not.
                 "-Dsonar.working.directory=/tmp/scannerwork", "-Dsonar.scm.disabled=true"],
                "", network=NETWORK, env={"SONAR_HOST_URL": "http://sonarqube:9000", "SONAR_TOKEN": env["SONAR_TOKEN"]})


def run(tool: Tool, src: Path | None, repo: Path | None, out: Path) -> Result:
    cmd = ["docker", "run", "--rm", "-v", f"{out}:/out", "-v", "scaner-trivy-cache:/cache"]
    if tool.mount_repo:
        cmd += ["-v", f"{repo}:/repo:ro"]
    elif src:
        cmd += ["-v", f"{src}:/src:ro", "-v", f"{src}:/usr/src:ro"]
    for volume in tool.volumes:
        cmd += ["-v", volume]
    if tool.docker_socket:
        cmd += ["-v", "/var/run/docker.sock:/var/run/docker.sock"]
    if tool.network:
        cmd += ["--network", tool.network]
    for key, value in tool.env.items():
        cmd += ["-e", f"{key}={value}"]
    if tool.entrypoint is not None:
        cmd += ["--entrypoint", tool.entrypoint]
    cmd += [tool.image, *tool.args]

    started = time.monotonic()
    log = out / "logs" / f"{slug(tool.name)}.log"
    proc = subprocess.run(cmd, capture_output=True, check=False)
    elapsed = time.monotonic() - started
    if tool.stdout_to_output:
        (out / tool.output).write_bytes(proc.stdout)
        log.write_bytes(proc.stderr)
    else:
        log.write_bytes(proc.stdout + proc.stderr)
    produced = not tool.output or (out / tool.output).exists()
    ok = proc.returncode == 0 and produced
    note = "" if ok else f"exit {proc.returncode}" + ("" if produced else ", no output") + f" (see logs/{log.name})"
    return Result(tool, ok, elapsed, note)


def complexity(out: Path) -> tuple[Path | None, str]:
    """Turns lizard.jsonl into complexity.md and DefectDojo generic findings."""
    path = out / "lizard.jsonl"
    if not path.exists():
        return None, ""
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        return None, ""

    findings = []
    for r in rows:
        severity = next((sev for limit, sev in CCN_SEVERITY if r["ccn"] > limit), None)
        if severity:
            findings.append({
                "title": f"High cyclomatic complexity: {r['function']} (CCN {r['ccn']})",
                "severity": severity,
                "description": f"`{r['function']}` in `{r['file']}` has a cyclomatic complexity of {r['ccn']} "
                               f"over {r['nloc']} lines and {r['params']} parameters. Above 15 a function is hard to test "
                               f"exhaustively; split it into smaller functions with one job each.",
                "file_path": r["file"],
                "line": r["start"],
                "cwe": 1121,
                "static_finding": True,
                "dynamic_finding": False,
                "unique_id_from_tool": f"lizard:{r['file']}:{r['function']}",
            })
    generic = out / "complexity-findings.json"
    generic.write_text(json.dumps({"findings": findings}, indent=2), encoding="utf-8")

    ccns = sorted(r["ccn"] for r in rows)
    total = len(ccns)
    over = lambda n: sum(c > n for c in ccns)  # noqa: E731
    by_file: dict[str, list[int]] = {}
    for r in rows:
        by_file.setdefault(r["file"], []).append(r["ccn"])
    top_files = sorted(by_file.items(), key=lambda kv: sum(kv[1]), reverse=True)[:10]
    top_funcs = sorted(rows, key=lambda r: r["ccn"], reverse=True)[:20]

    md = [
        "# Cyclomatic complexity", "",
        f"{total} functions, average CCN {sum(ccns) / total:.1f}, median {ccns[total // 2]}, max {ccns[-1]}.", "",
        "| CCN | functions | share |", "|---|---:|---:|",
        *[f"| > {n} | {over(n)} | {over(n) / total:.1%} |" for n in (10, 15, 25, 50)], "",
        "## Most complex functions", "", "| CCN | NLOC | function | where |", "|---:|---:|---|---|",
        *[f"| {r['ccn']} | {r['nloc']} | `{r['function']}` | {r['file']}:{r['start']} |" for r in top_funcs], "",
        "## Files with the most total complexity", "", "| total CCN | functions | max | file |", "|---:|---:|---:|---|",
        *[f"| {sum(c)} | {len(c)} | {max(c)} | {f} |" for f, c in top_files], "",
    ]
    (out / "complexity.md").write_text("\n".join(md), encoding="utf-8")
    headline = f"{total} functions, avg CCN {sum(ccns) / total:.1f}, {over(15)} over 15, {over(25)} over 25"
    return generic, headline


def upload_dojo(env, file: Path, scan_type: str, title: str, product: str, engagement: str,
                product_type: str = "Repositories", extra: dict[str, str] | None = None) -> str:
    stats = request(
        "POST", f"{DOJO_URL}/api/v2/reimport-scan/",
        headers={"Authorization": f"Token {env['DD_API_TOKEN']}"},
        form={
            "scan_type": scan_type,
            "test_title": title,
            "product_type_name": product_type,
            "product_name": product,
            "engagement_name": engagement,
            "auto_create_context": "true",
            "deduplication_on_engagement": "true",
            "close_old_findings": "true",
            "minimum_severity": "Info",
            "active": "true",
            "verified": "false",
            **(extra or {}),
        },
        files={"file": (file.name, file.read_bytes())},
        timeout=600,
    )
    stats = stats.get("statistics") or {}
    count = lambda d, key="total": ((d or {}).get("total") or {}).get(key, 0)  # noqa: E731
    if "before" not in stats:  # first import of this test
        return f"{count(stats.get('after'), 'active')} imported"
    delta = stats.get("delta") or {}
    return (f"{count(stats.get('after'), 'active')} open "
            f"(+{count(delta.get('created'))} new, -{count(delta.get('closed'))} closed)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("repo", type=Path)
    parser.add_argument("--name", help="product name in the platform (default: the folder name)")
    parser.add_argument("--image", action="append", default=[], help="also scan this container image (repeatable)")
    parser.add_argument("--no-upload", action="store_true", help="only write files under reports/")
    parser.add_argument("--no-sonar", action="store_true")
    parser.add_argument("--jobs", type=int, default=6, help="containers at once")
    args = parser.parse_args()

    repo = args.repo.resolve()
    product = args.name or repo.name
    branch = git(repo, "rev-parse", "--abbrev-ref", "HEAD")
    commit = git(repo, "rev-parse", "HEAD")
    try:
        repo_url = re.sub(r"\.git$", "", git(repo, "remote", "get-url", "origin"))
    except subprocess.CalledProcessError:
        repo_url = ""
    env = load_env()
    upload = not args.no_upload
    if upload and not env.get("DD_API_TOKEN"):
        raise SystemExit("No DD_API_TOKEN in .env: run `python bootstrap.py` first, or pass --no-upload.")

    src = ROOT / "work" / slug(product) / "src"
    out = ROOT / "reports" / slug(product) / datetime.now().strftime("%Y%m%d-%H%M%S")
    (out / "logs").mkdir(parents=True)
    print(f"[*] {product} @ {branch} {commit[:12]}")
    snapshot(repo, src)

    tools = plan(src, args.image, repo_url, env.get("GITHUB_TOKEN", ""))
    if repo_url.startswith("https://github.com/") and not env.get("GITHUB_TOKEN"):
        print("[--] scorecard skipped: it needs GITHUB_TOKEN in .env (read-only is enough)")
    sonar = upload and not args.no_sonar and bool(env.get("SONAR_TOKEN"))
    print(f"[*] running {len(tools) + sonar} scanners, {args.jobs} at a time; output in {out}")

    def report_line(r: Result) -> None:
        print(f"    {'ok ' if r.ok else 'ERR'} {r.tool.name:<34} {r.seconds:6.0f}s {r.note}", flush=True)

    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [pool.submit(run, t, src, repo, out) for t in tools]
        results = []
        for f in futures:
            results.append(f.result())
            report_line(results[-1])
    if sonar:  # last, so it reads the coverage the test suites just wrote
        results.append(run(sonar_tool(product, commit[:12], env, out), src, repo, out))
        report_line(results[-1])

    for r in results:
        if r.ok and r.tool.convert:
            r.tool.output = r.tool.convert(out / r.tool.output).name
            r.tool.dojo_scan_type = r.tool.dojo_scan_type or "Generic Findings Import"

    generic, headline = complexity(out)
    if generic:
        lizard = next(r for r in results if r.tool.name == "lizard")
        lizard.tool.output, lizard.tool.dojo_scan_type, lizard.tool.title = generic.name, "Generic Findings Import", "lizard (complexity)"
        lizard.note = headline

    if upload:
        print("[*] uploading")
        for r in results:
            if not r.ok:
                continue
            file = out / r.tool.output
            try:
                if r.tool.output and file.stat().st_size == 0:
                    r.dojo = "nothing found"  # e.g. trufflehog prints no lines; DefectDojo rejects empty files
                elif r.tool.dojo_scan_type:
                    r.dojo = upload_dojo(env, file, r.tool.dojo_scan_type, r.tool.test_title, product, f"branch {branch}",
                                         extra={"version": commit[:12], "commit_hash": commit, "branch_tag": branch,
                                                "source_code_management_uri": repo_url})
                elif r.tool.name == "sonar-scanner":
                    r.dojo = f"{SONAR_URL}/dashboard?id={slug(product)}"
                elif r.tool.name.startswith("tests "):
                    for s in report.test_suites(out, {"tools": [{"name": r.tool.name}]}):
                        cov = f", {s['covered'] / s['lines']:.1%} of lines covered" if s["lines"] else ""
                        r.dojo = f"{s['tests'] - s['failed']}/{s['tests']} passed{cov}"
            except HttpError as e:
                r.dojo = f"upload failed: {e}"
            print(f"    {r.tool.name:<34} {r.dojo}", flush=True)

    lines = [
        f"# {product} scan", "", f"{branch} @ `{commit[:12]}`, {datetime.now():%Y-%m-%d %H:%M}", "",
        "| tool | status | time | result |", "|---|---|---:|---|",
        *[f"| {r.tool.name} | {'ok' if r.ok else 'failed: ' + r.note} | {r.seconds:.0f}s | {r.dojo or r.note} |" for r in results],
        "", f"- Findings: {DOJO_URL}", f"- Quality: {SONAR_URL}/dashboard?id={slug(product)}", "",
    ]
    (out / "summary.md").write_text("\n".join(lines), encoding="utf-8")
    (out / "run.json").write_text(json.dumps({
        "product": product, "branch": branch, "commit": commit, "repo_url": repo_url,
        "finished": f"{datetime.now():%Y-%m-%d %H:%M}",
        "tools": [{"name": r.tool.name, "ok": r.ok, "seconds": r.seconds, "note": r.note, "result": r.dojo}
                  for r in results],
        # Each SBOM and the DefectDojo test its findings went to, for the report and inventory.py.
        "sboms": [{"label": r.tool.name.removeprefix("trivy ").replace("trivy-fs", "source"), "sbom": r.tool.sbom,
                   "test_title": r.tool.test_title}
                  for r in results if r.ok and r.tool.sbom],
    }, indent=1), encoding="utf-8")
    if headline:
        print(f"    complexity: {headline} (complexity.md)")
    if upload:
        print(f"[ok] report: {report.build(product)}")
    else:
        print(f"[ok] done: {out / 'summary.md'}")


if __name__ == "__main__":
    main()
