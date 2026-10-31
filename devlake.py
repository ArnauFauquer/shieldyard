"""DORA metrics for a GitHub repository in DevLake.

    python devlake.py my-org/my-repo
    python devlake.py my-org/my-repo --deploy-job "build-(backend|frontend)"

Needs GITHUB_TOKEN in .env: a fine-grained token with read-only access to the
repository's metadata, contents, pull requests, issues and actions.
Safe to run again; it updates what it made last time and starts a new collection.

How the four DORA metrics are derived, so the defaults can be adjusted per repo:

    deployment frequency   successful GitHub Actions jobs matching --deploy-job
    lead time for changes  first commit of a merged PR -> the deployment that shipped it
    change failure rate    deployments followed by an issue matching --incident-label
    time to restore        that issue's open -> close time
"""

from __future__ import annotations

import argparse
import os
from datetime import datetime, timedelta, timezone

from common import DEVLAKE_UI_URL, DEVLAKE_URL, HttpError, load_env, request, wait_for

CONNECTION = "github"


def api(method: str, path: str, body=None):
    return request(method, f"{DEVLAKE_URL}{path}", json_body=body, timeout=60)


def connection(token: str) -> int:
    existing = next((c for c in api("GET", "/plugins/github/connections") if c["name"] == CONNECTION), None)
    body = {
        "name": CONNECTION,
        "endpoint": "https://api.github.com/",
        "authMethod": "AccessToken",
        "token": token,
        "enableGraphql": True,
        "rateLimitPerHour": 4500,
    }
    if existing:
        api("PATCH", f"/plugins/github/connections/{existing['id']}", body)
        return existing["id"]
    return api("POST", "/plugins/github/connections", body)["id"]


def scope_config(conn: int, repo: str, deploy_job: str, incident_label: str) -> int:
    name = f"dora {repo}".replace("/", " ")
    body = {
        "name": name,
        "connectionId": conn,
        "entities": ["CODE", "CODEREVIEW", "TICKET", "CICD", "CROSS"],
        # Job names; every job matching both counts as a production deployment.
        "deploymentPattern": deploy_job,
        "productionPattern": deploy_job,
        "issueTypeIncident": incident_label,
        "issueTypeBug": "(?i)bug",
        "refdiff": {"tagsPattern": r"v\d+\.\d+\.\d+", "tagsLimit": 10, "tagsOrder": "reverse semver"},
    }
    existing = next(
        (c for c in api("GET", f"/plugins/github/connections/{conn}/scope-configs") if c["name"] == name), None
    )
    if existing:
        api("PATCH", f"/plugins/github/connections/{conn}/scope-configs/{existing['id']}", body)
        return existing["id"]
    return api("POST", f"/plugins/github/connections/{conn}/scope-configs", body)["id"]


def scope(conn: int, repo: str, config: int) -> int:
    info = api("GET", f"/plugins/github/connections/{conn}/proxy/repos/{repo}")
    api("PUT", f"/plugins/github/connections/{conn}/scopes", {"data": [{
        "connectionId": conn,
        "githubId": info["id"],
        "name": info["name"],
        "fullName": info["full_name"],
        "HTMLUrl": info["html_url"],
        "cloneUrl": info["clone_url"],
        "scopeConfigId": config,
    }]})
    return info["id"]


def project(name: str, conn: int, github_id: int, days: int) -> int:
    try:
        existing = api("GET", f"/projects/{name}")
    except HttpError as e:
        if e.status not in (400, 404):
            raise
        existing = api("POST", "/projects", {
            "name": name,
            "description": "DORA metrics, set up by scaner/devlake.py",
            "enable": True,
            "metrics": [{"pluginName": "dora", "pluginOption": {}, "enable": True}],
        })
    blueprint = existing["blueprint"]["id"]
    api("PATCH", f"/blueprints/{blueprint}", {
        "enable": True,
        "mode": "NORMAL",
        "cronConfig": "0 */6 * * *",
        "timeAfter": (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00Z"),
        "connections": [{"pluginName": "github", "connectionId": conn, "scopes": [{"scopeId": str(github_id)}]}],
    })
    return blueprint


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("repo", help="owner/name on GitHub")
    parser.add_argument("--deploy-job", default="(?i)deploy|release",
                        help="regex for the GitHub Actions job that is a production deployment")
    parser.add_argument("--incident-label", default="(?i)incident",
                        help="regex for the issue label that marks a production incident")
    parser.add_argument("--days", type=int, default=365, help="history to collect")
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN") or load_env().get("GITHUB_TOKEN")
    if not token:
        raise SystemExit(
            "No GITHUB_TOKEN. Create a fine-grained token (read-only: metadata, contents, pull requests,\n"
            "issues, actions) for the repository at https://github.com/settings/personal-access-tokens/new\n"
            "and add it to .env as GITHUB_TOKEN=..."
        )

    wait_for("DevLake", lambda: api("GET", "/ping") is not None, timeout=300)
    conn = connection(token)
    config = scope_config(conn, args.repo, args.deploy_job, args.incident_label)
    github_id = scope(conn, args.repo, config)
    name = args.repo.split("/")[-1]
    blueprint = project(name, conn, github_id, args.days)
    pipeline = api("POST", f"/blueprints/{blueprint}/trigger", {"skipCollectors": False, "fullSync": False})
    print(f"[ok] project {name}: collecting {args.days} days (pipeline {pipeline.get('id')}), then every 6 hours")
    print(f"     progress: {DEVLAKE_UI_URL}/projects/{name}")
    print(f"     DORA dashboard: {DEVLAKE_UI_URL}/grafana/d/qNo8_0M4z/dora")


if __name__ == "__main__":
    main()
