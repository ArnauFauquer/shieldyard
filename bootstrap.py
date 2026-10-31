"""First run: generate secrets, start the platform, set admin passwords, mint API keys.

    python bootstrap.py

Safe to run again: every step it already did is skipped. Admin passwords and
API keys end up in .env, which never leaves this machine (it's gitignored).
"""

from __future__ import annotations

import base64
import secrets
import subprocess

from common import (
    DOJO_URL,
    ROOT,
    SONAR_URL,
    HttpError,
    load_env,
    request,
    save_env,
    wait_for,
)

GENERATED = [
    "POSTGRES_PASSWORD",
    "DD_DB_PASSWORD",
    "SONAR_DB_PASSWORD",
    "DEVLAKE_DB_PASSWORD",
    "DD_SECRET_KEY",
    "DD_CREDENTIAL_AES_256_KEY",
    "DD_ADMIN_PASSWORD",
    "SONAR_ADMIN_PASSWORD",
    "DEVLAKE_ENCRYPTION_SECRET",
    "DEVLAKE_GRAFANA_PASSWORD",
]


def password() -> str:
    # token_urlsafe never yields "$", which compose would read as a variable.
    # Sonar wants a digit, a capital and a symbol in admin passwords.
    return secrets.token_urlsafe(24) + "-A1"


def generate_secrets() -> None:
    env = load_env()
    missing = {key: password() for key in GENERATED if not env.get(key)}
    if missing:
        save_env(missing)
        print(f"[ok] generated {len(missing)} secrets into .env")


def start() -> None:
    subprocess.run(["docker", "compose", "up", "-d"], cwd=ROOT, check=True)


def defectdojo(env: dict[str, str]) -> None:
    def token():
        return request(
            "POST",
            f"{DOJO_URL}/api/v2/api-token-auth/",
            form={"username": "admin", "password": env["DD_ADMIN_PASSWORD"]},
        )["token"]

    wait_for("DefectDojo (first start runs migrations, a few minutes)", token, timeout=1200)
    if not env.get("DD_API_TOKEN"):
        save_env({"DD_API_TOKEN": token()})
        print("[ok] DefectDojo API token saved")


def sonarqube(env: dict[str, str]) -> None:
    wait_for(
        "SonarQube",
        lambda: request("GET", f"{SONAR_URL}/api/system/status")["status"] == "UP",
        timeout=900,
    )
    if env.get("SONAR_TOKEN"):
        return

    def basic(pw: str) -> dict[str, str]:
        return {"Authorization": "Basic " + base64.b64encode(f"admin:{pw}".encode()).decode()}

    new = env["SONAR_ADMIN_PASSWORD"]
    try:
        request(
            "POST",
            f"{SONAR_URL}/api/users/change_password",
            form={"login": "admin", "previousPassword": "admin", "password": new},
            headers=basic("admin"),
        )
        print("[ok] SonarQube admin password changed")
    except HttpError as e:
        if e.status != 401:
            raise
    auth = basic(new)
    try:
        request("POST", f"{SONAR_URL}/api/user_tokens/revoke", form={"name": "scaner"}, headers=auth)
    except HttpError:
        pass
    token = request(
        "POST",
        f"{SONAR_URL}/api/user_tokens/generate",
        form={"name": "scaner", "type": "GLOBAL_ANALYSIS_TOKEN"},
        headers=auth,
    )["token"]
    save_env({"SONAR_TOKEN": token})
    print("[ok] SonarQube analysis token saved")


def devlake_grafana(env: dict[str, str]) -> None:
    # GF_SECURITY_ADMIN_PASSWORD only applies to a fresh Grafana database, so set it
    # explicitly too; harmless when it's already the same.
    subprocess.run(
        ["docker", "compose", "exec", "-T", "devlake-grafana",
         "grafana", "cli", "admin", "reset-admin-password", env["DEVLAKE_GRAFANA_PASSWORD"]],
        cwd=ROOT, check=True, capture_output=True,
    )
    print("[ok] DevLake Grafana admin password set")


def main() -> None:
    generate_secrets()
    start()
    defectdojo(load_env())
    sonarqube(load_env())
    devlake_grafana(load_env())
    print(
        "\nReady. Log in as admin with the passwords in .env (*_ADMIN_PASSWORD, DEVLAKE_GRAFANA_PASSWORD):\n"
        "  DefectDojo        http://localhost:8180\n"
        "  SonarQube         http://localhost:9100\n"
        "  DevLake (DORA)    http://localhost:4000   (python devlake.py once GITHUB_TOKEN is in .env)\n"
        "\nThen scan a repo:  python scan.py ../my-repo"
    )


if __name__ == "__main__":
    main()
