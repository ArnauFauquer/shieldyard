"""Which scanned repositories and images contain a component, from their stored SBOMs.

    python inventory.py openssl
    python inventory.py pip --exact

Reads the SBOMs of each repository's last scan (source tree and images), so the
answer is what is deployed, not what a lockfile once said.
"""

from __future__ import annotations

import argparse
import json

import report
from common import ROOT


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("name", help="component name, matched as a substring (case-insensitive)")
    parser.add_argument("--exact", action="store_true", help="match the whole name")
    args = parser.parse_args()
    query = args.name.lower()

    hits = []
    for product_dir in sorted((ROOT / "reports").iterdir()):
        run_dir, run = report.last_run(product_dir.name)
        for entry in run.get("sboms") or []:
            path = run_dir / entry["sbom"]
            if not path.exists():
                continue
            for c in json.loads(path.read_text(encoding="utf-8")).get("components", []):
                name = c.get("name", "")
                if (name.lower() == query) if args.exact else (query in name.lower()):
                    hits.append((run["product"], entry["label"], name, c.get("version", ""), c.get("purl", "")))

    if not hits:
        print(f"No component matching {args.name!r} in any stored SBOM.")
        return
    width = max(len(f"{p} / {label}") for p, label, *_ in hits)
    for product, label, name, version, purl in hits:
        print(f"{f'{product} / {label}':<{width}}  {name} {version}  {purl}")


if __name__ == "__main__":
    main()
