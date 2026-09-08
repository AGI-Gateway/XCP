#!/usr/bin/env python3
"""
sync-docs.py — mirror component READMEs into docs/ for the MkDocs site.

Some documents are the canonical README for a directory *and* a page on the docs
site. Rather than duplicate them by hand, mirror them here and rewrite the
repo-relative links so both views work: relative paths inside the repo, and
GitHub URLs for anything that isn't a docs page.

    python scripts/sync-docs.py        (or: make docs-sync)
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO_URL = "https://github.com/AGI-Gateway/XCP/blob/main"

MIRROR = {
    "trust/README.md": "trust-lattice.md",
    "discovery/README.md": "discovery.md",
    "CONTRIBUTING.md": "contributing.md",
    "GOVERNANCE.md": "governance.md",
    "ROADMAP.md": "roadmap.md",
}

DOCS_PAGES = {
    "docs/security.md": "security.md",
    "docs/self-serve.md": "self-serve.md",
    "docs/architecture.md": "architecture.md",
    "docs/protocol.md": "protocol.md",
    "../docs/self-serve.md": "self-serve.md",
    "../docs/security.md": "security.md",
    "security.md": "security.md",
    "self-serve.md": "self-serve.md",
    "architecture.md": "architecture.md",
    "protocol.md": "protocol.md",
    "trust-lattice.md": "trust-lattice.md",
    "receipts.md": "receipts.md",
    "trust-firewall.md": "trust-firewall.md",
    "discovery.md": "discovery.md",
    "deployment.md": "deployment.md",
    "index.md": "index.md",
}

LINK = re.compile(r"\]\(([^)]+)\)")


def rewrite(md: str) -> str:
    def repl(m: re.Match) -> str:
        target = m.group(1)
        if target.startswith(("http://", "https://", "#", "mailto:")):
            return m.group(0)
        base = target.split("#")[0]
        if base in DOCS_PAGES:
            return f"]({DOCS_PAGES[base]})"
        clean = base.lstrip("./")
        while clean.startswith("../"):
            clean = clean[3:]
        return f"]({REPO_URL}/{clean})"
    return LINK.sub(repl, md)


def main() -> int:
    docs = ROOT / "docs"
    for src, dst in MIRROR.items():
        s = ROOT / src
        if not s.exists():
            print(f"  skip {src} (missing)")
            continue
        (docs / dst).write_text(rewrite(s.read_text()))
        print(f"  {src} -> docs/{dst}")
    for page in ("protocol.md", "security.md", "architecture.md", "self-serve.md"):
        p = docs / page
        if p.exists():
            p.write_text(rewrite(p.read_text()))
            print(f"  rewrote links in docs/{page}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
