"""
python -m sdk — run this implementation against the committed vectors.

The same entry point every language's runner mirrors, so "does this SDK agree
with the protocol" has one answer shaped the same way in five ecosystems:

    python -m sdk                 # Python
    node sdk/typescript/vectors.mjs
    go test ./sdk/go/...
    mvn -q -f sdk/java/pom.xml test
    dotnet test sdk/dotnet
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sdk import check_python, vector_names  # noqa: E402


def main() -> int:
    print(f"vectors: {', '.join(vector_names())}\n")
    report = check_python()
    print(report.summary())
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
