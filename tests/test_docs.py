"""
test_docs.py — documentation that disagrees with the code is a defect.

Two kinds of drift, both of which have actually happened here:

  1. **Figures quoted in prose going stale.** The README's catalogue counts
     disagreed with `connectors/snapshot/servers.json` across three separate
     sessions: nine of the twenty category figures were wrong, and the total
     was 9,576 against a real 9,555. Nobody notices, because a number in a
     README is not executed. These tests execute it.

  2. **Generated assets drifting from their source.** `docs/diagrams.md` and
     `docs/diagrams/*.svg` are produced from `docs/diagrams.html`. A figure
     edited in one place and not the other ships as two versions of the same
     diagram, and the reader has no way to know which is current.

    python tests/test_docs.py
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

README = ROOT / "README.md"
SNAPSHOT = ROOT / "connectors" / "snapshot" / "servers.json"
DIAGRAM_SRC = ROOT / "docs" / "diagrams" / "full.html"
DIAGRAM_MD = ROOT / "docs" / "diagrams.md"
DIAGRAM_DIR = ROOT / "docs" / "diagrams"


def _snapshot() -> dict:
    return json.loads(SNAPSHOT.read_text())


def test_the_readme_catalogue_total_matches_the_snapshot():
    total = _snapshot()["counts"]["total"]
    m = re.search(r"## The catalog — ([\d,]+) entries", README.read_text())
    assert m, "the README no longer states a catalogue total"
    stated = int(m.group(1).replace(",", ""))
    assert stated == total, (
        f"README says {stated:,} catalogue entries, snapshot has {total:,}. "
        f"Regenerate the figure rather than editing it by hand.")


def test_the_readme_category_counts_match_the_snapshot():
    counts = Counter(s["category"] for s in _snapshot()["servers"])
    text = README.read_text()
    wrong = []
    for name, n in counts.items():
        m = re.search(rf"`{re.escape(name)}`\s+([\d,]+)", text)
        if not m:
            continue                      # not every category need be listed
        stated = int(m.group(1).replace(",", ""))
        if stated != n:
            wrong.append(f"{name}: README {stated:,}, snapshot {n:,}")
    assert not wrong, "README category counts are stale:\n  " + "\n  ".join(wrong)


def test_the_readme_kind_counts_match_the_snapshot():
    c = _snapshot()["counts"]
    text = README.read_text()
    for kind in ("routable", "wrappable", "installable"):
        m = re.search(rf"`{kind}`\s*\(([\d,]+)\)", text)
        if not m:
            continue
        stated = int(m.group(1).replace(",", ""))
        assert stated == c[kind], (
            f"README says {kind} is {stated:,}, snapshot says {c[kind]:,}")


def test_the_readme_links_to_the_diagrams():
    """
    The diagrams are the fastest way for a newcomer to understand what XCP
    does. A document nobody can find from the front page is a document that
    does not exist.
    """
    text = README.read_text()
    assert "docs/diagrams.md" in text, (
        "the README does not link to the technical diagrams")
    assert "docs/diagrams/full.html" in text, (
        "the README does not mention the full narrative version")


def test_the_readme_uses_absolute_links_for_the_diagrams():
    """
    pyproject.toml uses this README as the PyPI long description, where a
    relative link resolves against pypi.org and 404s. The diagrams are the
    entry point a newcomer is most likely to follow, so those links in
    particular must survive being rendered somewhere other than GitHub.
    """
    text = README.read_text()
    assert "https://github.com/AGI-Gateway/XCP/blob/main/docs/diagrams.md" in text, (
        "the README's diagram links are relative; they break wherever the "
        "README is rendered outside the repository, PyPI included")


def test_the_diagrams_are_linked_above_the_fold():
    """
    A document findable only in a list two hundred lines down is a document
    most readers never reach.
    """
    text = README.read_text()
    i = text.index("docs/diagrams.md")
    assert text[:i].count("\n") < 60, (
        f"the first diagram link is {text[:i].count(chr(10))} lines in; it "
        f"should be near the top where a newcomer will see it")


def test_the_site_serves_both_the_index_and_the_narrative():
    """
    These collided twice while being wired up. With mkdocs directory URLs on,
    docs/diagrams.md is served at /diagrams/ and its relative image paths gain
    a level, so every figure 404s on the site while rendering correctly on
    GitHub -- the worse way round for a defect to be found. With them off,
    diagrams.md renders to diagrams.html and collided with the narrative file
    of the same name, which mkdocs silently excluded.
    """
    nav = (ROOT / "mkdocs.yml").read_text()
    assert "use_directory_urls: false" in nav, (
        "directory URLs shift every relative path in diagrams.md by one level, "
        "breaking all fourteen figures on the site")
    assert DIAGRAM_SRC.exists(), (
        f"{DIAGRAM_SRC.relative_to(ROOT)} is missing; it must not share a name "
        f"with the page diagrams.md renders to")
    assert not (ROOT / "docs" / "diagrams.html").exists(), (
        "docs/diagrams.html is back and will collide with the page rendered "
        "from diagrams.md; mkdocs excludes one of them silently")


def test_every_readme_relative_link_resolves():
    """A dead link in the front page is the cheapest possible defect to find."""
    broken = []
    for m in re.finditer(r"\]\(((?!https?:|#|mailto:)[^)#]+)", README.read_text()):
        target = ROOT / m.group(1).strip()
        if not target.exists():
            broken.append(m.group(1))
    assert not broken, f"README links to files that do not exist: {broken}"


def test_the_diagram_assets_match_their_source():
    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "generate-diagram-assets.py"),
         "--check"], capture_output=True, text=True, cwd=str(ROOT))
    assert r.returncode == 0, (
        "docs/diagrams.md or docs/diagrams/*.svg differ from what "
        "docs/diagrams.html produces.\n"
        "Run: python scripts/generate-diagram-assets.py\n" + r.stderr)


def test_every_figure_became_a_standalone_svg():
    figures = len(re.findall(r"<figure>", DIAGRAM_SRC.read_text()))
    svgs = len(list(DIAGRAM_DIR.glob("*.svg")))
    assert svgs == figures, (
        f"{figures} figures in the source, {svgs} standalone SVGs. "
        f"Regenerate.")
    assert figures >= 14, f"only {figures} figures; the document has shrunk"


def test_each_standalone_svg_is_self_contained_and_themed():
    """
    An SVG referenced as an image is an independent document: it inherits none
    of the embedding page's CSS. Without its own palette every colour token
    resolves to nothing, `currentColor` falls back to the initial value, and
    the figure is invisible on a dark background — which is what GitHub serves
    to a large share of its readers.
    """
    problems = []
    for f in sorted(DIAGRAM_DIR.glob("*.svg")):
        s = f.read_text()
        checks = {
            "xmlns (without it browsers refuse to render it, silently)":
                'xmlns="http://www.w3.org/2000/svg"' in s,
            "intrinsic size": bool(re.search(r"<svg[^>]*\bwidth=\"\d", s)),
            "its own stylesheet": "<style>" in s,
            "a dark palette": "prefers-color-scheme: dark" in s,
            "color set, so currentColor resolves": "color: var(--fg)" in s,
            "an opaque background": 'fill="var(--bg)"' in s,
            "no unresolvable font vars": "var(--sans)" not in s,
            "no external references": "http" not in s.replace(
                'xmlns="http://www.w3.org/2000/svg"', ""),
        }
        missing = [k for k, v in checks.items() if not v]
        if missing:
            problems.append(f"{f.name}: missing {missing}")
    assert not problems, "\n  ".join([""] + problems)


def test_the_markdown_references_every_svg_that_exists():
    md = DIAGRAM_MD.read_text()
    for f in sorted(DIAGRAM_DIR.glob("*.svg")):
        assert f.name in md, f"{f.name} is not referenced by docs/diagrams.md"


def test_the_markdown_does_not_rely_on_inline_svg():
    """
    GitHub sanitises Markdown and strips inline <svg>. A document that embedded
    the figures directly would render as a page of captions with nothing
    between them, and would look fine locally.
    """
    md = DIAGRAM_MD.read_text()
    assert "<svg" not in md, (
        "docs/diagrams.md contains inline SVG, which GitHub strips; reference "
        "the standalone files as images instead")
    assert md.count("<img src=\"diagrams/") >= 14


def test_the_documentation_site_lists_the_diagrams():
    nav = (ROOT / "mkdocs.yml").read_text()
    assert "diagrams.md" in nav, "mkdocs nav does not include the diagrams"


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn(); print(f"  PASS {name}"); passed += 1
        except Exception as e:
            print(f"  FAIL {name}: {e}"); failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
