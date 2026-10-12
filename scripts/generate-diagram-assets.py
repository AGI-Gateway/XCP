#!/usr/bin/env python3
"""
generate-diagram-assets.py — make the technical diagrams readable in the repo.

THE PROBLEM THIS SOLVES
-----------------------
`docs/diagrams/full.html` is one self-contained page: fourteen inline SVG figures
styled by the page's own stylesheet, with a light and a dark palette. That works
when the page is served -- by mkdocs, or opened from a clone -- and not at all
when someone browses the repository on GitHub, for two independent reasons:

  1. GitHub sanitises Markdown. Inline `<svg>` is stripped, so a Markdown
     document containing the figures renders as a page of captions with nothing
     between them.

  2. An SVG referenced as an image is an independent document. It does not
     inherit the embedding page's CSS, so `currentColor` resolves to the
     initial value and every `var(--accent)` resolves to nothing. The figures
     come out black-on-transparent at best, and invisible on a dark background
     at worst -- which is what GitHub serves to about half its users.

So each figure is extracted into a standalone `.svg` that carries its own
stylesheet, its own palette for both colour schemes, and its own background.
`docs/diagrams.md` then references them as images, which GitHub does render.

WHY GENERATE RATHER THAN HAND-MAINTAIN
--------------------------------------
Fourteen figures, each needing a style block kept in step with the page's
palette, is fifteen places for a colour to drift. The tokens and the SVG helper
classes are read OUT of `docs/diagrams.html` here, so the standalone files and
the page cannot disagree: there is one definition and the copies are derived.

Committed and checked, like every other generated artifact in this repository:

    python scripts/generate-diagram-assets.py --check

THE THREE THINGS A STANDALONE SVG NEEDS THAT AN INLINE ONE DOES NOT
-------------------------------------------------------------------
  * An `xmlns` attribute. Without it the file is not a valid SVG document and
    browsers refuse to render it as an image, silently.

  * An explicit background rectangle. An image-embedded SVG is transparent, and
    this document's figures are drawn in a foreground colour. On GitHub's dark
    theme, dark strokes on a transparent ground are invisible. The rect is
    painted from the same `--bg` token the page uses.

  * `color` set on `:root`. `currentColor` -- which most of the strokes and all
    of the text use, precisely so the figures follow the reader's theme --
    resolves against the `color` property. Inline, that inherits from `body`.
    Standalone, there is no body, so it must be set or every `currentColor`
    falls back to the initial value.

Fonts are substituted for system stacks rather than kept as `var(--sans)`,
because an image-embedded SVG cannot load an external stylesheet: a Google
Fonts link in here is a silent no-op, and the glyphs would fall back anyway.
"""

from __future__ import annotations

import argparse
import html
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "docs" / "diagrams" / "full.html"
OUT_DIR = ROOT / "docs" / "diagrams"
OUT_MD = ROOT / "docs" / "diagrams.md"

#: Concrete stacks. An image-embedded SVG cannot fetch webfonts, so naming
#: IBM Plex here would render as the fallback with extra steps.
SANS = ("ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,"
        "'Helvetica Neue',Arial,sans-serif")
MONO = ("ui-monospace,'SF Mono',SFMono-Regular,Menlo,Consolas,"
        "'Liberation Mono',monospace")


def extract_tokens(css: str) -> tuple[dict[str, str], dict[str, str]]:
    """
    Pull the light and dark palettes out of the page's stylesheet.

    Read rather than restated: a hand-copied palette is a palette that drifts,
    and these files exist to look identical to the page.
    """
    def block(pattern: str) -> dict[str, str]:
        m = re.search(pattern, css, re.S)
        if not m:
            raise SystemExit(f"could not find the CSS block {pattern!r} in "
                             f"{SOURCE.name}; the stylesheet has been "
                             f"restructured and this script needs updating")
        return dict(re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", m.group(1)))

    light = block(r"^\s*:root\{(.*?)\}")
    dark = block(r":root\[data-theme=\"dark\"\]\{(.*?)\}")
    return light, dark


def extract_helpers(css: str) -> str:
    """The `.bx`, `.tm`, `.ln` family that the figures are drawn with."""
    m = re.search(r"/\* svg type helpers \*/(.*?)\n\n", css, re.S)
    if not m:
        raise SystemExit("could not find the svg helper classes")
    rules = m.group(1)
    rules = rules.replace("var(--sans)", SANS).replace("var(--mono)", MONO)
    return "\n".join("    " + line.strip()
                     for line in rules.splitlines() if line.strip())


def stylesheet(light: dict[str, str], dark: dict[str, str],
               helpers: str) -> str:
    def decls(tokens: dict[str, str]) -> str:
        wanted = ("--bg", "--surface", "--surface-2", "--fg", "--fg-2",
                  "--muted", "--rule", "--rule-2", "--accent", "--accent-wash",
                  "--refuse", "--refuse-wash")
        return " ".join(f"{k}:{tokens[k].strip()};"
                        for k in wanted if k in tokens)

    # `color` is set so currentColor resolves; see the module docstring.
    return f"""  <style>
    :root {{ {decls(light)} color: var(--fg); }}
    @media (prefers-color-scheme: dark) {{
      :root {{ {decls(dark)} color: var(--fg); }}
    }}
{helpers}
  </style>"""


def slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return re.sub(r"-{2,}", "-", s)[:60]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--check", action="store_true",
                    help="fail if the committed output differs (for CI)")
    args = ap.parse_args()

    if not SOURCE.exists():
        raise SystemExit(f"{SOURCE.relative_to(ROOT)} is missing; it is the "
                         f"source these assets are derived from")

    src = SOURCE.read_text()
    css = re.search(r"<style>(.*?)</style>", src, re.S).group(1)
    light, dark = extract_tokens(css)
    helpers = extract_helpers(css)
    style = stylesheet(light, dark, helpers)

    # Sections, in document order, so the Markdown mirrors the page.
    sections = re.findall(
        r'<section class="sec" id="([^"]+)">.*?<span class="sec-no">'
        r'([^<]+)</span>\s*<h2>(.*?)</h2>', src, re.S)
    section_of_id = {sid: (no, html.unescape(re.sub(r"<[^>]+>", "", h2)))
                     for sid, no, h2 in sections}

    # Each figure with the section it sits in, its caption label and claim.
    figures = []
    for m in re.finditer(r'<figure>(.*?)</figure>', src, re.S):
        chunk = m.group(1)
        svg_m = re.search(r"<svg\b.*?</svg>", chunk, re.S)
        if not svg_m:
            continue
        cap = re.search(r"<figcaption><b>([^<]+)</b><span>(.*?)</span>",
                        chunk, re.S)
        label = cap.group(1).strip() if cap else f"Fig {len(figures)+1}"
        claim = re.sub(r"\s+", " ",
                       re.sub(r"<[^>]+>", "", cap.group(2))).strip() if cap else ""
        # Which section contains this figure.
        before = src[:m.start()]
        sid = (re.findall(r'<section class="sec" id="([^"]+)"', before) or
               ["architecture"])[-1]
        figures.append({"label": label, "claim": html.unescape(claim),
                        "svg": svg_m.group(0), "section": sid})

    if not figures:
        raise SystemExit("no figures found; the page structure has changed")

    written: dict[Path, tuple[str, str]] = {}

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for fig in figures:
        svg = fig["svg"]
        vb = re.search(r'viewBox="0 0 ([\d.]+) ([\d.]+)"', svg)
        w, h = vb.group(1), vb.group(2)

        # xmlns, and an intrinsic size so the image has an aspect ratio before
        # CSS touches it.
        svg = svg.replace(
            "<svg ",
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" '
            f'height="{h}" ', 1)
        # Stylesheet and background, as the first children.
        bg = (f'  <rect width="100%" height="100%" fill="var(--bg)"/>')
        svg = re.sub(r"(<svg[^>]*>)", r"\1\n" + style + "\n" + bg, svg, count=1)

        num = fig["label"].replace("Fig ", "").replace(".", "-")
        name = f"fig-{num}-{slug(fig['claim'][:40] or fig['section'])}.svg"
        fig["file"] = name
        path = OUT_DIR / name
        before_text = path.read_text() if path.exists() else ""
        path.write_text(svg + "\n")
        written[path] = (before_text, svg + "\n")

    # ── the Markdown index ────────────────────────────────────────────────
    md = [
        "# Technical diagrams",
        "",
        "<!-- Generated by scripts/generate-diagram-assets.py from",
        "     docs/diagrams/full.html. Do not edit. -->",
        "",
        f"{len(figures)} figures covering the mechanisms XCP's per-call "
        "authority decision rests on. Each is traced from the code it "
        "describes rather than from the prose about it.",
        "",
        "Every figure below is a standalone SVG that carries its own palette "
        "for light and dark, so it is legible whichever theme you are reading "
        "in. The same figures with their full narrative are in "
        "[`diagrams/full.html`](diagrams/full.html) — open it from a clone, "
        "or read it on the documentation site.",
        "",
        "## Contents",
        "",
    ]
    seen: list[str] = []
    for fig in figures:
        if fig["section"] not in seen:
            seen.append(fig["section"])
    for sid in seen:
        no, title = section_of_id.get(sid, ("", sid))
        md.append(f"- [{no} — {title}](#{slug(no + ' ' + title)})")
    md.append("")

    current = None
    for fig in figures:
        if fig["section"] != current:
            current = fig["section"]
            no, title = section_of_id.get(current, ("", current))
            md += ["", f"## {no} — {title}", ""]
        md += [
            f"### {fig['label']}",
            "",
            f'<img src="diagrams/{fig["file"]}" alt="{fig["claim"][:200]}" '
            f'width="100%">',
            "",
            f"{fig['claim']}",
            "",
        ]

    md += [
        "---",
        "",
        "## Keeping these honest",
        "",
        "These files are generated. `docs/diagrams.html` is the source, and "
        "CI runs:",
        "",
        "```",
        "python scripts/generate-diagram-assets.py --check",
        "```",
        "",
        "so a figure edited in one place and not the other fails the build "
        "rather than shipping as two versions of the same diagram.",
        "",
    ]
    text = "\n".join(md)
    before_md = OUT_MD.read_text() if OUT_MD.exists() else ""
    OUT_MD.write_text(text)
    written[OUT_MD] = (before_md, text)

    changed = [p for p, (b, a) in written.items() if b != a]

    total = sum(len(v[1]) for v in written.values())
    print(f"  {len(figures)} figures -> {OUT_DIR.relative_to(ROOT)}/")
    print(f"  index           -> {OUT_MD.relative_to(ROOT)}")
    print(f"  total written      {total / 1024:.0f} KiB")

    if args.check and changed:
        print("\nThe committed diagram assets are stale. Regenerate:",
              file=sys.stderr)
        print("    python scripts/generate-diagram-assets.py", file=sys.stderr)
        for c in changed:
            print(f"  changed: {c.relative_to(ROOT)}", file=sys.stderr)
        return 1
    for c in changed:
        print(f"  updated {c.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
