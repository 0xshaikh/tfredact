#!/usr/bin/env python3
"""Render real ``tfredact`` CLI output into screenshots.

Everything here is captured by actually running the CLI as a subprocess -- the
screenshots in the README cannot drift from the behaviour they claim to show.
HTML output is produced from the same ANSI-tokeniser as the PNGs.

Usage: python tools/make_screenshots.py
"""

from __future__ import annotations

import html
import io
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
OUT = ROOT / "docs" / "img"

# (name, argv, one-line caption for the HTML page)
SHOTS = [
    ("scan-clean", ["scan", "examples/clean.tfstate", "--no-color"],
     "``tfredact scan`` on a state file with no secrets -- exit 0."),
    ("scan-state", ["scan", "examples/sample.tfstate", "--no-color"],
     "``tfredact scan`` on ``examples/sample.tfstate``: 32 findings across 18 "
     "types, each tagged with whether terraform had marked it sensitive."),
    ("audit", ["audit", "examples/main.tf", "--no-color"],
     "``tfredact audit`` on ``examples/main.tf``: variables and outputs that "
     "look like secrets but are not declared ``sensitive = true``."),
]

BG = (13, 17, 23)
FG = (230, 237, 243)

_ANSI_RE = re.compile(r"\033\[([0-9;]*)m")

# Terminal palette -> (RGB, css hex)
COLORS = {
    "31": ((255, 123, 114), "#ff7b72"),
    "32": ((126, 231, 135), "#7ee787"),
    "33": ((240, 198, 116), "#f0c674"),
    "34": ((121, 192, 255), "#79c0ff"),
    "35": ((200, 143, 238), "#c88fee"),
    "36": ((91, 214, 217), "#5bd6d9"),
    "2": ((139, 148, 158), "#8b949e"),
    "90": ((110, 118, 129), "#6e7681"),
}


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def tokenise(line: str):
    """Yield ``(text, css_or_rgb, rgb)`` pieces, carrying colour state across
    resets the way a real terminal does."""
    pos = 0
    active = None
    for match in _ANSI_RE.finditer(line):
        if match.start() > pos:
            yield line[pos:match.start()], active
        params = match.group(1).split(";") if match.group(1) else ["0"]
        current = active
        for param in params:
            if param in ("0", "39"):
                current = None
            elif param in COLORS:
                current = param
        active = current
        pos = match.end()
    if pos < len(line):
        yield line[pos:], active


def _clip_ansi(line: str, max_cols: int) -> str:
    """Truncate an ANSI line at ``max_cols`` visible characters, closing any
    colour sequence that was left open."""
    kept = []
    visible = 0
    for piece, _code in tokenise(line):
        if visible + len(piece) > max_cols:
            take = max_cols - visible
            kept.append(piece[:take])
            break
        kept.append(piece)
        visible += len(piece)
    return "".join(kept) + "\033[0m"


def to_html(text: str) -> str:
    """Convert ANSI terminal output into an HTML ``<pre>`` block."""
    lines = []
    for raw in text.rstrip("\n").split("\n"):
        parts = []
        for piece, code in tokenise(raw):
            esc = html.escape(piece)
            if not esc:
                continue
            css = COLORS.get(code or "", (None, None))[1]
            if css:
                esc = f'<span style="color:{css}">{esc}</span>'
            parts.append(esc)
        lines.append("".join(parts))
    return "\n".join(lines)


def to_png(text: str, font_path: str, size: int = 13, max_cols: int = 128) -> bytes:
    """Rasterise ANSI terminal output.

    Lines are clipped at ``max_cols`` so the widest summary line doesn't produce
    an unusably wide image; the clipped text is otherwise verbatim.
    """
    from PIL import Image, ImageDraw, ImageFont

    font = ImageFont.truetype(font_path, size)
    lines = []
    for raw in text.rstrip("\n").split("\n"):
        plain = strip_ansi(raw)
        if len(plain) > max_cols:
            cut = _clip_ansi(raw, max_cols)
            plain = cut + " …"
            lines.append(cut)
        else:
            lines.append(raw)
    width = min(max(len(strip_ansi(line)) for line in lines), max_cols + 2)
    line_h = size + 4
    pad_v, pad_l, pad_r = 30, 26, 26

    probe = Image.new("RGB", (12, 12))
    draw_probe = ImageDraw.Draw(probe)
    char_w = draw_probe.textbbox((0, 0), "M", font=font)[2]

    img = Image.new("RGB", (char_w * (width + 2) + pad_l + pad_r,
                            line_h * len(lines) + 2 * pad_v), BG)
    draw = ImageDraw.Draw(img)

    y = pad_v
    for line in lines:
        x = pad_l
        for piece, code in tokenise(line):
            label = piece
            rgb = COLORS.get(code or "", (FG, None))[0]
            draw.text((x, y), label, fill=rgb, font=font)
            x += char_w * len(label)
        y += line_h

    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def capture(bin_path: str, argv: list[str]) -> str:
    """Run the CLI. Falls back to the module entry point."""
    cmd = [bin_path, *argv]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if proc.stdout or proc.stderr:
            return proc.stdout + proc.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    proc = subprocess.run(
        [sys.executable, "-m", "tfredact.cli", *argv],
        capture_output=True, text=True, timeout=120, cwd=str(ROOT),
    )
    return proc.stdout + proc.stderr


def page(title: str, caption: str, body_html: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ margin:0; padding:48px 0; background:#010409; color:#e6edf3;
         font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif; }}
  .wrap {{ max-width:1080px; margin:0 auto; padding:0 24px; }}
  h1 {{ font-size:26px; margin:0 0 6px; }}
  p.sub {{ color:#8b949e; margin:0 0 28px; }}
  .term {{ background:#0d1117; border:1px solid #21262d; border-radius:10px;
           box-shadow:0 24px 48px rgba(0,0,0,.5); overflow-x:auto; padding:26px; }}
  pre {{ margin:0; font-family:"SF Mono",Menlo,Consolas,"DejaVu Sans Mono",monospace;
         font-size:13.5px; line-height:1.55; white-space:pre; }}
  .note {{ color:#6e7681; font-size:13px; margin-top:14px; line-height:1.6; }}
  code {{ background:#161b22; padding:1px 5px; border-radius:4px; font-size:12.5px; }}
</style></head><body><div class="wrap">
  <h1>{html.escape(title)}</h1>
  <p class="sub">Live output, captured from the CLI.</p>
  <div class="term"><pre>{body_html}</pre></div>
  <p class="note">{html.escape(caption)}</p>
</div></body></html>
"""


def find_font() -> str:
    for path in ("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
                 "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
                 "/System/Library/Fonts/Menlo.ttc",
                 "C:/Windows/Fonts/consola.ttf"):
        if os.path.exists(path):
            return path
    raise SystemExit("no monospace font found; install fonts-dejavu")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    font_path = find_font()

    bin_path = str(Path(sys.executable).parent / "tfredact")
    if not os.path.exists(bin_path):
        bin_path = "tfredact"

    n_png = 0
    for name, argv, caption in SHOTS:
        text = capture(bin_path, argv)
        if len(strip_ansi(text).strip()) < 20:
            print(f"WARNING: empty output for {name}", file=sys.stderr)
            continue
        (OUT / f"{name}.html").write_text(page(f"tfredact — {name}", caption,
                                               to_html(text)), encoding="utf-8")
        (OUT / f"{name}.png").write_bytes(to_png(text, font_path))
        n_png += 1
        print(f"wrote docs/img/{name}.html + .png ({len(text.splitlines())} lines)")
    print(f"{n_png} screenshots rendered")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
