#!/usr/bin/env python3
"""
Render a markdown investigation report to a styled PDF using Chrome
headless. Stdlib only — no pandoc/wkhtmltopdf needed. Tested against
the investigate-workspace-activity skill's report template.

Usage:
    python3 md_to_pdf.py <input.md>                  # writes alongside as .pdf
    python3 md_to_pdf.py <input.md> -o <output.pdf>
"""

import argparse
import html
import os
import re
import shutil
import subprocess
import sys
import tempfile


CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    shutil.which("google-chrome") or "",
    shutil.which("chromium") or "",
]


def find_chrome():
    for path in CHROME_CANDIDATES:
        if path and os.path.exists(path):
            return path
    sys.exit("Could not find Chrome/Chromium/Edge for PDF rendering. "
             "Install Google Chrome or pass --html-only and convert separately.")


def inline(text):
    text = html.escape(text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', text)
    return text


def md_to_html_body(md):
    lines = md.split("\n")
    out = []
    table_rows = []
    in_list = None  # "ul", "ol", or None

    def flush_table():
        nonlocal table_rows
        if not table_rows:
            return
        rows = [r for r in table_rows
                if not all(re.fullmatch(r":?-+:?", c) for c in r)]
        if rows:
            header, body = rows[0], rows[1:]
            out.append("<table>")
            out.append("<thead><tr>"
                       + "".join(f"<th>{inline(c)}</th>" for c in header)
                       + "</tr></thead>")
            out.append("<tbody>")
            for row in body:
                out.append("<tr>"
                           + "".join(f"<td>{inline(c)}</td>" for c in row)
                           + "</tr>")
            out.append("</tbody></table>")
        table_rows = []

    def flush_list():
        nonlocal in_list
        if in_list:
            out.append(f"</{in_list}>")
            in_list = None

    for line in lines:
        if line.startswith("|") and line.rstrip().endswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            table_rows.append(cells)
            continue
        else:
            flush_table()

        m = re.match(r"^(\d+)\.\s+(.*)$", line)
        if m:
            if in_list != "ol":
                flush_list()
                out.append("<ol>")
                in_list = "ol"
            out.append(f"<li>{inline(m.group(2))}</li>")
            continue

        if line.startswith("- "):
            if in_list != "ul":
                flush_list()
                out.append("<ul>")
                in_list = "ul"
            out.append(f"<li>{inline(line[2:])}</li>")
            continue

        flush_list()

        if line.startswith("### "):
            out.append(f"<h3>{inline(line[4:])}</h3>")
        elif line.startswith("## "):
            out.append(f"<h2>{inline(line[3:])}</h2>")
        elif line.startswith("# "):
            out.append(f"<h1>{inline(line[2:])}</h1>")
        elif line.strip() == "---":
            out.append("<hr>")
        elif line.strip() == "":
            out.append("")
        else:
            out.append(f"<p>{inline(line)}</p>")

    flush_table()
    flush_list()
    return "\n".join(out)


CSS = """
@page { size: Letter; margin: 0.7in 0.8in; }
body { font-family: -apple-system, "Helvetica Neue", Helvetica, Arial, sans-serif;
       font-size: 10.5pt; line-height: 1.45; color: #1d1d1f; }
h1 { font-size: 20pt; margin: 0 0 0.4em 0; border-bottom: 2px solid #333; padding-bottom: 0.2em; }
h2 { font-size: 14pt; margin: 1.4em 0 0.4em 0; border-bottom: 1px solid #ddd; padding-bottom: 0.2em; }
h3 { font-size: 11.5pt; margin: 1.2em 0 0.3em 0; color: #333; }
p  { margin: 0.4em 0; }
ul, ol { margin: 0.4em 0 0.4em 1.4em; }
li { margin: 0.18em 0; }
hr { border: none; border-top: 1px solid #ccc; margin: 1.2em 0; }
code { font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 9.5pt;
       background: #f4f4f6; padding: 1px 4px; border-radius: 3px; }
table { border-collapse: collapse; margin: 0.6em 0; width: 100%; font-size: 9.5pt; }
th, td { border: 1px solid #d1d1d6; padding: 5px 8px; text-align: left; vertical-align: top; }
th { background: #f4f4f6; font-weight: 600; }
tr:nth-child(even) td { background: #fafafa; }
strong { color: #111; }
a { color: #0a5cb3; text-decoration: none; }
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", help="Path to markdown file")
    ap.add_argument("-o", "--output", help="Output PDF path (default: input.pdf)")
    args = ap.parse_args()

    if not os.path.exists(args.input):
        sys.exit(f"Input not found: {args.input}")

    out_path = args.output or os.path.splitext(args.input)[0] + ".pdf"
    out_path = os.path.abspath(out_path)

    md = open(args.input).read()
    body = md_to_html_body(md)
    full_html = (f"<!doctype html><html><head><meta charset='utf-8'>"
                 f"<style>{CSS}</style></head><body>{body}</body></html>")

    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as f:
        f.write(full_html)
        tmp_html = f.name

    chrome = find_chrome()
    cmd = [
        chrome, "--headless", "--disable-gpu", "--no-pdf-header-footer",
        f"--print-to-pdf={out_path}", f"file://{tmp_html}",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    os.unlink(tmp_html)
    if proc.returncode != 0 or not os.path.exists(out_path):
        sys.stderr.write(proc.stderr)
        sys.exit(f"Chrome failed to produce PDF (exit {proc.returncode})")
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
