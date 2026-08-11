#!/usr/bin/env python3
"""Render paper.md to a readable, camera-ready PDF with WeasyPrint.

Readability pass: contents with page numbers, running head that tracks the
current section, larger type on a looser leading, styled figure/table captions,
zebra tables, and page-break control so headings, figures and captions do not
separate from what they belong to. Content is not altered -- this file only
decides how paper.md is set.

No external resources: the CSS is inline and no webfont is fetched, so the
render is deterministic offline.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import markdown
import weasyprint

HERE = Path(__file__).resolve().parent
LOCK = HERE / "RENDERER.lock.json"
CANONICAL_PDF = HERE / "Evidence-Backed Authority Verification.pdf"
CANONICAL_HASH = HERE / "Evidence-Backed Authority Verification.sha256"

lock = json.loads(LOCK.read_text(encoding="utf-8"))
actual = {
    "python_markdown": markdown.__version__,
    "weasyprint": weasyprint.__version__,
}
if lock.get("versions") != actual:
    raise SystemExit(f"renderer version mismatch: expected {lock['versions']}, got {actual}")

src = (HERE / "paper.md").read_text(encoding="utf-8")

lines = src.split("\n")
title = lines[0].lstrip("# ").strip()
rest = "\n".join(lines[1:])
status_m = re.search(r"\*\*Status:\*\*(.+?)\n\n", rest, re.S)
status = status_m.group(1).strip() if status_m else ""
rest = rest.replace(status_m.group(0), "", 1) if status_m else rest
rest = rest.lstrip("\n- ")

html_body = markdown.markdown(
    rest,
    extensions=["tables", "fenced_code", "sane_lists", "attr_list", "toc"],
    output_format="html5",
)

# --- captions: a paragraph that is only a bolded "Figure n:" / "Table n:" lead
# is the caption for the block that follows, so tag it and glue it down.
html_body = re.sub(
    r"<p><strong>(Figure|Table) (\d+):(.*?)</strong>(.*?)</p>",
    r'<p class="caption"><strong>\1 \2:</strong>\3\4</p>',
    html_body,
    flags=re.S,
)

# --- contents, built from the rendered headings so ids and text always agree
entries = re.findall(r'<(h2|h3) id="([^"]+)">(.*?)</\1>', html_body, flags=re.S)
toc_rows = []
for tag, hid, text in entries:
    label = re.sub(r"<[^>]+>", "", text).strip()
    if label.lower() == "contents":
        continue
    toc_rows.append(f'<li class="toc-{tag}"><a href="#{hid}">{label}</a></li>')
toc_html = (
    '<div class="toc-block"><h2 class="unnumbered">Contents</h2>'
    '<ul class="toc-list">' + "".join(toc_rows) + "</ul></div>"
)

# Contents goes after the reader's guide, immediately before the abstract.
abstract_anchor = re.search(r'<h2 id="[^"]*abstract[^"]*">', html_body)
if abstract_anchor:
    i = abstract_anchor.start()
    html_body = html_body[:i] + toc_html + html_body[i:]
else:
    html_body = toc_html + html_body

CSS = """
@page {
  size: A4;
  margin: 21mm 20mm 19mm 20mm;
  @top-left  {
    content: string(section);
    font: italic 8pt Georgia, 'Times New Roman', serif; color: #666;
  }
  @top-right {
    content: "Evidence-Backed Authority Verification";
    font: italic 8pt Georgia, 'Times New Roman', serif; color: #666;
  }
  @bottom-center {
    content: counter(page) " / " counter(pages);
    font: 8pt Georgia, 'Times New Roman', serif; color: #666;
  }
}
@page :first { @top-left { content: ""; } @top-right { content: ""; } }

html { font-size: 10.5pt; }
body {
  font-family: Georgia, 'Times New Roman', serif;
  line-height: 1.5;
  text-align: justify;
  hyphens: auto;
  color: #16181d;
}

.title {
  font-size: 20pt; line-height: 1.2; font-weight: 700;
  text-align: left; margin: 0 0 8pt 0; text-wrap: balance;
  color: #0d0f13;
}
.status {
  font-size: 8.5pt; color: #444; text-align: left; line-height: 1.45;
  border-left: 2.5pt solid #b8bcc4; padding-left: 9pt; margin: 0 0 16pt 0;
}

h2 {
  string-set: section content();
  font-size: 13pt; margin: 17pt 0 6pt; text-align: left; line-height: 1.25;
  border-bottom: 0.7pt solid #8d939d; padding-bottom: 3pt;
  break-after: avoid; break-inside: avoid; color: #0d0f13;
}
h3 {
  font-size: 11pt; margin: 12pt 0 4pt; text-align: left; line-height: 1.3;
  break-after: avoid; color: #0d0f13;
}
h2.unnumbered { string-set: section "Contents"; }

p { margin: 0 0 7pt; orphans: 2; widows: 2; }
ul, ol { margin: 0 0 7pt; padding-left: 16pt; }
li { margin-bottom: 3pt; }
li > p { margin-bottom: 3pt; }

blockquote {
  margin: 9pt 0; padding: 7pt 11pt;
  border-left: 3pt solid #3a3f47; background: #f2f2ef;
  break-inside: avoid;
}
blockquote p { margin: 0 0 4pt; }
blockquote p:last-child { margin-bottom: 0; }

/* --- contents ------------------------------------------------------------ */
.toc-block { break-inside: avoid; margin-bottom: 6pt; }
.toc-list { list-style: none; padding-left: 0; margin: 4pt 0 0; font-size: 9.5pt; }
.toc-list li { margin-bottom: 1.5pt; }
.toc-h3 { padding-left: 14pt; font-size: 9pt; color: #3a3f47; }
.toc-list a { text-decoration: none; color: #16181d; }
.toc-list a::after {
  content: " " leader('.') " " target-counter(attr(href), page);
  color: #6a707a;
}

/* --- captions ------------------------------------------------------------ */
.caption {
  font-size: 9pt; color: #2b2f36; text-align: left;
  margin: 9pt 0 3pt; break-after: avoid; break-inside: avoid;
}

/* --- code and figures ---------------------------------------------------- */
code {
  font-family: 'DejaVu Sans Mono', 'Liberation Mono', monospace;
  font-size: 0.82em; background: #f1f1ee; padding: 0.5pt 2pt;
  border-radius: 1.5pt; word-break: break-word;
}
pre {
  font-family: 'DejaVu Sans Mono', 'Liberation Mono', monospace;
  font-size: 7.8pt; line-height: 1.34;
  background: #f8f8f6; border: 0.5pt solid #d8d8d2;
  border-left: 2.5pt solid #b8bcc4;
  padding: 6pt 8pt; margin: 4pt 0 9pt;
  white-space: pre; overflow: hidden;
  break-inside: avoid;
}
pre code { background: none; font-size: 1em; padding: 0; border-radius: 0; }

/* --- tables -------------------------------------------------------------- */
table {
  border-collapse: collapse; width: 100%;
  font-size: 8.4pt; line-height: 1.35; margin: 4pt 0 10pt;
  break-inside: auto; text-align: left;
}
thead { display: table-header-group; }
tr { break-inside: avoid; }
th, td {
  border: 0.4pt solid #c3c7cd; padding: 3pt 4.5pt;
  vertical-align: top; text-align: left; hyphens: auto;
}
th { background: #e6e7e3; font-weight: 700; color: #0d0f13; }
tbody tr:nth-child(even) { background: #f7f7f5; }
td code, th code { font-size: 0.92em; word-break: break-all; background: none; }

hr { border: 0; border-top: 0.4pt solid #d4d6da; margin: 13pt 0; }
h2 + hr, hr + h2 { margin-top: 0; }
a { color: #16181d; text-decoration: none; word-break: break-all; }
strong { font-weight: 700; }
"""

page = (
    "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
    f"<title>{title}</title><style>{CSS}</style></head><body>"
    f"<div class='title'>{title}</div>"
    f"<div class='status'><strong>Status:</strong> {status}</div>"
    f"{html_body}</body></html>"
)


def render(output: Path) -> str:
    env = dict(os.environ)
    env["SOURCE_DATE_EPOCH"] = str(lock["source_date_epoch"])
    with tempfile.TemporaryDirectory(prefix="authority-render-") as tmp:
        html_path = Path(tmp) / "paper.html"
        html_path.write_text(page, encoding="utf-8")
        result = subprocess.run(
            ["weasyprint", "-e", "utf-8", str(html_path), str(output)],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
    if result.returncode != 0:
        print(result.stdout + result.stderr, file=sys.stderr)
        raise SystemExit(result.returncode)
    return hashlib.sha256(output.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=CANONICAL_PDF)
    args = parser.parse_args()
    output = args.output.resolve()
    digest = render(output)
    if output == CANONICAL_PDF:
        CANONICAL_HASH.write_text(f"{digest}  {CANONICAL_PDF.name}\n", encoding="utf-8")
    print(f"html {len(page)} bytes, {len(toc_rows)} contents entries")
    print(f"pdf  {output}")
    print(f"sha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
