"""마크다운 문서를 PDF로 만든다.

마크다운 → HTML → Chrome 헤드리스 인쇄 순서다. Chrome 을 쓰는 이유는
한글 폰트, 코드블록, 표를 별도 설정 없이 제대로 그려주기 때문이다.

usage: python3 scripts/md2pdf.py <input.md> <output.pdf> [문서제목]
"""

import re
import subprocess
import sys
import tempfile
from pathlib import Path

import markdown

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

CSS = """
@page { size: A4; margin: 20mm 18mm 22mm 18mm; }
body {
  font-family: "AppleSDGothicNeo-Regular", "Apple SD Gothic Neo", sans-serif;
  font-size: 10.5pt; line-height: 1.75; color: #1a1a1a;
  word-break: keep-all; overflow-wrap: break-word;
}
h1 { font-size: 21pt; margin: 0 0 4pt; letter-spacing: -0.5px; }
h1 + .subtitle { color: #666; font-size: 11pt; margin-bottom: 28pt; }
h2 { font-size: 15pt; margin: 30pt 0 11pt; page-break-after: avoid; }
h3 { font-size: 12.5pt; margin: 18pt 0 7pt; page-break-after: avoid; }
h4 { font-size: 11pt; margin: 14pt 0 5pt; page-break-after: avoid; }
p { margin: 0 0 9pt; }
ul, ol { margin: 0 0 9pt; padding-left: 20pt; }
li { margin-bottom: 3pt; }
code { font-family: "SFMono-Regular", Menlo, monospace; font-size: 9.2pt; }
pre {
  padding: 2pt 0 2pt 14pt; overflow-x: auto;
  page-break-inside: avoid; margin: 0 0 12pt;
}
pre code {
  background: none; padding: 0; font-size: 8.6pt; line-height: 1.5;
  white-space: pre; display: block;
}
table {
  border-collapse: collapse; width: 100%; margin: 0 0 12pt;
  font-size: 9.3pt; page-break-inside: avoid;
}
th, td { border: 1px solid #ccc; padding: 5pt 7pt; text-align: left; vertical-align: top; }
th { font-weight: 600; }
blockquote { margin: 0 0 11pt; padding-left: 14pt; }
hr { border: none; margin: 22pt 0; }
a { color: #1a1a1a; text-decoration: none; }
.toc { margin-bottom: 30pt; }
.toc h2 { font-size: 12pt; margin: 0 0 8pt; padding: 0; }
.toc ul { margin: 0; padding-left: 16pt; }
.toc li { margin-bottom: 2pt; font-size: 9.5pt; }
"""


def build_toc(md_text: str) -> str:
    """## 과 ### 제목만 모아 간단한 목차를 만든다."""
    items = []
    for line in md_text.splitlines():
        m = re.match(r"^(#{2,3})\s+(.*)$", line.strip())
        if m:
            depth = len(m.group(1)) - 2
            items.append(f'<li style="margin-left:{depth * 14}pt">{m.group(2).strip()}</li>')
    if not items:
        return ""
    return f'<div class="toc"><h2>목차</h2><ul>{"".join(items)}</ul></div>'


def main() -> None:
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    title = sys.argv[3] if len(sys.argv) > 3 else src.stem

    md_text = src.read_text(encoding="utf-8")
    body = markdown.markdown(
        md_text, extensions=["tables", "fenced_code", "sane_lists", "nl2br"]
    )

    html = f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<title>{title}</title><style>{CSS}</style></head><body>
{build_toc(md_text)}
{body}
</body></html>"""

    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as f:
        f.write(html)
        tmp = f.name

    dst.parent.mkdir(parents=True, exist_ok=True)
    # --headless=new 가 없는 구버전 대비로 실패 시 구식 플래그로 한 번 더 시도한다.
    for flag in ("--headless=new", "--headless"):
        r = subprocess.run(
            [CHROME, flag, "--disable-gpu", "--no-sandbox", "--no-pdf-header-footer",
             f"--print-to-pdf={dst}", f"file://{tmp}"],
            capture_output=True, text=True, timeout=180,
        )
        if dst.exists() and dst.stat().st_size > 0:
            print(f"{dst}  {dst.stat().st_size // 1024}KB")
            return
    print("PDF 생성 실패", r.stderr[-500:], file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
