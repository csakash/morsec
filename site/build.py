#!/usr/bin/env python3
"""Builds the morsec site into site/public: inlines shared.css, the hairline kernel, figures.js,
the arrow and the brand icons, and wraps the landing page in its document head. No dependencies."""
import pathlib, re

HERE = pathlib.Path(__file__).resolve().parent
SRC, OUT = HERE / "src", HERE / "public"
URL = "https://morsec.motiontic.com"
ARROW = ('<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3" aria-hidden="true">'
         '<path d="M4 12 12 4M5.5 4H12v6.5"/></svg>')
DESC = "Coding agents use your API keys, database passwords and tokens without ever seeing them."


def icon(name: str) -> str:
    svg = re.sub(r"<title>.*?</title>", "", (SRC / "icons" / f"{name}.svg").read_text())
    return svg.replace("<svg ", '<svg class="logo" aria-hidden="true" focusable="false" fill="currentColor" ', 1)


def head(title: str, path: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>{title}</title>
<meta name="description" content="{DESC}">
<link rel="canonical" href="{URL}{path}">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<meta name="theme-color" content="#f2f0eb" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0f0f0e" media="(prefers-color-scheme: dark)">
<meta property="og:type" content="website">
<meta property="og:title" content="{title}">
<meta property="og:description" content="{DESC}">
<meta property="og:url" content="{URL}{path}">
<meta name="twitter:card" content="summary">
<style>:root{{padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}}body{{margin:0}}img{{max-width:100%}}[hidden]{{display:none!important}}</style>
"""


def fill(text: str) -> str:
    text = (text.replace("{{shared}}", (SRC / "shared.css").read_text())
                .replace("{{kernel}}", (SRC / "kernel.js").read_text())
                .replace("{{figures}}", (SRC / "figures.js").read_text())
                .replace("{{arrow}}", ARROW))
    text = re.sub(r"\{\{icon:(\w+)\}\}", lambda m: icon(m.group(1)), text)
    leftover = [line for line in text.splitlines() if "{{" in line and "${" not in line]
    assert not leftover, leftover[:3]
    return text


def main() -> None:
    OUT.mkdir(exist_ok=True)
    # The landing page source is a body fragment with its own <title>; give it a full document.
    page = (SRC / "index.html").read_text()
    page = re.sub(r"^<title>.*?</title>\n(<meta name=\"claude:[^>]*>\n)?(<meta name=\"description\"[^>]*>\n)?", "", page)
    page = head("morsec: agents use the keys, never see them", "/") + page.replace("<style>", "<style>", 1)
    page = page.replace("\n<header", "\n</head>\n<body>\n<header", 1) + "\n</body>\n</html>\n"
    (OUT / "index.html").write_text(fill(page))
    docs = fill((SRC / "docs.html").read_text())
    docs = docs.replace("<title>morsec docs</title>", "<title>morsec docs</title>\n" + head("morsec docs", "/docs").split("<title>morsec docs</title>\n", 1)[1].split("<style>")[0], 1)
    (OUT / "docs.html").write_text(docs)
    for f in ["favicon.svg", "robots.txt", "_headers", "404.html"]:
        (OUT / f).write_text((HERE / "static" / f).read_text())
    print("built", *sorted(p.name for p in OUT.iterdir()))


if __name__ == "__main__":
    main()
