#!/usr/bin/env python3
"""shot.py - render a terminal transcript file to a PNG (patchright venv)."""
import html
import sys
from patchright.sync_api import sync_playwright

src, dst = sys.argv[1], sys.argv[2]
width = int(sys.argv[3]) if len(sys.argv) > 3 else 1180
text = open(src, encoding="utf-8", errors="replace").read().rstrip("\n")
doc = (
    "<html><body style=\"margin:0;background:#0b0f14;color:#e6edf3;"
    "font:12.5px/1.5 Menlo,monospace;padding:18px\">"
    "<pre style=\"margin:0;white-space:pre-wrap\">%s</pre></body></html>"
    % html.escape(text)
)
with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": width, "height": 400})
    page.set_content(doc)
    height = page.evaluate("document.documentElement.scrollHeight")
    page.set_viewport_size({"width": width,
                            "height": max(120, min(int(height) + 4, 4000))})
    page.screenshot(path=dst, full_page=True)
    browser.close()
print(dst)
