#!/usr/bin/env python3
"""challenge.py - mint Cloudflare cookies with a real stealth browser.

Runs under the solver virtualenv (scrapling + camoufox installed):

    .venv/bin/python challenge.py <url> [timeout]

Prints exactly one JSON object on stdout:

    {"cookies": {...}, "user_agent": "...", "status": 200,
     "final_url": "...", "title": "...", "challenge": false, "error": null}

The engine itself stays stdlib-only; wafbypass.py invokes this file as a
subprocess and feeds the cookies + UA into its own raw requests.
"""
import json
import os
import sys
import time
from urllib.parse import urlsplit

CHALLENGE_TITLES = ("just a moment", "attention required", "checking your browser",
                    "please wait", "verify you are human", "ddos-guard")
CACHE_DIR = os.path.expanduser("~/.cache/wafbypass")
CACHE_TTL = 900


def _cache_path(url):
    host = urlsplit(url).netloc.replace(":", "_")
    return os.path.join(CACHE_DIR, host + ".json")


def _load_cache(url):
    try:
        with open(_cache_path(url), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if time.time() - data.get("saved", 0) > CACHE_TTL:
        return None
    if not data.get("cookies"):
        return None
    return data


def _save_cache(url, data):
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        data["saved"] = time.time()
        with open(_cache_path(url), "w", encoding="utf-8") as fh:
            json.dump(data, fh)
    except OSError:
        pass


def main(argv):
    url = argv[1] if len(argv) > 1 else None
    timeout = float(argv[2]) if len(argv) > 2 else 120.0
    refresh = "--refresh" in argv[2:]
    if not url:
        print(json.dumps({"error": "usage: challenge.py <url> [timeout] [--refresh]"}))
        return 2
    if not refresh:
        cached = _load_cache(url)
        if cached:
            cached["cached"] = True
            cached["error"] = None
            print(json.dumps(cached))
            return 0
    out = {"cookies": {}, "user_agent": None, "status": None,
           "final_url": None, "title": None, "challenge": None, "error": None}
    page_state = {}

    def page_action(page):
        page_state["ua"] = page.evaluate("navigator.userAgent")
        page_state["url"] = page.url
        try:
            page_state["title"] = page.title()
        except Exception:  # noqa: BLE001
            page_state["title"] = None

    session = None
    try:
        from scrapling.fetchers import StealthySession
        with StealthySession(headless=True, solve_cloudflare=True,
                             timeout=int(timeout * 1000)) as session:
            response = session.fetch(url, google_search=False, wait=2000,
                                     page_action=page_action,
                                     timeout=int(timeout * 1000))
            out["status"] = getattr(response, "status", None)
            try:
                out["cookies"] = dict(
                    (c["name"], c["value"]) for c in session.context.cookies())
            except Exception as exc:  # noqa: BLE001
                out["error"] = "cookie export failed: %s: %s" % (
                    type(exc).__name__, exc)
        out["user_agent"] = page_state.get("ua")
        out["final_url"] = page_state.get("url") or url
        out["title"] = page_state.get("title")
        title = (out["title"] or "").lower()
        out["challenge"] = any(marker in title for marker in CHALLENGE_TITLES)
    except Exception as exc:  # noqa: BLE001
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        if session is not None:
            try:
                session.close()
            except Exception:  # noqa: BLE001
                pass
    if not out["error"] and out["cookies"]:
        _save_cache(url, out)
    print(json.dumps(out))
    return 0 if not out["error"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
