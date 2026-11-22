#!/usr/bin/env python3
"""wafdetect.py - passive + single-probe WAF fingerprint.

Fetches a URL, inspects status/headers/cookies/body for known WAF markers,
then (optional) sends one benign trigger payload and compares.

Usage:
  python3 tools/wafdetect.py https://example.com
  python3 tools/wafdetect.py -f hosts.txt --no-probe
  python3 tools/wafdetect.py https://example.com --json
"""
import argparse
import http.client
import json
import re
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor

TIMEOUT = 12.0
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

# kind, key, value(None = presence only), label
SIGS = {
    "cloudflare": ("cloud edge WAF/CDN", [
        ("header", "server", "cloudflare", "server: cloudflare"),
        ("header", "cf-ray", None, "cf-ray header"),
        ("header", "cf-mitigated", None, "cf-mitigated header"),
        ("cookie", "__cf_bm", None, "__cf_bm cookie"),
        ("body", "cf-error-details", None, "body: cf-error-details"),
        ("body", "Attention Required! | Cloudflare", None, "body: Attention Required"),
        ("body", "Just a moment...", None, "JS challenge page"),
    ]),
    "akamai": ("cloud edge WAF/CDN (Kona/Ghost)", [
        ("header", "server", "akamaighost", "server: AkamaiGHost"),
        ("header", "x-akamai-request-id", None, "x-akamai-request-id"),
        ("header", "x-akamai-transformed", None, "x-akamai-transformed"),
        ("cookie", "ak_bmsc", None, "ak_bmsc cookie"),
        ("cookie", "akaas_", None, "akaas_* cookie"),
        ("header", "x-akam-sw-version", None, "x-akam-sw-version"),
        ("body", "Reference #", None, "body: Reference #"),
        ("body", "errors.edgesuite.net", None, "body: edgesuite error"),
        ("body", "Reference&#32;&#35;", None, "body: HTML-encoded Reference #"),
    ]),
    "aws-waf": ("cloud WAF (AWS WAF)", [
        ("header", "x-amzn-requestid", None, "x-amzn-requestid"),
        ("header", "x-amzn-waf-action", None, "x-amzn-waf-action"),
        ("body", "Request blocked", None, "body: Request blocked"),
        ("body", "The request could not be satisfied", None, "body: request not satisfied"),
    ]),
    "cloudfront": ("cloud CDN/WAF (CloudFront)", [
        ("header", "x-amz-cf-id", None, "x-amz-cf-id"),
        ("header", "x-amz-cf-pop", None, "x-amz-cf-pop"),
        ("header", "via", "cloudfront", "via: CloudFront"),
        ("body", "cloudfront", None, "body: cloudfront"),
    ]),
    "imperva": ("cloud WAF (Imperva/Incapsula)", [
        ("header", "x-iinfo", None, "x-iinfo header"),
        ("header", "x-cdn", "incapsula", "x-cdn: Incapsula"),
        ("cookie", "visid_incap", None, "visid_incap cookie"),
        ("cookie", "incap_ses", None, "incap_ses cookie"),
        ("body", "Incapsula incident ID", None, "body: Incapsula incident ID"),
        ("body", "_Incapsula_Resource", None, "body: Incapsula resource"),
    ]),
    "f5-bigip": ("ADC WAF (F5 BIG-IP ASM)", [
        ("header", "server", "bigip", "server: BigIP"),
        ("cookie", "BIGipServer", None, "BIGipServer cookie"),
        ("cookie", "TS01", None, "TS* ASM cookie"),
        ("body", "Support ID", None, "body: Support ID"),
        ("body", "The requested URL was rejected", None, "body: URL rejected"),
    ]),
    "sucuri": ("cloud WAF (Sucuri)", [
        ("header", "server", "sucuri", "server: Sucuri"),
        ("header", "x-sucuri-id", None, "x-sucuri-id"),
        ("header", "x-sucuri-cache", None, "x-sucuri-cache"),
        ("body", "Sucuri WebSite Firewall", None, "body: Sucuri firewall"),
        ("body", "Access Denied - Sucuri", None, "body: Sucuri denied"),
    ]),
    "barracuda": ("appliance WAF (Barracuda)", [
        ("cookie", "barra_counter_session", None, "barra_counter_session"),
        ("body", "Barracuda", None, "body: Barracuda"),
        ("header", "server", "barracuda", "server: Barracuda"),
    ]),
    "netscaler": ("ADC WAF (Citrix NetScaler)", [
        ("cookie", "NSC_", None, "NSC_* cookie"),
        ("header", "via", "ns-cache", "via: NS-CACHE"),
        ("body", "netscaler", None, "body: NetScaler"),
    ]),
    "azure-frontdoor": ("cloud WAF (Azure Front Door)", [
        ("header", "x-azure-ref", None, "x-azure-ref"),
        ("header", "x-fd-int-roxy-purgeid", None, "Front Door header"),
        ("body", "Azure Front Door", None, "body: Azure Front Door"),
    ]),
    "google-cloud": ("cloud WAF (Google Cloud Armor/GFE)", [
        ("header", "server", "gfe", "server: GFE"),
        ("header", "server", "Google Frontend", "server: Google Frontend"),
        ("body", "Google Cloud", None, "body: Google Cloud"),
    ]),
    "wordfence": ("host plugin WAF (Wordfence)", [
        ("cookie", "wfwaf-authcookie", None, "wfwaf-authcookie cookie"),
        ("body", "Wordfence", None, "body: Wordfence"),
        ("body", "Your access to this site has been limited", None, "body: access limited"),
    ]),
    "imunify360": ("host WAF (Imunify360)", [
        ("header", "x-imunify", None, "x-imunify header"),
        ("body", "Imunify360", None, "body: Imunify360"),
        ("body", "imunify", None, "body: imunify"),
    ]),
    "safeline": ("host WAF (SafeLine)", [
        ("body", "SafeLine", None, "body: SafeLine"),
        ("header", "x-safeline", None, "x-safeline header"),
    ]),
    "datadome": ("bot/WAF (DataDome)", [
        ("header", "x-datadome", None, "x-datadome"),
        ("cookie", "datadome", None, "datadome cookie"),
    ]),
    "perimeterx": ("bot/WAF (HUMAN/PerimeterX)", [
        ("cookie", "_px", None, "_px cookie"),
        ("header", "x-px", None, "x-px header"),
    ]),
    "kasada": ("bot/WAF (Kasada)", [
        ("header", "x-kpsdk", None, "x-kpsdk header"),
        ("cookie", "kpsdk", None, "kpsdk cookie"),
    ]),
    "modsecurity": ("host module WAF (ModSecurity/CRS)", [
        ("header", "server", "mod_security", "server mentions mod_security"),
        ("body", "ModSecurity", None, "body: ModSecurity"),
        ("body", "Not Acceptable", None, "body: Not Acceptable (CRS default)"),
    ]),
    "f5-xc": ("cloud WAF (F5 Distributed Cloud)", [
        ("header", "server", "volt-adc", "server: volt-adc (F5 XC)"),
        ("header", "x-volterra-location", None, "x-volterra-location"),
    ]),
    "fastly": ("cloud CDN (Fastly, WAF optional)", [
        ("header", "x-fastly-request-id", None, "x-fastly-request-id"),
        ("header", "x-served-by", "cache-", "x-served-by: cache-*"),
        ("header", "via", "varnish", "via: varnish"),
    ]),
}

CLASS_OF = {v: c for v, (c, _) in SIGS.items()}


def fetch(url, path="/", probe=None):
    m = re.match(r"^(https?)://([^/]+)(/.*)?$", url.rstrip("/"))
    if not m:
        raise ValueError(f"bad url: {url}")
    scheme, hostport, base = m.group(1), m.group(2), m.group(3) or "/"
    target = (base.rstrip("/") + path) if path != "/" else base
    conn = http.client.HTTPSConnection(hostport, timeout=TIMEOUT, context=ssl._create_unverified_context()) \
        if scheme == "https" else http.client.HTTPConnection(hostport, timeout=TIMEOUT)
    headers = {"User-Agent": UA, "Accept": "*/*", "Connection": "close"}
    try:
        conn.request("GET", target, headers=headers)
        r = conn.getresponse()
        body = r.read(65536).decode("utf-8", "replace")
        return r.status, dict((k.lower(), v) for k, v in r.getheaders()), r.msg.get_all("Set-Cookie") or [], body
    finally:
        conn.close()


def match(headers, cookies, body, status):
    hits = {}
    for vendor, (cls, checks) in SIGS.items():
        ev = []
        for kind, key, val, label in checks:
            if kind == "header":
                got = headers.get(key)
                if got is not None and (val is None or val.lower() in got.lower()):
                    ev.append(f"{label} [{key}: {got[:80]}]")
            elif kind == "cookie":
                for c in cookies:
                    if key in c:
                        ev.append(f"{label}")
                        break
            elif kind == "body":
                if key.lower() in body.lower():
                    ev.append(f"{label}")
        if ev:
            hits[vendor] = (cls, ev, len(ev))
    return hits


def detect(url, do_probe=True):
    out = {"url": url, "vendor": None, "class": None, "evidence": [], "brace": {}, "probe": None}
    try:
        status, hdrs, cookies, body = fetch(url)
    except Exception as e:  # noqa: BLE001
        out["error"] = f"{type(e).__name__}: {e}"
        return out
    out["status"] = status
    out["server"] = hdrs.get("server", "")
    hits = match(hdrs, cookies, body, status)

    # reactive check: one benign trigger payload
    if do_probe:
        p = "/?q=%3Cscript%3Ealert(1)%3C/script%3E&id=1%27%20OR%201%3D1--"
        try:
            ps, ph, pc, pb = fetch(url, p)
            out["probe"] = {"status": ps}
            if ps in (403, 406, 419, 429, 501, 503):
                out["brace"]["reactive_block"] = f"trigger payload -> {ps} (baseline {status})"
                out["brace"]["probe_server"] = ph.get("server", "")
        except Exception as e:  # noqa: BLE001
            out["probe"] = {"error": f"{type(e).__name__}"}

    # body-only keywords are weak; require a header/cookie marker or two body hits
    strong = {k: v for k, v in hits.items()
              if any(not e.startswith("body") for e in v[1]) or v[2] >= 2}
    if strong:
        best = max(strong.items(), key=lambda kv: (any(not e.startswith("body") for e in kv[1][1]), kv[1][2]))
        out["vendor"], (out["class"], ev, _) = best[0], best[1]
        out["evidence"] = ev
        out["all_matches"] = {k: v[1] for k, v in hits.items()}
    elif out["brace"].get("reactive_block"):
        out["vendor"] = "unknown-generic"
        out["class"] = "unknown WAF (reactive only)"
        out["evidence"] = [out["brace"]["reactive_block"]]
    else:
        out["vendor"] = "none-detected"
        out["class"] = "no WAF marker"
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("urls", nargs="*")
    ap.add_argument("-f", "--file")
    ap.add_argument("--no-probe", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("-j", "--jobs", type=int, default=6)
    a = ap.parse_args()
    urls = list(a.urls)
    if a.file:
        urls += [x.strip() for x in open(a.file) if x.strip() and not x.startswith("#")]
    if not urls:
        ap.error("no url")
    with ThreadPoolExecutor(max_workers=a.jobs) as ex:
        res = list(ex.map(lambda u: detect(u, not a.no_probe), urls))
    if a.json:
        print(json.dumps(res, indent=2))
        return
    print(f"{'URL':38} {'STATUS':6} {'VENDOR':18} {'CLASS':32} EVIDENCE")
    for r in res:
        if r.get("error"):
            print(f"{r['url']:38} {'ERR':6} {r['error'][:70]}")
            continue
        ev = "; ".join(r["evidence"][:3])
        print(f"{r['url']:38} {r.get('status',''):6} {r['vendor']:18} {r['class'][:32]:32} {ev[:110]}")


if __name__ == "__main__":
    main()
