"""platforms.py - pull the brief text and the real product hosts off a program page."""
import json, re
from pathlib import Path
from urllib.parse import urlparse

import bh

SKIP = ("twitter.com", "x.com", "discord", "t.me", "telegram", "linkedin", "medium.com",
        "youtube", "google", "gstatic", "googletagmanager", "cloudflare", "jsdelivr",
        "unpkg", "w3.org", "schema.org", "gmpg.org", "apple.com", "gravatar", "fonts.",
        "fontawesome", "cdnjs", "githubassets", "sentry", "segment", "hotjar",
        "cloudfront", "imgur", "bit.ly", "npmjs", "pypi", "reddit", "facebook",
        "instagram", "hackenproof", "immunefi", "cantina", "code4rena", "sherlock",
        "hats.finance", "bugcrowd", "hackerone", "guardianaudits")

EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css", ".js",
       ".woff", ".woff2", ".ttf", ".mp4", ".pdf", ".zip")


def _host(u):
    try:
        return urlparse(u).netloc.lower()
    except Exception:
        return ""


def extract_targets(html, base, limit=3):
    host = _host(base)
    seen, out = set([host]), []
    for m in re.finditer(r'href="(https?://[^"#?\s]+)', html):
        u = m.group(1).rstrip("/")
        h = _host(u)
        if not h or h in seen or any(s in h for s in SKIP):
            continue
        if u.lower().endswith(EXT):
            continue
        seen.add(h)
        out.append((0 if urlparse(u).path in ("", "/") else 1, len(u), u))
    out.sort()
    return [u for _, _, u in out[:limit]]


def details(pid, url):
    d = bh.project_dir(pid)
    code, body, hdrs = bh.fetch(url)
    if not code or len(body) < 200:
        return 0
    text = re.sub(r"<[^>]+>", " ", body)
    text = re.sub(r"\s+", " ", text).strip()
    (d / "details.html").write_text(body, encoding="utf-8")
    (d / "details.txt").write_text(text, encoding="utf-8")
    tg = extract_targets(body, url)
    if tg:
        (d / "targets.txt").write_text("\n".join(tg), encoding="utf-8")
    (d / "details.json").write_text(
        json.dumps({"url": url, "bytes": len(body), "text": len(text),
                    "adapter": "generic", "tier": "html", "reason": "",
                    "targets": tg}), encoding="utf-8")
    if tg:
        bh.log(pid, "intake: %d product host(s) -> %s" % (len(tg), ", ".join(tg)))
    return len(body)