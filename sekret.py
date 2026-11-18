#!/usr/bin/env python3
"""sekret.py - credential and endpoint harvesting.

Called by bh.py as sekret.run(bh, pid). TruffleHog and SecretFinder in one
pass: entropy plus known-provider patterns over page source, linked javascript,
source maps, repo files and git history. Every hit is stored with context and
redacted, and verifiable providers are checked live.

Findings are written with a proof artifact and the endpoint harvest is folded
back into details.txt so the scanner keeps expanding on its own.
"""
import json
import math
import re

MAX_FILES = 15
MAX_BYTES = 600000
ENTROPY_MIN = 4.0
ENTROPY_LEN = 20

SUSPECT_EXT = (".js", ".mjs", ".map", ".json", ".txt", ".env", ".yml", ".yaml",
               ".ts", ".jsx", ".tsx", ".php", ".py", ".rb", ".go", ".sol", ".rs",
               ".properties", ".cfg", ".ini", ".xml", ".html")

SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff",
            ".woff2", ".ttf", ".mp4", ".zip")

SKIP_NAMES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "cargo.lock",
              "composer.lock", "verification_data.json", "ip_retention_snapshot.json",
              "contracts.json", "snapshot")

PATTERNS = [
    ("private key block", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
     "critical", "crypto", "none"),
    ("aws access key id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "critical", "crypto", "none"),
    ("aws secret key", r"(?i)aws_?secret_?access_?key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})",
     "critical", "crypto", "none"),
    ("github token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "critical", "crypto", "github"),
    ("gitlab token", r"\bglpat-[A-Za-z0-9_-]{20,}\b", "critical", "crypto", "none"),
    ("slack webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{30,}",
     "critical", "crypto", "slack"),
    ("slack token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}", "high", "crypto", "none"),
    ("stripe live key", r"\bsk_live_[A-Za-z0-9]{16,}", "critical", "crypto", "none"),
    ("stripe test key", r"\bsk_test_[A-Za-z0-9]{16,}", "medium", "crypto", "none"),
    ("google api key", r"\bAIza[0-9A-Za-z_-]{35}\b", "high", "crypto", "google"),
    ("firebase url", r"https://[a-z0-9-]+\.firebaseio\.com", "medium", "web", "none"),
    ("npm token", r"\bnpm_[A-Za-z0-9]{36}\b", "high", "crypto", "npm"),
    ("pypi token", r"\bpypi-[A-Za-z0-9_-]{40,}", "high", "crypto", "none"),
    ("sendgrid key", r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}", "high", "crypto", "none"),
    ("mailgun key", r"\bkey-[0-9a-f]{32}\b", "medium", "crypto", "none"),
    ("twilio sid", r"\bAC[0-9a-f]{32}\b", "medium", "crypto", "none"),
    ("openai key", r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}", "high", "crypto", "none"),
    ("anthropic key", r"\bsk-ant-[A-Za-z0-9_-]{20,}", "high", "crypto", "none"),
    ("huggingface token", r"\bhf_[A-Za-z0-9]{30,}\b", "high", "crypto", "none"),
    ("discord webhook", r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+",
     "medium", "web", "none"),
    ("telegram bot token", r"\b\d{8,10}:AA[A-Za-z0-9_-]{30,}", "high", "crypto", "none"),
    ("supabase service role", r"\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",
     "high", "crypto", "none"),
    ("cloudflare token", r"\b[A-Za-z0-9_-]{40}\b(?=.*cloudflare)", "low", "crypto", "none"),
    ("basic auth in url", r"https?://[^\s:@/]+:[^\s@/]{6,}@[^\s/]+", "medium", "crypto", "none"),
    ("db connection string", r"(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s\"'<>]{10,}",
     "high", "crypto", "none"),
]

ENDPOINT_RE = re.compile(
    r"""(?:https?|wss?)://[A-Za-z0-9._-]+(?::\d+)?(?:/[A-Za-z0-9._~%!$&'()*+,;=:@/-]*)?|"""
    r"""["'](/(?:api|v\d|graphql|rest|internal|admin|auth|oauth|upload|export)[A-Za-z0-9._~%!$&'()*+,;=:@/-]*)["']""")

SKIP_HOST = ("w3.org", "schema.org", "gmpg.org", "jsdelivr.net", "unpkg.com",
             "googleapis.com", "gstatic.com", "cloudflare.com", "github.com/assets",
             "bootstrapcdn", "jquery.com", "fontawesome", "cdnjs")

ALLOW_LOW = re.compile(r"^(?:true|false|null|undefined|localhost|127\.0\.0\.1)$", re.I)


def _entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(s))
    return -sum((c / n) * math.log(c / n, 2) for c in counts.values())


def _looks_secret(s):
    if len(s) < ENTROPY_LEN or ALLOW_LOW.match(s):
        return False
    if s.isalpha() or s.isdigit():
        return False
    if re.fullmatch(r"[a-f0-9]+", s):
        return len(s) >= 32 and _entropy(s) >= 3.0
    if re.fullmatch(r"[A-Za-z0-9+/=_-]+", s):
        return _entropy(s) >= ENTROPY_MIN
    return False


def _redact(s):
    if len(s) <= 12:
        return s
    return "%s...%s (%d chars)" % (s[:6], s[-4:], len(s))


def _emit(bh, pid, tool, title, sev, file, evidence, proof=None):
    t = bh.TOOLS.get(tool, {})
    try:
        with bh.db() as c:
            if c.execute("SELECT id FROM findings WHERE pid=? AND title=? AND file=?",
                         (pid, title[:300], file[:300])).fetchone():
                return 0
            cur = c.execute(
                "INSERT INTO findings(pid,title,sev,cls,file,line,evidence,score,fund,reward,"
                "tool,ts) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (pid, title[:300], sev, t.get("cls", "crypto"), file[:300], 0,
                 evidence[:20000],
                 min(100, bh.SEV_W.get(sev, 14) + t.get("reward", 0) // 400
                     + min(12, len(evidence) // 120) + 8),
                 1 if t.get("fund") else 0, bh.REWARD.get(t.get("cls", ""), 0),
                 tool, __import__("time").time()))
            fid = cur.lastrowid
    except Exception:
        return 0
    if proof:
        try:
            d = bh.project_dir(pid) / "secrets"
            d.mkdir(parents=True, exist_ok=True)
            fn = d / ("%s.proof.txt" % fid)
            fn.write_text(proof[:20000], encoding="utf-8")
            with bh.db() as c:
                c.execute("UPDATE findings SET poc_path=? WHERE id=?", (str(fn), fid))
        except Exception:
            pass
    return 1


def _verify(bh, kind, value):
    try:
        if kind == "github":
            code, body, _, _ = bh.fetch_full(
                "https://api.github.com/user",
                headers={"Authorization": "token " + value, "Accept": "application/vnd.github+json"})
            if code == 200:
                try:
                    return "valid, identity %s" % json.loads(body).get("login", "?")
                except Exception:
                    return "valid"
            return "rejected (%d)" % code
        if kind == "slack":
            code, body, _, _ = bh.fetch_full(value, data=b'{"text":"bh"}',
                                             headers={"Content-Type": "application/json"},
                                             method="POST")
            return "valid" if code == 200 and body.strip() == "ok" else "rejected (%d)" % code
        if kind == "google":
            code, body, _, _ = bh.fetch_full(
                "https://maps.googleapis.com/maps/api/geocode/json?address=x&key=" + value)
            return "rejected" if "REQUEST_DENIED" in body else "accepted"
        if kind == "npm":
            code, _, _, _ = bh.fetch_full("https://registry.npmjs.org/-/whoami",
                                          headers={"Authorization": "Bearer " + value})
            return "valid" if code == 200 else "rejected (%d)" % code
    except Exception as ex:
        return "unknown (%s)" % str(ex)[:40]
    return "unchecked"


def _scan_text(bh, pid, where, text, verify_budget):
    n = 0
    seen = set()
    for name, pat, sev, cls, kind in PATTERNS:
        for m in re.finditer(pat, text):
            val = m.group(0)
            key = (name, val[:60])
            if key in seen:
                continue
            seen.add(key)
            line = text[:m.start()].count("\n") + 1
            ctx = text[max(0, m.start() - 90):m.end() + 90].replace("\n", " ")
            verdict = ""
            if kind != "none" and verify_budget[0] > 0:
                verify_budget[0] -= 1
                verdict = _verify(bh, kind, val)
                if verdict.startswith("rejected"):
                    sev = "low"
                elif verdict.startswith("valid") or verdict.startswith("accepted"):
                    sev = "critical"
            n += _emit(bh, pid, "m100", "%s in %s" % (name, where), sev,
                       "%s#L%d" % (where, line),
                       "match %s\nverification: %s\ncontext: %s"
                       % (_redact(val), verdict or "not checked", ctx[:600]),
                       proof="%s line %d\nvalue: %s\nverification: %s\n\n%s\n"
                             % (where, line, val, verdict or "-", ctx))
            if len(seen) > 60:
                break
    if not any(s in where.lower() for s in SKIP_NAMES):
        for m in re.finditer(r"[\"']([A-Za-z0-9+/=_\-]{20,120})[\"']", text):
            val = m.group(1)
            if not _looks_secret(val):
                continue
            key = ("entropy", val[:60])
            if key in seen:
                continue
            seen.add(key)
            line = text[:m.start()].count("\n") + 1
            ctx = text[max(0, m.start() - 90):m.end() + 90].replace("\n", " ")
            n += _emit(bh, pid, "m100", "high entropy string in %s" % where, "medium",
                       "%s#L%d" % (where, line),
                       "value %s, entropy %.2f\ncontext: %s"
                       % (_redact(val), _entropy(val), ctx[:600]),
                       proof="%s line %d\nentropy %.2f\n%s\n" % (where, line, _entropy(val), ctx))
            if n > 40:
                break
    return n


def _endpoints(bh, pid, text, bucket):
    for m in ENDPOINT_RE.finditer(text):
        u = m.group(0).strip("\"'")
        if len(u) < 6 or any(s in u for s in SKIP_HOST):
            continue
        if u.startswith("/"):
            continue
        if u not in bucket:
            bucket.append(u)


def _fetch_js(bh, pid, page):
    n = 0
    srcs = []
    for m in re.finditer(r'<script[^>]+src="([^"]+)"', page or ""):
        u = m.group(1)
        if u.startswith("//"):
            u = "https:" + u
        elif u.startswith("/"):
            u = "https://" + bh.urlparse(page).netloc + u
        if u not in srcs:
            srcs.append(u)
    for m in re.finditer(r'"(/[A-Za-z0-9._/-]+\.js)"', page or ""):
        u = "https://" + bh.urlparse(page).netloc + m.group(1)
        if u not in srcs:
            srcs.append(u)
    budget = [8]
    endpoints = []
    for u in srcs[:MAX_FILES]:
        if bh.STOP.is_set() or budget[0] <= 0:
            break
        code, body, _, _ = bh.fetch_full(u, timeout=25)
        if not code or code >= 400 or not body:
            continue
        budget[0] -= 1
        bh.log(pid, "sekret: js %s %d bytes" % (u, len(body)))
        n += _scan_text(bh, pid, u, body[:MAX_BYTES], [2])
        _endpoints(bh, pid, body, endpoints)
        if ".js.map" in body or "sourceMappingURL" in body:
            n += _source_map(bh, pid, u)
    if endpoints:
        _merge(bh, pid, endpoints)
    return n


def _source_map(bh, pid, js_url):
    m = re.search(r"sourceMappingURL=([\w./-]+\.map)", js_url) or \
        re.search(r"//# sourceMappingURL=([\w./-]+\.map)", "")
    cand = []
    if m:
        cand.append(m.group(1))
    cand.append(js_url.split("?")[0] + ".map")
    for c in cand:
        if c.startswith("http"):
            u = c
        elif c.startswith("/"):
            u = "https://" + bh.urlparse(js_url).netloc + c
        else:
            u = js_url.rsplit("/", 1)[0] + "/" + c
        code, body, _, _ = bh.fetch_full(u, timeout=30)
        if code == 200 and "sourcesContent" in body:
            bh.log(pid, "sekret: source map %s" % u)
            n = _emit(bh, pid, "m104", "source map exposes original source", "medium", u,
                      "sourcesContent present, %d bytes" % len(body),
                      proof="GET %s -> 200, %d bytes\n" % (u, len(body)))
            return n + _scan_text(bh, pid, u, body[:MAX_BYTES], [0])
    return 0


def _merge(bh, pid, endpoints):
    f = bh.project_dir(pid) / "details.txt"
    have = f.read_text(encoding="utf-8", errors="ignore") if f.exists() else ""
    new = [u for u in endpoints if u not in have]
    if not new:
        return 0
    with f.open("a", encoding="utf-8") as fh:
        fh.write("\n\n# endpoints harvested by sekret\n")
        for u in new[:60]:
            fh.write(u + "\n")
    bh.log(pid, "sekret: %d endpoint(s) added to scope text" % len(new))
    return len(new)


def _repo(bh, pid, owner, repo):
    n = 0
    try:
        tree = json.loads(bh.gh("/repos/%s/%s/git/trees/HEAD?recursive=1" % (owner, repo)))
    except Exception as ex:
        bh.log(pid, "sekret: tree %s" % ex)
        return 0
    files = [x["path"] for x in tree.get("tree") or []
             if x.get("type") == "blob"
             and x["path"].lower().endswith(SUSPECT_EXT)
             and not x["path"].lower().endswith(SKIP_EXT)
             and not any(s in x["path"].lower() for s in SKIP_NAMES)]
    files.sort(key=lambda p: (0 if p.lower().endswith((".env", ".json", ".yml", ".yaml"))
                              else 1, len(p)))
    endpoints = []
    for path in files[:MAX_FILES]:
        if bh.STOP.is_set():
            break
        try:
            body = bh.fetch("https://raw.githubusercontent.com/%s/%s/HEAD/%s"
                            % (owner, repo, path), timeout=25)[:MAX_BYTES]
        except Exception:
            continue
        n += _scan_text(bh, pid, "%s/%s" % (repo, path), body, [1])
        _endpoints(bh, pid, body, endpoints)
    try:
        commits = json.loads(bh.gh("/repos/%s/%s/commits?per_page=4" % (owner, repo)))
    except Exception:
        commits = []
    for cm in commits[:4]:
        sha = cm.get("sha")
        if not sha:
            continue
        try:
            detail = json.loads(bh.gh("/repos/%s/%s/commits/%s" % (owner, repo, sha)))
        except Exception:
            continue
        for f in detail.get("files") or []:
            patch = f.get("patch") or ""
            added = "\n".join(l[1:] for l in patch.splitlines() if l.startswith("+"))
            if added:
                n += _scan_text(bh, pid, "%s@%s:%s" % (repo, sha[:8], f.get("filename")),
                                added, [0])
    if endpoints:
        _merge(bh, pid, endpoints)
    return n


def run(bh, pid, targets=None):
    p = bh.getp(pid)
    if not p:
        return 0
    if not bh._envb("BH_SEKRET", True):
        return 0
    targets = targets or bh.collect_targets(pid)
    n = 0
    done = 0
    limit = bh._envi("BH_SEKRET_MAX", 4)
    for t in targets:
        if done >= limit or bh.STOP.is_set():
            break
        if "github.com" in t:
            m = re.search(r"github\.com/([\w.-]+)/([\w.-]+)", t)
            if not m:
                continue
            done += 1
            try:
                meta, owner, repo = bh._resolve_repo(pid, m.group(1), m.group(2).rstrip("."))
                if meta:
                    n += _repo(bh, pid, owner, repo)
            except Exception as ex:
                bh.log(pid, "sekret: repo %s" % ex)
        elif t.startswith("http") and done < limit:
            done += 1
            try:
                code, body, hdrs, _ = bh.fetch_full(t)
                if code and code < 400:
                    n += _scan_text(bh, pid, t, body[:MAX_BYTES], [1])
                    n += _fetch_js(bh, pid, t)
            except Exception as ex:
                bh.log(pid, "sekret: %s" % ex)
    if p["url"].startswith("http"):
        try:
            code, body, _, _ = bh.fetch_full(p["url"])
            if code and code < 400:
                n += _scan_text(bh, pid, p["url"], body[:MAX_BYTES], [2])
                n += _fetch_js(bh, pid, p["url"])
        except Exception as ex:
            bh.log(pid, "sekret: page %s" % ex)
    bh.log(pid, "sekret: %d hit(s)" % n)
    return n