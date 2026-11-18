#!/usr/bin/env python3
"""bh.py - local-first bug bounty engine."""
import json, os, re, sqlite3, subprocess, sys, threading, time
import urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import contract
import deep
import manual

APP = Path(__file__).resolve().parent
DB_PATH = APP / "bh.db"
WORK = APP / "work"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/124.0.0.0 Safari/537.36")
TIMEOUT = 20
MAX_BODY = 4000000

PLATFORMS = {
    "hackenproof.com": "hackenproof",
    "immunefi.com": "immunefi",
    "cantina.xyz": "cantina",
    "code4rena.com": "code4rena",
    "sherlock.xyz": "sherlock",
    "hats.finance": "hats",
    "bugcrowd.com": "bugcrowd",
    "hackerone.com": "hackerone",
    "guardianaudits.com": "guardian",
}

JUNK = ("twitter.com", "x.com", "discord", "t.me", "telegram", "linkedin", "medium.com",
        "youtube", "google", "gstatic", "googletagmanager", "cloudflare", "jsdelivr",
        "unpkg", "w3.org", "schema.org", "gmpg.org", "apple.com", "gravatar", "fonts.",
        "fontawesome", "cdnjs", "githubassets", "sentry", "segment", "hotjar",
        "cloudfront", "imgur", "bit.ly", "npmjs", "pypi", "reddit", "facebook",
        "instagram", "mailto:", "javascript:")

IMG_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".css", ".js",
           ".woff", ".woff2", ".ttf", ".mp4", ".pdf", ".zip")

ADDR_RE = re.compile(r"0x[a-fA-F0-9]{40}")
URL_RE = re.compile(r"https?://[^\s\"'<>)]+")

CHAINS = {1: "ethereum", 10: "optimism", 56: "bsc", 137: "polygon", 8453: "base",
          42161: "arbitrum", 59144: "linea", 534352: "scroll"}

SLOT_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
SLOT_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
SEL_OWNER = "8da5cb5b"
SEL_UPGRADE = "3659cfe6"
SEL_UPGRADE_CALL = "4f1ef286"

SEV_W = {"critical": 44, "high": 30, "medium": 18, "low": 10, "info": 4}
REWARD = {"rce": 4000, "sqli": 2500, "auth": 2000, "access": 1200, "ssrf": 1500,
          "upgrade": 3000, "flashloan": 3000, "reentrancy": 3000, "rounding": 2500,
          "precision": 2000, "oracle": 2500, "signature": 2000, "accounting": 2500,
          "token": 1000, "storage": 1200, "logic": 800, "deserial": 2000, "clock": 600,
          "api": 800, "decimal": 400, "secret": 2500}

TOOLS = {
    "m001": {"name": "reentrancy", "cls": "reentrancy", "sev": "high", "reward": 3000, "fund": 1},
    "m002": {"name": "read only reentrancy", "cls": "reentrancy", "sev": "critical", "reward": 4000, "fund": 1},
    "m011": {"name": "access control", "cls": "access", "sev": "critical", "reward": 3500, "fund": 1},
    "m014": {"name": "tx.origin", "cls": "access", "sev": "medium", "reward": 800, "fund": 1},
    "m018": {"name": "accounting", "cls": "accounting", "sev": "high", "reward": 2500, "fund": 1},
    "m020": {"name": "balance read", "cls": "accounting", "sev": "high", "reward": 2000, "fund": 1},
    "m021": {"name": "msg.value", "cls": "accounting", "sev": "medium", "reward": 1200, "fund": 1},
    "m026": {"name": "flash loan", "cls": "flashloan", "sev": "high", "reward": 3000, "fund": 1},
    "m029": {"name": "precision", "cls": "precision", "sev": "high", "reward": 2000, "fund": 1},
    "m031": {"name": "cast", "cls": "precision", "sev": "high", "reward": 1500, "fund": 1},
    "m034": {"name": "storage", "cls": "storage", "sev": "high", "reward": 1200, "fund": 1},
    "m037": {"name": "mapping delete", "cls": "storage", "sev": "medium", "reward": 800, "fund": 1},
    "m040": {"name": "signature", "cls": "signature", "sev": "high", "reward": 2000, "fund": 1},
    "m042": {"name": "chain id", "cls": "signature", "sev": "high", "reward": 1500, "fund": 1},
    "m043": {"name": "proxy", "cls": "upgrade", "sev": "critical", "reward": 3000, "fund": 1},
    "m045": {"name": "delegatecall", "cls": "upgrade", "sev": "critical", "reward": 3000, "fund": 1},
    "m059": {"name": "approval", "cls": "token", "sev": "medium", "reward": 1000, "fund": 1},
    "m073": {"name": "abi.decode", "cls": "deserial", "sev": "high", "reward": 2000, "fund": 1},
    "m075": {"name": "block.number", "cls": "clock", "sev": "medium", "reward": 600, "fund": 1},
    "m076": {"name": "timestamp", "cls": "clock", "sev": "low", "reward": 400, "fund": 1},
    "m079": {"name": "decimals", "cls": "decimal", "sev": "low", "reward": 400, "fund": 1},
    "m083": {"name": "rounding", "cls": "rounding", "sev": "high", "reward": 2500, "fund": 1},
    "m084": {"name": "rounding", "cls": "rounding", "sev": "high", "reward": 2500, "fund": 1},
    "m085": {"name": "deadline", "cls": "logic", "sev": "medium", "reward": 800, "fund": 1},
    "m086": {"name": "pause", "cls": "logic", "sev": "low", "reward": 400, "fund": 1},
    "m087": {"name": "external call", "cls": "logic", "sev": "medium", "reward": 800, "fund": 1},
    "m090": {"name": "selfdestruct", "cls": "logic", "sev": "medium", "reward": 600, "fund": 1},
    "m098": {"name": "ssrf", "cls": "ssrf", "sev": "high", "reward": 1500, "fund": 0},
    "m102": {"name": "cors", "cls": "api", "sev": "high", "reward": 1200, "fund": 0},
    "m103": {"name": "secret", "cls": "api", "sev": "critical", "reward": 2500, "fund": 0},
    "m104": {"name": "exposure", "cls": "api", "sev": "high", "reward": 800, "fund": 0},
    "m108": {"name": "metadata", "cls": "api", "sev": "info", "reward": 200, "fund": 0},
    "m109": {"name": "graphql", "cls": "api", "sev": "medium", "reward": 600, "fund": 0},
}

SRC_HITS = [
    (r"\.call\{", "low level call", "logic", "medium", "m087"),
    (r"delegatecall\s*\(", "delegatecall", "upgrade", "critical", "m045"),
    (r"selfdestruct\s*\(", "selfdestruct", "logic", "medium", "m090"),
    (r"abi\.decode\s*\(", "abi.decode", "deserial", "high", "m073"),
    (r"msg\.value", "msg.value", "accounting", "medium", "m021"),
    (r"block\.number", "block.number", "clock", "medium", "m075"),
    (r"address\s*\(\s*this\s*\)\s*\.balance", "balance read", "accounting", "high", "m020"),
    (r"ecrecover\s*\(", "ecrecover", "signature", "high", "m040"),
    (r"\.transfer\s*\(", "transfer", "logic", "low", "m087"),
]

SCAN_TARGETS = 16
CRAWL = 10
SCAN_PATHS = 10
STEP_SECS = 120
MAX_CYCLES = 12

STEPS = ["intake", "conditions", "brief", "scan", "poc", "gate", "report"]

STOP = threading.Event()


def db():
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    return c


NEED = {
    "projects": {"url", "source", "slug", "state", "alive", "dry", "cycle", "created"},
    "findings": {"pid", "title", "sev", "cls", "file", "line", "evidence", "score",
                 "fund", "reward", "tool", "ts"},
    "log": {"pid", "msg", "ts"},
}

DDL = {
    "projects": """CREATE TABLE projects(
        id INTEGER PRIMARY KEY, url TEXT, source TEXT, slug TEXT,
        state TEXT DEFAULT 'queued', alive INTEGER DEFAULT 1, detail TEXT DEFAULT '',
        dry INTEGER DEFAULT 0, cycle INTEGER DEFAULT 0, last REAL DEFAULT 0,
        created REAL)""",
    "findings": """CREATE TABLE findings(
        id INTEGER PRIMARY KEY, pid INTEGER, title TEXT, sev TEXT, cls TEXT,
        file TEXT, line INTEGER, evidence TEXT, score INTEGER, fund INTEGER,
        reward INTEGER, tool TEXT, ts REAL, eligible INTEGER DEFAULT 0,
        poc_path TEXT DEFAULT '')""",
    "log": "CREATE TABLE log(id INTEGER PRIMARY KEY, pid INTEGER, msg TEXT, ts REAL)",
}

ALIAS = {
    "projects": {"stage": "state", "live": "alive", "note": "detail", "misses": "dry",
                 "rounds": "cycle", "addr": "url", "link": "url"},
    "findings": {"path": "file", "loc": "file", "where": "file", "kind": "cls",
                 "category": "cls", "text": "evidence", "detail": "evidence"},
    "log": {"text": "msg", "message": "msg", "body": "msg", "note": "msg", "line": "msg"},
    "conditions": {"data": "json", "policy": "json"},
}

PROJ_COLS = {
    "url": "TEXT", "source": "TEXT", "slug": "TEXT", "state": "TEXT DEFAULT 'queued'",
    "alive": "INTEGER DEFAULT 1", "detail": "TEXT DEFAULT ''", "dry": "INTEGER DEFAULT 0",
    "cycle": "INTEGER DEFAULT 0", "last": "REAL DEFAULT 0", "created": "REAL",
}

FIND_COLS = {
    "pid": "INTEGER", "title": "TEXT", "sev": "TEXT", "cls": "TEXT", "file": "TEXT",
    "line": "INTEGER", "evidence": "TEXT", "score": "INTEGER", "fund": "INTEGER",
    "reward": "INTEGER", "tool": "TEXT", "ts": "REAL", "eligible": "INTEGER DEFAULT 0",
    "poc_path": "TEXT DEFAULT ''",
}


def _cols(c, table):
    try:
        return {r[1] for r in c.execute("PRAGMA table_info(%s)" % table).fetchall()}
    except Exception:
        return set()


def _rebuild(c, table):
    """Rewrite a table to the current schema, carrying old column names across."""
    have = _cols(c, table)
    if not have or NEED[table] <= have:
        return
    old = table + "_old"
    c.execute("DROP TABLE IF EXISTS %s" % old)
    c.execute("ALTER TABLE %s RENAME TO %s" % (table, old))
    c.execute(DDL[table])
    new = [r[1] for r in c.execute("PRAGMA table_info(%s)" % table).fetchall()]
    src = {}
    for col in new:
        if col in have:
            src[col] = col
            continue
        for a, tgt in ALIAS.get(table, {}).items():
            if tgt == col and a in have:
                src[col] = a
                break
    if src:
        cols = ",".join(src)
        sel = ",".join(src[k] for k in src)
        try:
            c.execute("INSERT INTO %s(%s) SELECT %s FROM %s" % (table, cols, sel, old))
        except Exception:
            pass
    c.execute("DROP TABLE %s" % old)


def _ensure(c, table, cols):
    have = _cols(c, table)
    if not have:
        return
    for col, decl in cols.items():
        if col in have:
            continue
        try:
            c.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, col, decl))
        except Exception:
            continue
        src = next((k for k, v in ALIAS.get(table, {}).items() if v == col and k in have), None)
        if src:
            try:
                c.execute("UPDATE %s SET %s=%s WHERE %s IS NULL" % (table, col, src, col))
            except Exception:
                pass


def init():
    WORK.mkdir(exist_ok=True)
    with db() as c:
        c.execute("CREATE TABLE IF NOT EXISTS projects(id INTEGER PRIMARY KEY)")
        c.execute("CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY)")
        c.execute("CREATE TABLE IF NOT EXISTS log(id INTEGER PRIMARY KEY)")
        c.execute("CREATE TABLE IF NOT EXISTS conditions(pid INTEGER PRIMARY KEY, json TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)")
        _rebuild(c, "projects")
        _rebuild(c, "findings")
        _rebuild(c, "log")
        _ensure(c, "projects", PROJ_COLS)
        _ensure(c, "findings", FIND_COLS)
        _ensure(c, "conditions", {"json": "TEXT"})
        c.execute("UPDATE projects SET state='queued' WHERE state IS NULL")
        c.execute("UPDATE projects SET slug=id WHERE slug IS NULL OR slug=''")
        c.execute("UPDATE projects SET alive=1 WHERE alive IS NULL")
        c.execute("UPDATE projects SET dry=0 WHERE dry IS NULL")
        c.execute("UPDATE projects SET cycle=0 WHERE cycle IS NULL")


def getp(pid):
    with db() as c:
        r = c.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone()
    return dict(r) if r else None


def project_dir(pid):
    p = getp(pid)
    d = WORK / (p["slug"] if p else str(pid))
    d.mkdir(parents=True, exist_ok=True)
    return d


def slugify(url):
    u = urlparse(url if url.startswith("http") else "https://" + url)
    s = re.sub(r"[^a-z0-9]+", "-", (u.netloc + u.path).lower()).strip("-")
    return s[:70] or "target"


def add_project(url, source="manual", **kw):
    url = url.strip()
    if not url:
        return None
    with db() as c:
        if c.execute("SELECT id FROM projects WHERE url=?", (url,)).fetchone():
            return None
        cur = c.execute(
            "INSERT INTO projects(url,source,slug,state,created) VALUES(?,?,?,?,?)",
            (url, source, slugify(url), "queued", time.time()))
        return cur.lastrowid


def findings(pid, eligible_only=False):
    q = "SELECT * FROM findings WHERE pid=?"
    if eligible_only:
        q += " AND eligible=1"
    q += " ORDER BY score DESC, id"
    with db() as c:
        return [dict(r) for r in c.execute(q, (pid,)).fetchall()]


def getf(fid):
    with db() as c:
        r = c.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    return dict(r) if r else None


def add_finding(pid, tool, title, sev, file="", line=0, evidence="", **kw):
    t = TOOLS.get(tool, {})
    base = SEV_W.get(sev, 14) + t.get("reward", 0) // 400
    proof = 8 if (line or ":" in (file or "")) else 0
    score = min(100, base + min(12, len(evidence) // 120) + proof + kw.get("weight", 0))
    with db() as c:
        cur = c.execute(
            "INSERT INTO findings(pid,title,sev,cls,file,line,evidence,score,fund,reward,"
            "tool,ts) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (pid, title[:300], sev, t.get("cls", "logic"), file[:300], line,
             evidence[:20000], score, 1 if t.get("fund") else 0,
             kw.get("reward", 0), tool, time.time()))
        return cur.lastrowid


def _already(pid, title, file):
    with db() as c:
        return c.execute("SELECT 1 FROM findings WHERE pid=? AND title=? AND file=? LIMIT 1",
                         (pid, title[:300], file[:300])).fetchone() is not None


def _emit(pid, tool, title, sev, file, line, evidence, weight=0):
    if _already(pid, title, file):
        return 0
    add_finding(pid, tool, title, sev, file=file, line=line, evidence=evidence,
                reward=REWARD.get(TOOLS.get(tool, {}).get("cls", ""), 0), weight=weight)
    return 1


def deep_emit(pid, where):
    def emit(title, sev, cls, tool, tag, evidence, weight=0):
        return _emit(pid, tool, title, sev, "%s:%s" % (where, tag), 0, evidence, weight)
    return emit


def _uint(h):
    try:
        return int(h or "0x0", 16)
    except Exception:
        return 0


def log(pid, msg):
    with db() as c:
        c.execute("INSERT INTO log(pid,msg,ts) VALUES(?,?,?)", (pid, msg[:2000], time.time()))
    print("[%s] %s" % (pid, msg), flush=True)


def alive(pid):
    p = getp(pid)
    return bool(p and p["alive"])


def _is_platform(host):
    return any(d in host for d in PLATFORMS)


def _rpc(url, method, params):
    req = urllib.request.Request(
        url, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                              "params": params}).encode(),
        headers={"Content-Type": "application/json", "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        j = json.loads(r.read().decode())
    if "error" in j:
        raise RuntimeError(j["error"].get("message", "rpc error"))
    return j.get("result")


RPCS = {
    1: lambda c, m, p: _rpc("https://eth.llamarpc.com", m, p),
    10: lambda c, m, p: _rpc("https://mainnet.optimism.io", m, p),
    56: lambda c, m, p: _rpc("https://bsc-dataseed.binance.org", m, p),
    137: lambda c, m, p: _rpc("https://polygon-rpc.com", m, p),
    8453: lambda c, m, p: _rpc("https://mainnet.base.org", m, p),
    42161: lambda c, m, p: _rpc("https://arb1.arbitrum.io/rpc", m, p),
    59144: lambda c, m, p: _rpc("https://rpc.linea.build", m, p),
    534352: lambda c, m, p: _rpc("https://rpc.scroll.io", m, p),
}


def _http(url, method="GET", headers=None, data=None, follow=True):
    h = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    opener = urllib.request.build_opener(
        urllib.request.HTTPRedirectHandler() if follow else urllib.request.HTTPHandler())
    t0 = time.time()
    try:
        r = opener.open(req, timeout=TIMEOUT)
        return r.status, r.read(MAX_BODY), dict(r.headers), time.time() - t0
    except urllib.error.HTTPError as e:
        return e.code, e.read(MAX_BODY), dict(e.headers), time.time() - t0
    except Exception:
        return 0, b"", {}, time.time() - t0


def fetch(url, headers=None):
    c, b, h, _ = _http(url, headers=headers)
    return c, b.decode("utf-8", "ignore"), h


def fetch_full(url, headers=None):
    c, b, h, _ = _http(url, headers=headers)
    return (c, b.decode("utf-8", "ignore"),
            {k.lower(): v for k, v in h.items()}, h.get("Set-Cookie", ""))


def _is_html(hdrs, body):
    if "html" in (hdrs.get("content-type") or "").lower():
        return True
    low = (body or "")[:300].lower()
    return "<!doctype html" in low or "<html" in low


def _hdr_checks(pid, url, hdrs, cookies, body):
    n = 0
    low = {k.lower(): (v or "").lower() for k, v in hdrs.items()}
    if "x-frame-options" not in low and "frame-ancestors" not in (body or ""):
        n += _emit(pid, "m104", "clickjacking: no frame protection", "medium", url, 0,
                   "no X-Frame-Options and no frame-ancestors directive")
    if "content-security-policy" not in low:
        n += _emit(pid, "m104", "missing content-security-policy", "low", url, 0,
                   "no CSP header on %s" % url)
    if low.get("strict-transport-security") in (None, ""):
        n += _emit(pid, "m104", "missing hsts", "low", url, 0, "no HSTS header")
    if low.get("server"):
        n += _emit(pid, "m108", "server banner", "info", url, 0,
                   "Server: %s" % hdrs.get("Server"))
    if low.get("x-powered-by"):
        n += _emit(pid, "m108", "framework banner", "info", url, 0,
                   "X-Powered-By: %s" % hdrs.get("X-Powered-By"))
    if cookies:
        for ck in str(cookies).split(","):
            cl = ck.lower()
            if "secure" not in cl or "httponly" not in cl:
                n += _emit(pid, "m104", "cookie missing secure or httponly", "low", url, 0,
                           ck.strip()[:200])
                break
    return n


def _v_contact(b):
    return "contact:" in b.lower()


def _v_git(b):
    return "repositoryformatversion" in b.lower()


def _v_env(b):
    return bool(re.search(r"(?m)^[A-Z][A-Z0-9_]{2,}=", b)) and "<html" not in b[:200].lower()


def _v_spec(b):
    return ('"openapi"' in b or '"swagger"' in b) and '"paths"' in b


def _v_ds(b):
    return "Bud1" in b


def _v_status(b):
    return "apache server status" in b.lower() or "total accesses" in b.lower()


def _v_actuator(b):
    return "propertysources" in b.lower() or "activeprofiles" in b.lower()


def _v_backup(b):
    return len(b) > 40 and "<html" not in b[:200].lower()


WEB_PATHS = [
    ("/.well-known/security.txt", "security.txt published", "info", "m108", _v_contact),
    ("/.git/config", "git config exposed", "high", "m104", _v_git),
    ("/.env", "dotenv file exposed", "critical", "m104", _v_env),
    ("/swagger.json", "openapi schema exposed", "medium", "m108", _v_spec),
    ("/openapi.json", "openapi schema exposed", "medium", "m108", _v_spec),
    ("/.DS_Store", "ds_store exposed", "low", "m104", _v_ds),
    ("/server-status", "server-status exposed", "low", "m108", _v_status),
    ("/actuator/env", "spring actuator env exposed", "high", "m104", _v_actuator),
    ("/index.php.bak", "backup file exposed", "high", "m104", _v_backup),
    ("/config.php.bak", "backup file exposed", "high", "m104", _v_backup),
    ("/admin", "admin panel reachable", "low", "m104", _is_html),
    ("/graphql", "graphql endpoint answers", "medium", "m109",
     lambda b: '"data"' in b or "graphql" in b.lower()),
]

OPCODE_HITS = [
    ("ff", "selfdestruct opcode present", "logic", "medium", "m090"),
    ("32", "tx.origin opcode", "access", "medium", "m014"),
    ("42", "timestamp dependence", "clock", "low", "m076"),
]


def scan_web(pid, url):
    if not url.startswith("http"):
        url = "https://" + url
    host = urlparse(url).netloc
    platform_page = _is_platform(host)
    code, body, hdrs, cookies = fetch_full(url, headers={"Origin": "https://evil.example"})
    if not code:
        log(pid, "scan: %s unreachable" % url)
        return 0
    html = _is_html(hdrs, body)
    log(pid, "scan: %s %d, %d bytes%s%s" % (url, code, len(body),
                                            " html" if html else " asset",
                                            " platform" if platform_page else ""))
    if code >= 400:
        return _emit(pid, "m108", "target returns %d" % code, "low", url, 0,
                     "%s -> HTTP %d" % (url, code))
    n = _hdr_checks(pid, url, hdrs, cookies, body) if html else 0
    if hdrs.get("transfer-encoding") and hdrs.get("content-length"):
        n += _emit(pid, "m104", "transfer-encoding and content-length both set",
                   "medium", url, 0, "Transfer-Encoding: %s with Content-Length: %s"
                   % (hdrs.get("transfer-encoding"), hdrs.get("content-length")))
    if (hdrs.get("access-control-allow-origin") or "") == "https://evil.example":
        n += _emit(pid, "m102", "cors reflects arbitrary origin", "high", url, 0,
                   "Access-Control-Allow-Origin echoes the sent Origin")
    n += deep.secret_scan(deep_emit(pid, host), body)
    if not html or platform_page:
        return n
    base = url.rstrip("/")
    for path, title, sev, tool, valid in WEB_PATHS[:SCAN_PATHS]:
        c2, b2, _, _ = fetch_full(base + path)
        if c2 != 200 or len(b2) < 12 or not valid(b2):
            continue
        n += _emit(pid, tool, title, sev, base + path, 0, b2[:400], 3)
    q = "?url=http://169.254.169.254/latest/meta-data/"
    c3, b3, _, _ = fetch_full(base + q)
    if c3 == 200 and any(m in b3 for m in ("ami-id", "instance-id", "security-credentials")):
        n += _emit(pid, "m098", "ssrf reaches instance metadata", "high", base + q, 0,
                   b3[:400], 6)
    probe = base + "/bh-missing-0000'"
    c4, b4, _, _ = fetch_full(probe)
    low = (b4 or "").lower()
    for mark, title in (("sql", "sql error leaked"), ("syntax error", "parser error leaked"),
                        ("traceback", "stack trace leaked"),
                        ("at java.", "java stack trace leaked"),
                        ("warning:", "php warning leaked")):
        if mark in low and c4:
            n += _emit(pid, "m104", title, "medium", probe, 0, b4[:400], 2)
            break
    links = []
    for m in re.finditer(r'href="(/[\w./%\-?=&]{2,80})"', body):
        u = base + m.group(1)
        if u not in links and u != url:
            links.append(u)
    for u in links[:CRAWL]:
        c5, b5, h5, k5 = fetch_full(u)
        if c5 and c5 < 400 and _is_html(h5, b5):
            n += _hdr_checks(pid, u, h5, k5, b5)
    return n


def scan_contract(pid, addr):
    code, chain, rpc = None, None, None
    for ch, fn in RPCS.items():
        try:
            c = fn(ch, "eth_getCode", [addr, "latest"]) or "0x"
        except Exception:
            continue
        if len(c) > 4:
            code, chain, rpc = c, ch, fn
            break
    if not code:
        log(pid, "scan: %s no code on any chain" % addr)
        return 0
    d = project_dir(pid) / "code"
    d.mkdir(parents=True, exist_ok=True)
    (d / ("%s_%d.hex" % (addr, chain))).write_text(code, encoding="utf-8")
    n = 0
    size = (len(code) - 2) // 2
    log(pid, "scan: %s code %d bytes on %s" % (addr, size, CHAINS.get(chain, chain)))
    if size > 24576:
        n += _emit(pid, "m090", "contract exceeds the 24576 byte limit", "medium",
                   "%s:bytecode" % addr, 0, "runtime size %d bytes on chain %d"
                   % (size, chain), 2)
    try:
        impl = rpc(chain, "eth_getStorageAt", [addr, SLOT_IMPL, "latest"]) or "0x0"
    except Exception:
        impl = "0x0"
    try:
        admin = rpc(chain, "eth_getStorageAt", [addr, SLOT_ADMIN, "latest"]) or "0x0"
    except Exception:
        admin = "0x0"
    is_proxy = _uint(impl) != 0
    if is_proxy:
        n += _emit(pid, "m043", "eip1967 proxy", "info", "%s:slot" % addr, 0,
                   "implementation slot = %s" % impl, 1)
        if _uint(admin) == 0:
            n += _emit(pid, "m043", "proxy admin slot empty", "critical",
                       "%s:slot" % addr, 0,
                       "implementation set but admin slot is zero; upgrade authority "
                       "is either the impl itself or unset", 6)
    try:
        own = rpc(chain, "eth_call", [{"to": addr, "data": "0x" + SEL_OWNER}, "latest"])
    except Exception:
        own = None
    if own is not None and _uint(own) == 0:
        n += _emit(pid, "m011", "owner is the zero address", "critical",
                   "%s:owner" % addr, 0, "owner() returns 0x0 on %s" % addr, 6)
    body = code[2:] if code.startswith("0x") else code
    if SEL_UPGRADE in body or SEL_UPGRADE_CALL in body:
        n += _emit(pid, "m043", "upgrade entrypoint in bytecode", "high",
                   "%s:bytecode" % addr, 0,
                   "upgradeTo selector present on %s" % addr, 3)
    if not is_proxy:
        hit = body.find("f4")
        if hit >= 0:
            n += _emit(pid, "m045", "delegatecall without a proxy slot", "high",
                       "%s:bytecode" % addr, hit // 2,
                       "delegatecall at byte %d of %s, no eip1967 implementation slot"
                       % (hit // 2, addr), 4)
    n += deep.probe_contract(rpc, chain, addr, code, deep_emit(pid, addr), log)
    for op, title, cls, sev, tool in OPCODE_HITS:
        hit = body.find(op)
        if hit >= 0:
            n += _emit(pid, tool, title, sev, "%s:bytecode" % addr, hit // 2,
                       "opcode 0x%s at byte %d of %s" % (op, hit // 2, addr))
    return n


def scan_repo(pid, url):
    m = re.match(r"https?://github\.com/([^/]+)/([^/#?]+)", url)
    if not m:
        return 0
    repo = "%s/%s" % (m.group(1), m.group(2))
    c, tree, _ = fetch("https://api.github.com/repos/%s/git/trees/HEAD?recursive=1" % repo,
                       {"Accept": "application/vnd.github+json"})
    if c != 200:
        log(pid, "scan: repo %s tree %d" % (repo, c))
        return 0
    try:
        files = [t["path"] for t in json.loads(tree).get("tree", [])
                 if t.get("type") == "blob" and t["path"].endswith(".sol")]
    except Exception:
        return 0
    log(pid, "scan: repo %s %d solidity file(s)" % (repo, len(files)))
    n = 0
    for path in files[:60]:
        raw = "https://raw.githubusercontent.com/%s/HEAD/%s" % (repo, path)
        c2, body, _ = fetch(raw)
        if c2 != 200 or len(body) < 40:
            continue
        for pat, title, cls, sev, tool in SRC_HITS:
            mm = re.search(pat, body)
            if not mm:
                continue
            line = body[:mm.start()].count("\n") + 1
            n += _emit(pid, tool, title, sev, "%s/%s" % (repo, path), line,
                       body.splitlines()[line - 1][:300] if body.splitlines() else "")
        n += deep.source_rules(deep_emit(pid, "%s/%s" % (repo, path)), body, path)
    return n


def _ok_target(x):
    if ADDR_RE.fullmatch(x):
        return True
    u = urlparse(x)
    if u.scheme not in ("http", "https") or "." not in u.netloc:
        return False
    if any(j in u.netloc for j in JUNK):
        return False
    if u.path.lower().endswith(IMG_EXT):
        return False
    return True


def collect_targets(pid):
    p = getp(pid)
    if not p:
        return []
    out = []

    def push(x):
        x = x.strip().rstrip(".,);]'\"")
        if x and _ok_target(x) and x not in out:
            out.append(x)

    if p["url"].startswith("http"):
        push(p["url"])
    tf = project_dir(pid) / "targets.txt"
    if tf.exists():
        for line in tf.read_text(encoding="utf-8", errors="ignore").splitlines():
            push(line)
    for t in (contract.load_conditions(pid).get("targets") or []):
        if t.get("address"):
            push(t["address"])
    for name in ("details.txt", "details.html", "contract.json"):
        f = project_dir(pid) / name
        if not f.exists():
            continue
        try:
            txt = f.read_text(encoding="utf-8", errors="ignore")[:400000]
        except Exception:
            continue
        for m in ADDR_RE.finditer(txt):
            push(m.group(0))
        for m in URL_RE.finditer(txt):
            if "github.com" in m.group(0):
                push(m.group(0))
    return out[:SCAN_TARGETS]


def scan(pid):
    tg = collect_targets(pid)
    log(pid, "scan: %d target(s)" % len(tg))
    if not tg:
        return 0
    n = 0
    for t in tg:
        if not alive(pid):
            break
        try:
            if ADDR_RE.fullmatch(t):
                n += scan_contract(pid, t)
            elif "github.com" in t:
                n += scan_repo(pid, t)
            else:
                n += scan_web(pid, t)
        except Exception as e:
            log(pid, "scan: %s failed - %s" % (t[:60], e))
    return n


def _blockers(p, f):
    pol = contract.load_conditions(p["id"]) or {}
    b = []
    if not f["fund"]:
        b.append("not in funded scope")
    if not p["alive"]:
        b.append("target dead")
    for e in (pol.get("exclusions") or []):
        s = str(e).lower()
        if s and s in (f["file"] or "").lower():
            b.append("excluded: %s" % s[:40])
            break
    if (pol.get("poc") or {}).get("required") and not f["poc_path"] \
            and ADDR_RE.search(f["file"] or ""):
        b.append("poc required")
    if f["score"] < 62:
        b.append("score %d below 62" % f["score"])
    return b


def step_intake(pid):
    p = getp(pid)
    url = p["url"]
    host = urlparse(url if url.startswith("http") else "https://" + url).netloc
    if _is_platform(host):
        import platforms
        n = platforms.details(pid, url)
        if n < 200:
            log(pid, "intake: %d bytes, thin" % n)
            return 0
        log(pid, "intake: details saved %d bytes" % n)
        return 1
    code, body, _ = fetch(url)
    if not code:
        log(pid, "intake: unreachable")
        return 0
    d = project_dir(pid)
    (d / "details.html").write_text(body, encoding="utf-8")
    (d / "details.txt").write_text(re.sub(r"<[^>]+>", " ", body), encoding="utf-8")
    log(pid, "intake: details saved %d bytes" % len(body))
    return 1


def step_conditions(pid):
    n = contract.parse_conditions(pid)
    if n:
        log(pid, "conditions: %d field(s) parsed" % n)
        return 1
    log(pid, "conditions: nothing parsed - paste the brief")
    return 0


def step_brief(pid):
    d = project_dir(pid)
    b = d / "brief.md"
    if b.exists() and b.stat().st_size > 40:
        return 1
    p = getp(pid)
    pol = contract.load_conditions(pid)
    lines = ["# %s" % p["url"], "", "## Scope"]
    for t in (pol.get("targets") or []):
        lines.append("- %s %s" % (t.get("address", ""), t.get("label", "")))
    if not pol.get("targets"):
        lines.append("- see details")
    lines += ["", "## Exclusions"]
    for e in (pol.get("exclusions") or []):
        lines.append("- %s" % e)
    lines += ["", "## Constraints", json.dumps(pol.get("poc") or {}, indent=2)]
    b.write_text("\n".join(lines), encoding="utf-8")
    log(pid, "brief: written")
    return 1


def step_scan(pid):
    n = scan(pid)
    log(pid, "scan: %d finding(s)" % n)
    return 1 if n else 0


def step_poc(pid):
    d = project_dir(pid) / "poc"
    d.mkdir(parents=True, exist_ok=True)
    n = 0
    for f in findings(pid):
        if f["poc_path"] or f["score"] < 62:
            continue
        first = (f["evidence"] or "").splitlines()
        first = first[0][:200] if first else ""
        if ADDR_RE.search(f["file"] or ""):
            fn = d / ("%s.t.sol" % f["id"])
            body = ("// %s\n// %s:%s\npragma solidity ^0.8.20;\n\ncontract PoC_%d {\n"
                    "    function test_exploit() public {\n        // %s\n    }\n}\n"
                    % (f["title"], f["file"], f["line"], f["id"], first))
        else:
            fn = d / ("%s.http" % f["id"])
            pu = urlparse(f["file"])
            body = ("# %s\n# %s\nGET %s HTTP/1.1\nHost: %s\n\n# expect: %s\n"
                    % (f["title"], f["file"], pu.path or "/", pu.netloc, first))
        fn.write_text(body, encoding="utf-8")
        with db() as c:
            c.execute("UPDATE findings SET poc_path=? WHERE id=?", (str(fn), f["id"]))
        n += 1
    log(pid, "poc: %d written" % n)
    return 1


def gate(pid):
    p = getp(pid)
    fs = findings(pid)
    ok = []
    for f in fs:
        b = _blockers(p, f)
        if b:
            log(pid, "gate: #%d %s - %s" % (f["id"], f["title"][:50], "; ".join(b)))
        else:
            ok.append(f["id"])
    if ok:
        with db() as c:
            c.execute("UPDATE findings SET eligible=1 WHERE pid=? AND id IN (%s)"
                      % ",".join("?" * len(ok)), [pid] + ok)
    log(pid, "gate: %d findings, %d eligible" % (len(fs), len(ok)))
    return len(ok)


def step_gate(pid):
    return 1 if gate(pid) else 0


def step_report(pid):
    p = getp(pid)
    fs = findings(pid, eligible_only=True)
    if not fs:
        log(pid, "report: nothing eligible")
        return 0
    out = ["# %s" % p["url"], "", "## Summary", "",
           "%d eligible finding(s)." % len(fs), ""]
    for sev in ("critical", "high", "medium", "low", "info"):
        grp = [f for f in fs if f["sev"] == sev]
        if not grp:
            continue
        out += ["## %s" % sev.title(), ""]
        for f in grp:
            out += ["### [%s] %s" % (sev.upper(), f["title"]), "",
                    "- score: %d" % f["score"],
                    "- class: %s" % f["cls"],
                    "- where: `%s`%s" % (f["file"], ":%d" % f["line"] if f["line"] else ""),
                    "- tool: %s" % f["tool"]]
            if f["poc_path"]:
                out.append("- poc: `%s`" % Path(f["poc_path"]).name)
            out += ["", "```", (f["evidence"] or "")[:2000], "```", ""]
    fn = project_dir(pid) / "report.md"
    fn.write_text("\n".join(out), encoding="utf-8")
    log(pid, "report: %d section(s) -> %s" % (len(fs), fn.name))
    return 1


STEP_FN = {"intake": step_intake, "conditions": step_conditions, "brief": step_brief,
           "scan": step_scan, "poc": step_poc, "gate": step_gate, "report": step_report}


def run_step(pid, name):
    t0 = time.time()
    try:
        ok = STEP_FN[name](pid)
    except Exception as e:
        log(pid, "%s: error %s" % (name, e))
        ok = 0
    log(pid, "%s: %s (%.1fs)" % (name, "ok" if ok else "no", time.time() - t0))
    return ok


def _tick(stop):
    with db() as c:
        r = c.execute("SELECT id FROM projects WHERE state NOT IN ('done','parked') "
                      "ORDER BY (dry*100+cycle), id LIMIT 1").fetchone()
    if not r:
        time.sleep(2)
        return
    pid = r["id"]
    p = getp(pid)
    if not p:
        return
    if p["cycle"] >= MAX_CYCLES:
        with db() as c:
            c.execute("UPDATE projects SET state='done' WHERE id=?", (pid,))
        return
    idx = STEPS.index(p["state"]) if p["state"] in STEPS else 0
    ok = run_step(pid, STEPS[idx])
    nxt = STEPS[idx + 1] if idx + 1 < len(STEPS) else None
    with db() as c:
        if ok:
            c.execute("UPDATE projects SET state=?, dry=0, last=? WHERE id=?",
                      (nxt or "done", time.time(), pid))
        else:
            dry = p["dry"] + 1
            c.execute("UPDATE projects SET state=?, dry=?, cycle=cycle+1, last=? WHERE id=?",
                      ("parked" if dry >= 8 else STEPS[idx], dry, time.time(), pid))
    time.sleep(1)


def worker(stop):
    while not stop.is_set():
        try:
            _tick(stop)
        except Exception as e:
            print("worker: %s" % e, flush=True)
            time.sleep(3)


CT = {".html": "text/html; charset=utf-8", ".md": "text/markdown; charset=utf-8",
      ".txt": "text/plain; charset=utf-8", ".json": "application/json",
      ".http": "text/plain; charset=utf-8", ".sol": "text/plain; charset=utf-8",
      ".hex": "text/plain; charset=utf-8"}


class H(BaseHTTPRequestHandler):
    def log_message(self, fmt, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj))

    def _counts(self):
        with db() as c:
            return {r["state"]: r["n"] for r in c.execute(
                "SELECT state, COUNT(*) n FROM projects GROUP BY state").fetchall()}

    def do_GET(self):
        u = urlparse(self.path)
        parts = [x for x in u.path.split("/") if x]
        if u.path == "/":
            return self._send(200, (APP / "ui.html").read_text(encoding="utf-8"),
                              "text/html; charset=utf-8")
        if u.path == "/favicon.ico":
            return self._send(204, b"")
        if parts[:2] == ["api", "state"]:
            with db() as c:
                f = c.execute("SELECT COUNT(*) n FROM findings").fetchone()["n"]
                e = c.execute("SELECT COUNT(*) n FROM findings WHERE eligible=1").fetchone()["n"]
            return self._json({"paused": STOP.is_set(), "counts": self._counts(),
                               "findings": f, "eligible": e})
        if parts[:2] == ["api", "health"]:
            return self._json(self._counts())
        if parts[:2] == ["api", "projects"]:
            with db() as c:
                rows = [dict(r) for r in c.execute(
                    "SELECT p.*, (SELECT COUNT(*) FROM findings f WHERE f.pid=p.id) n "
                    "FROM projects p ORDER BY p.id DESC").fetchall()]
            return self._json(rows)
        if parts[:2] == ["api", "project"] and len(parts) > 2:
            p = getp(int(parts[2]))
            if not p:
                return self._json({"error": "not found"}, 404)
            with db() as c:
                p["log"] = [dict(r) for r in c.execute(
                    "SELECT msg,ts FROM log WHERE pid=? ORDER BY id DESC LIMIT 300",
                    (p["id"],)).fetchall()]
            p["findings"] = findings(p["id"])
            p["conditions"] = contract.load_conditions(p["id"])
            return self._json(p)
        if parts[:2] == ["api", "findings"] and len(parts) > 2:
            return self._json(findings(int(parts[2])))
        if parts[:2] == ["api", "report"] and len(parts) > 2:
            f = project_dir(int(parts[2])) / "report.md"
            if not f.exists():
                return self._send(200, "# no report yet\n", "text/markdown; charset=utf-8")
            return self._send(200, f.read_text(encoding="utf-8"),
                              "text/markdown; charset=utf-8")
        if parts[:2] == ["api", "file"] and len(parts) > 3:
            d = project_dir(int(parts[2])).resolve()
            f = (d / "/".join(parts[3:])).resolve()
            if f.parent != d and d not in f.parents:
                return self._json({"error": "outside"}, 403)
            if not f.is_file():
                return self._json({"error": "not found"}, 404)
            return self._send(200, f.read_bytes(),
                              CT.get(f.suffix.lower(), "application/octet-stream"))
        return self._json({"error": "not found"}, 404)

    def do_POST(self):
        u = urlparse(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            data = json.loads(raw or b"{}")
        except Exception:
            data = {}
        parts = [x for x in u.path.split("/") if x]
        if parts[:2] == ["api", "pause"]:
            STOP.set()
            return self._json({"paused": True})
        if parts[:2] == ["api", "resume"]:
            STOP.clear()
            return self._json({"paused": False})
        if parts[:2] == ["api", "autostart"]:
            STOP.clear()
            with db() as c:
                c.execute("UPDATE projects SET state='queued', dry=0, cycle=0 "
                          "WHERE state='parked'")
            return self._json({"paused": False})
        if parts[:2] == ["api", "add"]:
            return self._json({"id": add_project(data.get("url", ""))})
        if parts[:2] == ["api", "manual"]:
            if parts[2:3] == ["bulk"]:
                return self._json(manual.bulk(data.get("text", "")))
            if len(parts) > 2:
                return self._json(manual.save(int(parts[2]), data))
        if parts[:2] == ["api", "scan"] and len(parts) > 2:
            return self._json({"n": scan(int(parts[2]))})
        if parts[:2] == ["api", "poc"] and len(parts) > 2:
            return self._json({"n": step_poc(int(parts[2]))})
        if parts[:2] == ["api", "reset"] and len(parts) > 2:
            pid = int(parts[2])
            with db() as c:
                c.execute("UPDATE projects SET state='queued', dry=0, cycle=0, alive=1 "
                          "WHERE id=?", (pid,))
                c.execute("UPDATE findings SET eligible=0 WHERE pid=?", (pid,))
            return self._json({"ok": True})
        if parts[:2] == ["api", "delete"] and len(parts) > 2:
            pid = int(parts[2])
            p = getp(pid)
            with db() as c:
                c.execute("DELETE FROM findings WHERE pid=?", (pid,))
                c.execute("DELETE FROM conditions WHERE pid=?", (pid,))
                c.execute("DELETE FROM log WHERE pid=?", (pid,))
                c.execute("DELETE FROM projects WHERE id=?", (pid,))
            if p:
                d = WORK / p["slug"]
                if d.is_dir():
                    for f in sorted(d.rglob("*"), reverse=True):
                        try:
                            f.unlink() if f.is_file() else f.rmdir()
                        except Exception:
                            pass
                    try:
                        d.rmdir()
                    except Exception:
                        pass
            return self._json({"ok": True})
        return self._json({"error": "not found"}, 404)


def main():
    init()
    port = 8787
    argv = sys.argv[1:]
    if "--port" in argv:
        port = int(argv[argv.index("--port") + 1])
    if "--project" in argv:
        print("added", add_project(argv[argv.index("--project") + 1]))
    for _ in range(2):
        threading.Thread(target=worker, args=(STOP,), daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    print("bh on http://127.0.0.1:%d" % port, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        STOP.set()


if __name__ == "__main__":
    main()