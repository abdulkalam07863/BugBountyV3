"""Manual program entry: presets, parsing, validation, normalisation."""
import re

KNOWN = {"solidity", "rust", "go", "python", "js", "php", "ruby", "java", "c", "web", "unknown"}

PRESETS = {
    "evm": {"label": "EVM / Solidity", "toolchain": "solidity", "poc": True,
            "tiers": [("critical", 1000000), ("high", 50000), ("medium", 10000), ("low", 1000)],
            "template": ["summary", "affected", "impact", "likelihood", "poc", "fix"],
            "submit": "email"},
    "solana": {"label": "Solana / Rust", "toolchain": "rust", "poc": True,
               "tiers": [("critical", 500000), ("high", 25000), ("medium", 5000), ("low", 500)],
               "template": ["summary", "affected", "impact", "poc", "fix"], "submit": "email"},
    "web": {"label": "Web app / API", "toolchain": "web", "poc": False,
            "tiers": [("critical", 20000), ("high", 5000), ("medium", 1000), ("low", 200)],
            "template": ["summary", "steps", "impact", "fix"], "submit": "form"},
    "generic": {"label": "Generic source repo", "toolchain": "unknown", "poc": False,
                "tiers": [("critical", 10000), ("high", 2000), ("medium", 500), ("low", 100)],
                "template": ["summary", "affected", "impact", "fix"], "submit": "email"},
}

ADDR = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
SOL = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")
REPO = re.compile(r"\b(?:https?://)?(?:www\.)?github\.com/([\w.-]+)/([\w.-]+)")
DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
TIERLINE = re.compile(r"\b(critical|high|medium|low|informational|info)\b[^\n$]{0,60}?"
                      r"\$\s?([\d,]+(?:\.\d+)?)\s*([kKmM])?", re.I)
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b")
EXCL_HEAD = re.compile(r"out of scope|exclusion|not in scope|non-?vuln|non-?submission", re.I)
SCALE = {"k": 1_000, "m": 1_000_000}


def presets():
    return [{"id": k, "label": v["label"], "toolchain": v["toolchain"], "poc": v["poc"],
             "tiers": [{"tier": t, "max": m} for t, m in v["tiers"]],
             "template": v["template"], "submit": v["submit"]} for k, v in PRESETS.items()]


def _money(num, suf):
    try:
        v = float(num.replace(",", ""))
    except ValueError:
        return 0
    return int(v * SCALE.get((suf or "").lower(), 1))


def parse_block(text):
    """Best-effort draft from pasted program text. Never raises."""
    text = text or ""
    d = {"name": "", "url": "", "toolchain": "unknown", "max": 0, "rank": 60, "scope": [],
         "tiers": [], "poc": False, "channel": "", "address": "", "exclusions": [],
         "template": [], "notes": ""}
    for line in text.splitlines()[:12]:
        s = line.strip()
        if s and not d["name"] and 2 <= len(s) <= 80 and not s.lower().startswith("http"):
            d["name"] = s
            break
    m = re.search(r"https?://[^\s)>\]]+", text)
    if m:
        d["url"] = m.group(0).rstrip(".,;")
    r = REPO.search(text)
    if r:
        d["scope"].append("https://github.com/%s/%s" % (r.group(1), r.group(2).rstrip(".")))
        d["toolchain"] = "rust"
    for a in ADDR.findall(text):
        if a not in d["scope"]:
            d["scope"].append(a)
    if not d["scope"]:
        for s in SOL.findall(text):
            if len(s) >= 32 and not s.startswith("0x") and s not in d["scope"]:
                d["scope"].append(s)
                d["toolchain"] = "rust"
    low = text.lower()
    if re.search(r"\bsolidity|smart contract|\bevm\b|erc-?20", low) and d["toolchain"] == "unknown":
        d["toolchain"] = "solidity"
    if re.search(r"\banchor\b|\bsolana\b|\bpda\b", low):
        d["toolchain"] = "rust"
    if not d["scope"]:
        for h in DOMAIN.findall(text):
            h = h.lower()
            if h.endswith((".png", ".jpg", ".svg", ".js", ".css")):
                continue
            d["scope"].append(h)
            if d["toolchain"] == "unknown" and not re.match(r"^docs?\.", h):
                d["toolchain"] = "web"
            if len(d["scope"]) >= 6:
                break
    for m2 in TIERLINE.finditer(text):
        d["tiers"].append((m2.group(1).lower().replace("informational", "info"),
                           _money(m2.group(2), m2.group(3))))
    if d["tiers"]:
        d["max"] = max(v for _, v in d["tiers"])
    if re.search(r"\b(poc|proof of concept)\b[^\n]{0,40}\b(required|must|mandatory)\b", low):
        d["poc"] = True
    e = EMAIL.search(text)
    if e:
        d["channel"], d["address"] = "email", e.group(0)
    elif re.search(r"\bsubmit[^\n]{0,40}\bform\b", low):
        d["channel"] = "form"
    grab = False
    for line in text.splitlines():
        if EXCL_HEAD.search(line):
            grab = True
            continue
        if grab:
            s = line.strip(" -*\t")
            if not s:
                if d["exclusions"]:
                    grab = False
                continue
            if len(s) < 120:
                d["exclusions"].append(s)
            if len(d["exclusions"]) >= 25:
                break
    p = PRESETS.get(d["toolchain"] if d["toolchain"] in PRESETS else "generic")
    d["template"] = list(p["template"])
    return d


def _scope(raw):
    out = []
    for item in raw if isinstance(raw, list) else str(raw or "").splitlines():
        s = str(item).strip().strip(",")
        if not s:
            continue
        r = REPO.search(s)
        if r:
            s = "https://github.com/%s/%s" % (r.group(1), r.group(2).rstrip("."))
        if s not in out:
            out.append(s)
    return out[:300]


def _tiers(raw):
    out = []
    for row in raw or []:
        if isinstance(row, dict):
            tier, mx = row.get("tier"), row.get("max")
        else:
            pair = list(row) + [0]
            tier, mx = pair[0], pair[1]
        tier = str(tier or "").lower().replace("informational", "info")
        if tier not in ("critical", "high", "medium", "low", "info"):
            continue
        try:
            mx = max(0, min(10_000_000, int(float(mx or 0))))
        except (TypeError, ValueError):
            mx = 0
        if tier not in [t for t, _ in out]:
            out.append((tier, mx))
    return out


def validate(d, draft=False):
    """Return (clean, errors)."""
    errs = []
    name = str(d.get("name") or "").strip()[:80]
    if len(name) < 2:
        errs.append("name needs at least 2 characters")
    url = str(d.get("url") or "").strip()[:400]
    if url and not re.match(r"^https?://", url) and not REPO.search(url) \
            and not ADDR.fullmatch(url) and not SOL.fullmatch(url):
        errs.append("url must be http(s), a github repo, or an address")
    toolchain = str(d.get("toolchain") or "unknown").lower()
    if toolchain not in KNOWN:
        toolchain = "unknown"
    try:
        mx = max(0, min(10_000_000, int(float(d.get("max") or 0))))
    except (TypeError, ValueError):
        mx = 0
        errs.append("max bounty must be a number")
    try:
        rank = max(1, min(100, int(float(d.get("rank") or 60))))
    except (TypeError, ValueError):
        rank = 60
    scope = _scope(d.get("scope"))
    tiers = _tiers(d.get("tiers"))
    if not draft and not scope:
        errs.append("at least one scope asset is required")
    poc = d.get("poc")
    if isinstance(poc, str):
        poc = poc.strip().lower() in ("1", "true", "yes", "on")
    poc = bool(poc) or toolchain in ("solidity", "rust")
    channel = str(d.get("channel") or "").strip().lower()
    if channel not in ("email", "form", "platform", "other", ""):
        channel = "other"
    address = str(d.get("address") or "").strip()[:300]
    if channel == "email" and address and not EMAIL.search(address):
        errs.append("submission address is not an email")
    exclusions = [str(s).strip()[:200] for s in (d.get("exclusions") or []) if str(s).strip()][:60]
    template = [str(s).strip()[:40] for s in (d.get("template") or []) if str(s).strip()][:12]
    return {"name": name, "url": url, "toolchain": toolchain, "max": mx, "rank": rank,
            "scope": scope, "tiers": tiers, "poc": poc, "channel": channel,
            "address": address, "exclusions": exclusions, "template": template,
            "notes": str(d.get("notes") or "").strip()[:4000], "draft": bool(draft)}, errs


def slugify(name, pid=0):
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")[:48]
    return "%s-%d" % (s or "manual", pid)


def conditions_from(c):
    return {"scope_model": "manual",
            "targets": [{"address": a, "chain": "manual", "kind": "manual"}
                        for a in c["scope"]],
            "severity": [{"tier": t, "band": ("<=$%d" % m) if m else "", "definition": ""}
                         for t, m in c["tiers"]],
            "poc": {"required": c["poc"], "framework": "", "source": "manual"},
            "exclusions": {"surfaces": c["exclusions"], "non_vulns": [],
                           "non_submissions": []},
            "submit": {"channel": c["channel"], "address": c["address"], "subject_fmt": ""},
            "template": c["template"], "one_page": False, "constraints": {}}


def bulk(text):
    """name | url | type | max | asset,asset"""
    made, bad = [], []
    for i, line in enumerate((text or "").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        while len(parts) < 5:
            parts.append("")
        clean, errs = validate({"name": parts[0], "url": parts[1],
                                "toolchain": parts[2] or "unknown", "max": parts[3],
                                "scope": [s for s in re.split(r"[,\s]+", parts[4]) if s]})
        if errs:
            bad.append((i, line[:60], "; ".join(errs)))
        else:
            made.append(clean)
    return made, bad