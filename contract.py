"""contract.py - parse the brief into conditions."""
import json, re
from pathlib import Path

import bh

ADDR = re.compile(r"0x[a-fA-F0-9]{40}")
FIELD = re.compile(r"(?im)^\s*(max|min|reward|poc|poc required|kyc|exclusions?|out of scope)"
                   r"\s*[:=-]\s*(.+)$")
MAX_SEV = {"critical", "high", "medium", "low", "info"}


def load_conditions(pid):
    with bh.db() as c:
        r = c.execute("SELECT json FROM conditions WHERE pid=?", (pid,)).fetchone()
    if not r:
        return {}
    try:
        return json.loads(r["json"])
    except Exception:
        return {}


def save_conditions(pid, pol):
    with bh.db() as c:
        c.execute("INSERT INTO conditions(pid,json) VALUES(?,?) "
                  "ON CONFLICT(pid) DO UPDATE SET json=excluded.json",
                  (pid, json.dumps(pol)))


def parse_conditions(pid):
    d = bh.project_dir(pid)
    text = ""
    t = d / "details.txt"
    h = d / "details.html"
    if t.exists():
        text = t.read_text(encoding="utf-8", errors="ignore")
    elif h.exists():
        text = re.sub(r"<[^>]+>", " ", h.read_text(encoding="utf-8", errors="ignore"))
    text = re.sub(r"(?m)^[A-Za-z0-9+/=]{24,}$", " ", text)
    if not text:
        return 0
    pol = load_conditions(pid) or {"targets": [], "exclusions": [], "poc": {}}
    n = 0
    for m in ADDR.finditer(text):
        a = m.group(0)
        if not any(t_["address"] == a for t_ in pol["targets"]):
            pol["targets"].append({"address": a, "label": ""})
            n += 1
    for m in FIELD.finditer(text):
        k = m.group(1).lower().strip()
        v = m.group(2).strip()[:200]
        if k == "poc" or k == "poc required":
            pol["poc"]["required"] = v.lower() not in ("no", "false", "0")
            n += 1
        elif k.startswith("exclusion") or k == "out of scope":
            for part in re.split(r"[,;]", v):
                part = part.strip()
                if part and part not in pol["exclusions"]:
                    pol["exclusions"].append(part)
                    n += 1
        elif k in ("max", "min", "reward", "kyc"):
            pol[k] = v
            n += 1
    save_conditions(pid, pol)
    return n


def summary(pid):
    pol = load_conditions(pid)
    return ("targets=%d exclusions=%d poc=%s"
            % (len(pol.get("targets") or []), len(pol.get("exclusions") or []),
               (pol.get("poc") or {}).get("required")))