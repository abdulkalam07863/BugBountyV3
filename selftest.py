#!/usr/bin/env python3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def read(p):
    raw = p.read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", "replace")
    for enc in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("utf-8", "replace")


for f in ("bh.py", "platforms.py", "contract.py", "manual.py", "ui.html"):
    if not (ROOT / f).exists():
        sys.exit("missing: " + f)

if len((ROOT / "ui.html").read_bytes()) < 20000:
    sys.exit("ui.html is only %d bytes — truncated" % (ROOT / "ui.html").stat().st_size)

try:
    import bh
except Exception as ex:
    sys.exit("import failed: %s: %s" % (type(ex).__name__, ex))

bad = []
for n in ("intake", "conditions", "brief", "gate", "report", "poc"):
    if n not in bh.STEP_FN or not callable(bh.STEP_FN[n]):
        bad.append("step " + n)
for k, v in bh.TOOLS.items():
    if not v.get("name") or not v.get("cls"):
        bad.append("tool " + k)
if len(bh.TOOLS) < 100:
    bad.append("tool count %d" % len(bh.TOOLS))
for r in ("/api/state", "/api/manual", "/api/manual/parse", "/api/health", "/api/attack"):
    if r not in read(ROOT / "bh.py"):
        bad.append("route " + r)

ui = read(ROOT / "ui.html")
for n in ("/api/manual", "/api/state", "render", "openManual", "parse into form"):
    if n not in ui:
        bad.append("ui missing " + n)

envf = ROOT / ".env"
if not envf.exists():
    bad.append(".env missing")
else:
    keys = [l.split("=", 1)[0].strip()
            for l in read(envf).splitlines()
            if "=" in l and not l.strip().startswith("#")]
    dup = {k for k in keys if keys.count(k) > 1}
    if dup:
        bad.append("duplicate .env keys: " + ", ".join(sorted(dup)))
    for k in ("ETH_RPC_URL", "RPC_BASE", "ETHERSCAN_KEY", "GITHUB_TOKEN", "BH_THRESHOLD"):
        if k not in keys:
            bad.append(".env missing " + k)

if bad:
    print("SELFTEST FAIL")
    for b in bad:
        print("  -", b)
    sys.exit(1)
print("selftest ok: %d steps, %d methods, %d fund" % (len(bh.STEP_FN), len(bh.TOOLS), len(bh.FUND)))