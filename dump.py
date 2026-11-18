#!/usr/bin/env python3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import bh, contract

if len(sys.argv) < 2:
    sys.exit("usage: dump.py <url-or-file>")
arg = sys.argv[1]
text = Path(arg).read_text(encoding="utf-8", errors="ignore") if Path(arg).exists() else ""
pol = contract.parse_program(arg, None, text=text)
for k in ("scope_model", "targets", "severity", "poc", "exclusions", "submit", "template"):
    print("\n== %s ==" % k)
    print(pol.get(k))
print("\n== methods ==\n%d registered, %d fund" % (len(bh.TOOLS), len(bh.FUND)))