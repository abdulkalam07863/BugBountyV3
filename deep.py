"""deep.py - read-only chain probes and source rules.

Every check returns the value it read as evidence, so the gate weighs a fact
instead of a keyword.
"""

PAD = lambda x: format(x, "064x")

SEL_TOTAL_ASSETS = "01e1d114"
SEL_TOTAL_SUPPLY = "18160ddd"
SEL_DECIMALS = "313ce567"
SEL_OWNER = "8da5cb5b"
SEL_PAUSED = "5c975abb"
SEL_NAME = "06fdde03"
SEL_ALLOWANCE = "dd62ed3e"
SEL_PERMIT = "d505accf"
SEL_DOMAIN = "3644e515"
SEL_CONV_ASSETS = "07a2d13a"
SEL_CONV_SHARES = "c6e6f592"
SEL_PREVIEW_REDEEM = "4cdad506"
SEL_PREVIEW_WITHDRAW = "0a28a477"
SEL_FLASH_V2 = "23e30c8b"
SEL_FLASH_V3 = "920f5c84"

SLOT_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
PERMIT2 = "000000000022d473030f116ddee9f6b43ac78ba3"
MAXU = (1 << 256) - 1


def _u(h):
    if not h or h == "0x":
        return 0
    try:
        return int(h, 16)
    except (TypeError, ValueError):
        return 0


def _call(rpc, chain, addr, data):
    try:
        return rpc(chain, "eth_call", [{"to": addr, "data": "0x" + data}, "latest"])
    except Exception:
        return None


def _slot(rpc, chain, addr, slot):
    try:
        return rpc(chain, "eth_getStorageAt", [addr, slot, "latest"]) or "0x0"
    except Exception:
        return "0x0"


def probe_contract(rpc, chain, addr, code, emit, log):
    """emit(title, sev, cls, tool, tag, evidence, weight) -> count."""
    n = 0
    body = code[2:] if code.startswith("0x") else code

    impl = _slot(rpc, chain, addr, SLOT_IMPL)
    impl_addr = "0x" + impl[-40:]
    is_proxy = bool(_u(impl))

    if is_proxy:
        try:
            icode = rpc(chain, "eth_getCode", [impl_addr, "latest"]) or "0x"
        except Exception:
            icode = "0x"
        if len(icode) < 4:
            n += emit("proxy implementation holds no code", "critical", "upgrade",
                      "m043", "impl",
                      "implementation slot resolves to %s, which has no runtime code "
                      "on chain %d" % (impl_addr, chain), 8)
        own = _call(rpc, chain, impl_addr, SEL_OWNER)
        if own is not None and _u(own) == 0:
            n += emit("implementation has no owner", "high", "access", "m011",
                      "implowner",
                      "owner() on implementation %s returns zero; an unowned "
                      "implementation can be re-initialised" % impl_addr, 5)
        s0 = _u(_slot(rpc, chain, impl_addr, "0x0"))
        if s0:
            n += emit("implementation storage slot 0 is populated", "medium",
                      "storage", "m034", "implslot0",
                      "slot 0 of implementation %s = 0x%x" % (impl_addr, s0), 3)

    for sel, label, tool in ((SEL_FLASH_V2, "onFlashLoan", "m026"),
                             (SEL_FLASH_V3, "executeOperation", "m026")):
        if sel in body:
            n += emit("flash loan callback %s exposed" % label, "high", "flashloan",
                      tool, "bytecode",
                      "selector 0x%s (%s) in runtime code of %s; initiator and repay "
                      "checks must hold before any state write" % (sel, label, addr), 5)

    one = PAD(10 ** 18)
    ca = _u(_call(rpc, chain, addr, SEL_CONV_ASSETS + one))
    pr = _u(_call(rpc, chain, addr, SEL_PREVIEW_REDEEM + one))
    if ca and pr and pr > ca:
        n += emit("previewRedeem rounds above convertToAssets", "high", "rounding",
                  "m084", "rounding",
                  "previewRedeem(1e18)=%d vs convertToAssets(1e18)=%d on %s; redeem "
                  "pays above the exact ratio" % (pr, ca, addr), 5)
    cs = _u(_call(rpc, chain, addr, SEL_CONV_SHARES + one))
    pw = _u(_call(rpc, chain, addr, SEL_PREVIEW_WITHDRAW + one))
    if cs and pw and pw < cs:
        n += emit("previewWithdraw rounds below convertToShares", "high", "rounding",
                  "m083", "rounding",
                  "previewWithdraw(1e18)=%d vs convertToShares(1e18)=%d on %s; withdraw "
                  "undercharges shares" % (pw, cs, addr), 5)

    if SEL_PERMIT in body:
        ds = _call(rpc, chain, addr, SEL_DOMAIN)
        if ds is None or _u(ds) == 0:
            n += emit("permit present but DOMAIN_SEPARATOR is dead", "high",
                      "signature", "m040", "permit",
                      "permit selector present on %s but DOMAIN_SEPARATOR() reverts or "
                      "returns zero" % addr, 5)

    a = _u(_call(rpc, chain, addr, SEL_TOTAL_ASSETS))
    s = _u(_call(rpc, chain, addr, SEL_TOTAL_SUPPLY))
    if a == 0 and s:
        n += emit("totalAssets zero while supply is live", "high", "accounting",
                  "m018", "assets",
                  "totalAssets()=0 but totalSupply()=%d on %s" % (s, addr), 4)

    al = _u(_call(rpc, chain, addr,
                  SEL_ALLOWANCE + PAD(int(addr, 16)) + PAD(int(PERMIT2, 16))))
    if al == MAXU:
        n += emit("unbounded Permit2 allowance", "medium", "token", "m059", "permit2",
                  "allowance(%s, Permit2) = type(uint256).max" % addr, 3)

    pz = _call(rpc, chain, addr, SEL_PAUSED)
    if pz is not None and _u(pz):
        n += emit("contract is paused", "low", "logic", "m086", "paused",
                  "paused() returns true on %s" % addr, 1)
    dec = _u(_call(rpc, chain, addr, SEL_DECIMALS))
    if dec and (dec == 0 or dec > 18):
        n += emit("non-standard token decimals", "low", "decimal", "m079", "decimals",
                  "decimals() = %d on %s" % (dec, addr), 1)
    nm = _call(rpc, chain, addr, SEL_NAME)
    if nm is not None and len(nm) <= 130:
        n += emit("token has empty name", "info", "token", "m090", "name",
                  "name() returns %s on %s" % (nm or "0x", addr), 0)
    return n


SRC_RULES = [
    (r"abi\.decode\s*\(", "abi.decode outside try/catch", "deserial", "high", "m073", 4),
    (r"block\.number", "block.number used as a clock", "clock", "medium", "m075", 3),
    (r"address\s*\(\s*this\s*\)\s*\.balance", "logic reads address(this).balance",
     "accounting", "high", "m020", 4),
    (r"delegatecall\s*\(", "delegatecall to untrusted target", "upgrade", "critical",
     "m045", 5),
    (r"selfdestruct\s*\(", "selfdestruct present", "logic", "medium", "m090", 2),
    (r"\.call\{[^}]*value", "value-bearing external call", "logic", "medium", "m087", 2),
    (r"delete\s+\w+\s*\[", "mapping element deleted", "storage", "medium", "m037", 2),
    (r"uint(128|96|64|32|16|8)\s*\(\s*\w+\s*\)", "narrowing cast", "precision", "high",
     "m031", 3),
    (r"/\s*[A-Za-z_]\w*\s*\*", "division before multiply", "precision", "high", "m029", 4),
    (r"ecrecover\s*\(", "ecrecover without domain binding", "signature", "high", "m040", 3),
    (r"require\s*\(\s*\w+\s*!=\s*address\s*\(\s*0\s*\)", "zero address guard present",
     "logic", "info", "m011", 0),
    (r"nonReentrant", "reentrancy guard present", "reentrancy", "info", "m001", 0),
]


def source_rules(emit, body, path):
    import re
    n = 0
    lines = body.splitlines()
    for pat, title, cls, sev, tool, weight in SRC_RULES:
        m = re.search(pat, body)
        if not m:
            continue
        line = body[:m.start()].count("\n") + 1
        snip = "\n".join(lines[max(0, line - 2):line + 1])[:500]
        n += emit(title, sev, cls, tool, str(line), snip, weight)
    return n


SECRET_HITS = [
    (r"AKIA[0-9A-Z]{16}", "aws access key in page source", "critical", "m103", 7),
    (r"sk_live_[0-9a-zA-Z]{20,}", "stripe live key in page source", "critical", "m103", 7),
    (r"AIza[0-9A-Za-z_\-]{35}", "google api key in page source", "medium", "m103", 3),
    (r"gh[pousr]_[0-9A-Za-z]{36,}", "github token in page source", "high", "m103", 5),
    (r"https://[a-z0-9\-]+\.infura\.io/v3/[0-9a-f]{32}", "infura project id exposed",
     "medium", "m103", 2),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "private key in page source",
     "critical", "m103", 8),
    (r"(?:^|\s)(?:[a-z]{3,8}\s+){11}[a-z]{3,8}(?:\s|$)", "bip39 mnemonic candidate",
     "high", "m103", 5),
]


def secret_scan(emit, body):
    import re
    n = 0
    for pat, title, sev, tool, weight in SECRET_HITS:
        m = re.search(pat, body, re.M)
        if not m:
            continue
        n += emit(title, sev, "api", tool, "body",
                  "matched %r at offset %d: %s"
                  % (pat[:28], m.start(), m.group(0)[:120]), weight)
    return n