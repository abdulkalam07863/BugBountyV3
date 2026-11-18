#!/usr/bin/env python3
"""Report missing globals and duplicate function definitions in bh.py."""
import ast
import collections
import sys

import bh

REQ = ["LOCK", "STOP", "RUNNING", "RUN_LOCK", "JOBQ", "BOUNTY_PATHS", "DEFAULT_TIERS",
       "COND_DEFAULT", "CONSTRAINT_KEYS", "INS_COLS", "INS_PROJECT", "INS_PROJECT_STATUS",
       "PROGRAMS", "PROGRAM_BY_KEY", "REPAIR_LOG", "REPAIR_KINDS", "TOOLS", "WORK", "DB",
       "UI", "SEV_BASE", "BAND", "SEV_ORDER", "EXT", "TYPES", "SKIP_DIRS", "SOURCE_DIRS",
       "NOISE_DIRS", "MANIFESTS", "GH_LANG", "CONF_LABEL", "ADDR_RE", "REPO_RE", "GH_URL_RE",
       "CONTRACT_RE", "FN_RE", "C4_REPO", "TRAIL_SLASH_HOSTS", "USD_RE", "HEAD_RE",
       "DOCS_RE", "CODE_RE", "EMAIL_RE", "WEB_WORDS", "WEBISH", "APP_URL_RE", "ASSET_PATH",
       "APP_BAD_HOST", "JSON_SCRIPTS", "NEXT_DATA", "NUXT_DATA", "INIT_STATE", "CHUNK_RE",
       "IMPL_SLOT", "BEACON_SLOT", "SEL_TOTAL_ASSETS", "SEL_TOTAL_SUPPLY", "CHAIN",
       "STEP_FN", "PREP_STEPS", "ACQUIRE_STEPS", "LEVEL_STEPS", "LEVEL_NAME", "BRIEF_TMPL",
       "TMPL_STD", "TMPL_ALADDIN", "SEV_LINK", "MD_LINK", "BARE_LINK", "USD", "TYPE_LABEL"]

FUNCS = ["db", "init", "seed_programs", "setp", "getp", "slugify", "log", "purge", "restart",
         "sh", "rmtree_force", "norm_url", "fetch", "fetch_host", "rpc", "eth_call",
         "fork_block", "safe_fork_block", "es_source", "impl_of", "clean_src", "brace_span",
         "units", "add_finding", "score_findings", "best_score", "best_rank", "files_for",
         "sol_files", "run_pat", "reg", "hammer", "ext", "lang_ok", "tools_for",
         "cond_path", "load_cond", "seed_conditions", "policy", "parse_conditions", "judge",
         "readiness", "poc_stub", "st_intake", "st_conditions", "st_brief", "st_gate",
         "st_scopeaddr", "st_onchain", "st_onchain_stage", "st_value", "st_surface",
         "st_clone", "st_toolchain", "st_deps", "st_build", "st_static", "st_baseline",
         "st_harness", "st_symbolic", "st_fork", "st_adversarial", "st_hammer", "st_triage",
         "st_report", "st_poc", "run_step", "has_surface", "_run_once",
         "attack_until_finding", "attack_plan", "start_attack", "stop_attack", "running_pids",
         "start_all", "stop_all", "discover", "pool_worker", "serve", "main",
         "program_spec", "web_only", "web_target", "web_disabled", "details_ok", "langs_of"]

missing = [n for n in REQ + FUNCS if not hasattr(bh, n)]

src = open("bh.py", encoding="utf-8").read()
tree = ast.parse(src)
defs = collections.Counter(n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
dupes = {k: v for k, v in defs.items() if v > 1}

print("missing:", ", ".join(missing) if missing else "none")
print("duplicate defs:", dupes or "none")
print("defs:", len(defs), "lines:", src.count("\n"))
sys.exit(1 if (missing or dupes) else 0)