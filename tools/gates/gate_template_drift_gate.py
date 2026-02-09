#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Iterable, Tuple, List, Optional

RULE_DRIFT = "GATE_TEMPLATE_DRIFT"
RULE_MISSING = "GATE_TEMPLATE_MISSING"
RULE_TAG = "GATE_TEMPLATE_TAG_MISSING"

RE_NAME = re.compile(r'^\s*name\s*:\s*.+\s*$')
RE_COMMENT = re.compile(r'^\s*#.*$')
RE_EMPTY = re.compile(r'^\s*$')
RE_TAG = re.compile(r'^\s*#\s*gatekit_template\s*:\s*([a-zA-Z0-9_.-]+)\s*$')

def emit_fail(payload: dict) -> None:
    sys.stderr.write("WHY_FAIL_LOG " + json.dumps(payload, ensure_ascii=False) + "\n")

def read_lines(p: Path) -> List[str]:
    try:
        return p.read_text(encoding="utf-8").splitlines(keepends=False)
    except FileNotFoundError:
        emit_fail({
            "rule_id": RULE_MISSING,
            "file": str(p),
            "line": 0,
            "expected": "file exists",
            "got": "FileNotFoundError",
            "hint": "Add the missing file, or exclude it from glob.",
        })
        sys.exit(2)

def detect_template_key(lines: List[str], max_scan: int = 40) -> Optional[str]:
    for ln in lines[:max_scan]:
        m = RE_TAG.match(ln)
        if m:
            return m.group(1)
    return None

def normalize_common(lines: Iterable[str]) -> List[str]:
    out: List[str] = []
    for ln in lines:
        if RE_COMMENT.match(ln) or RE_EMPTY.match(ln):
            continue
        if RE_NAME.match(ln):
            out.append("name: __GATE_NAME__")
        else:
            out.append(ln.rstrip())
    return out

def normalize_gate_file_tokens(lines: Iterable[str], gate_file: str) -> List[str]:
    out: List[str] = []
    for ln in lines:
        ln_norm = ln.replace("__GATE_FILE__", gate_file)
        ln2 = ln_norm.replace(gate_file, "__GATE_FILE__")
        out.append(ln2.rstrip())
    return out

def normalize_paths_entries(lines: List[str]) -> List[str]:
    """
    Normalize any `paths:` list by collapsing all list items into a single placeholder entry.
    This removes drift caused by different path item counts across gate workflows.
    """
    out: List[str] = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        out.append(ln)

        m = re.match(r'^(\s*)paths:\s*$', ln)
        if not m:
            i += 1
            continue

        base_indent = m.group(1)
        item_indent = base_indent + "  "
        j = i + 1
        consumed = False

        while j < len(lines):
            if re.match(r'^' + re.escape(item_indent) + r'-\s+.*$', lines[j]):
                consumed = True
                j += 1
                continue
            break

        # paths 항목은 무조건 1개로 압축
        out.append(f'{item_indent}- "__PATH__"')
        i = j if consumed else (i + 1)

    return out
def normalize_gate_exec(lines: List[str]) -> List[str]:
    """
    Allow gate-specific python exec lines while still enforcing structure.
    Keep drift command itself strict.
    """
    out: List[str] = []
    for ln in lines:
        if "gate_template_drift_gate.py" in ln:
            out.append(ln)
            continue
        if re.match(r'^\s*python\s+.*\.py\s*$', ln):
            # normalize any python script execution line
            out.append(re.sub(r'^\s*python\s+.*\.py\s*$', "          python __GATE_EXEC__", ln))
        else:
            out.append(ln)
    return out


def normalize_jobs_key(lines: List[str]) -> List[str]:
    """
    Normalize the first job id under `jobs:` to `gate:` so repo-specific job ids don't cause drift.
    """
    out: List[str] = []
    prev = ""
    for ln in lines:
        if prev.strip() == "jobs:":
            # any "  <job_id>:" becomes "  gate:"
            m = re.match(r'^\s{2}[A-Za-z0-9_.-]+:\s*$', ln)
            if m:
                out.append("  gate:")
                prev = ln
                continue
        out.append(ln)
        prev = ln
    return out


def sha256_lines(lines: Iterable[str]) -> str:
    h = hashlib.sha256()
    for ln in lines:
        h.update(ln.encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()

def first_diff(a: List[str], b: List[str]) -> Tuple[int, str, str]:
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i, a[i], b[i]
    if len(a) != len(b):
        i = n
        a_ln = a[i] if i < len(a) else "<EOF>"
        b_ln = b[i] if i < len(b) else "<EOF>"
        return i, a_ln, b_ln
    return -1, "", ""

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--templates-dir", required=True, help="Directory containing class templates (*.yml)")
    ap.add_argument("--instance", action="append", default=[], help="Workflow instance YAML (repeatable)")
    ap.add_argument("--instances-glob", action="append", default=[], help="Glob(s) to discover instances, e.g. .github/workflows/*-gate.yml")
    ap.add_argument("--require-instances", action="store_true", help="Fail if no instances discovered/provided")
    ap.add_argument("--require-template-tag", action="store_true", help="Fail if # gatekit_template: <key> tag missing")
    ap.add_argument("--root", default=".", help="Repo root")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    templates_dir = (root / args.templates_dir).resolve()

    instances = list(args.instance)
    for pat in args.instances_glob:
        for p in root.glob(pat):
            if p.is_file():
                rel = str(p.relative_to(root))
                if rel not in instances:
                    instances.append(rel)

    if args.require_instances and not instances:
        emit_fail({
            "rule_id": RULE_MISSING,
            "file": "(instances)",
            "line": 0,
            "expected": ">=1 instance",
            "got": "0 instances",
            "hint": "Provide --instance or --instances-glob.",
        })
        sys.exit(2)

    failures = 0

    for inst in instances:
        inst_path = (root / inst).resolve()
        gate_file = os.path.basename(str(inst_path))

        inst_raw = read_lines(inst_path)
        key = detect_template_key(inst_raw)

        if not key:
            if args.require_template_tag:
                failures += 1
                emit_fail({
                    "rule_id": RULE_TAG,
                    "file": inst,
                    "line": 1,
                    "expected": "# gatekit_template: <template-key>",
                    "got": "(missing)",
                    "hint": "Add a template tag like: # gatekit_template: pr-paths-gate",
                })
                continue
            else:
                # fallback: treat as drift against sentinel template name if present
                key = "pr-paths-gate"

        template_path = (templates_dir / f"{key}.yml").resolve()
        tmpl_raw = read_lines(template_path)

        inst_lines = normalize_common(inst_raw)
        tmpl_lines = normalize_common(tmpl_raw)

        # apply normalizations for class-wide compare
        inst_lines = normalize_gate_file_tokens(inst_lines, gate_file=gate_file)
        tmpl_lines = normalize_gate_file_tokens(tmpl_lines, gate_file=gate_file)

        inst_lines = normalize_paths_entries(inst_lines)
        tmpl_lines = normalize_paths_entries(tmpl_lines)

        inst_lines = normalize_gate_exec(inst_lines)
        tmpl_lines = normalize_gate_exec(tmpl_lines)

        tmpl_hash = sha256_lines(tmpl_lines)
        inst_hash = sha256_lines(inst_lines)

        if inst_hash != tmpl_hash:
            failures += 1
            idx, expected, got = first_diff(tmpl_lines, inst_lines)
            emit_fail({
                "rule_id": RULE_DRIFT,
                "file": inst,
                "line": (idx + 1) if idx >= 0 else 0,
                "expected": expected,
                "got": got,
                "template": str(template_path.relative_to(root)),
                "template_sha256": tmpl_hash,
                "instance_sha256": inst_hash,
                "hint": "Workflow instance must match its class template after normalization.",
            })
        else:
            print(f"OK GATE_TEMPLATE_MATCH instance={inst} template={key}")

    if failures:
        sys.exit(1)

if __name__ == "__main__":
    main()
