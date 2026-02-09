#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Iterable, Tuple, List

RULE_DRIFT = "GATE_TEMPLATE_DRIFT"
RULE_MISSING = "GATE_TEMPLATE_MISSING"

RE_NAME = re.compile(r'^\s*name\s*:\s*.+\s*$')
RE_COMMENT = re.compile(r'^\s*#.*$')
RE_EMPTY = re.compile(r'^\s*$')

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
            "hint": "Remove missing instance from --instance list, or add the workflow file to this repo.",
        })
        sys.exit(2)

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
    ap.add_argument("--template", required=True)
    ap.add_argument("--instance", required=True, action="append")
    ap.add_argument("--root", default=".")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    template_path = (root / args.template).resolve()

    tmpl_raw = read_lines(template_path)
    tmpl_lines_base = normalize_common(tmpl_raw)

    failures = 0

    for inst in args.instance:
        inst_path = (root / inst).resolve()
        gate_file = os.path.basename(str(inst_path))

        inst_raw = read_lines(inst_path)
        inst_lines = normalize_gate_file_tokens(normalize_common(inst_raw), gate_file=gate_file)

        tmpl_for_this = normalize_gate_file_tokens(tmpl_lines_base, gate_file=gate_file)

        tmpl_hash = sha256_lines(tmpl_for_this)
        inst_hash = sha256_lines(inst_lines)

        if inst_hash != tmpl_hash:
            failures += 1
            idx, expected, got = first_diff(tmpl_for_this, inst_lines)
            emit_fail({
                "rule_id": RULE_DRIFT,
                "file": inst,
                "line": (idx + 1) if idx >= 0 else 0,
                "expected": expected,
                "got": got,
                "template": args.template,
                "template_sha256": tmpl_hash,
                "instance_sha256": inst_hash,
                "hint": "Workflow instance must match canonical template after normalization (name + __GATE_FILE__).",
            })
        else:
            print(f"OK GATE_TEMPLATE_MATCH instance={inst}")

    if failures:
        sys.exit(1)

if __name__ == "__main__":
    main()
