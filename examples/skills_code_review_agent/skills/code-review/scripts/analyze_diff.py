#!/usr/bin/env python3
"""Sandbox analyzer that emits a compact machine-readable summary."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument('diff')
    p.add_argument('--output', default='/out/tool_findings.json')
    a = p.parse_args()
    text = Path(a.diff).read_text(encoding='utf-8', errors='replace')
    result = {
        "sha256":
        hashlib.sha256(text.encode()).hexdigest(),
        "line_count":
        len(text.splitlines()),
        "suspicious_shell_lines": [
            i for i, line in enumerate(text.splitlines(), 1)
            if re.search(r'shell=True|os\.system', line)
        ]
    }
    out = Path(a.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(result))


if __name__ == '__main__':
    main()
