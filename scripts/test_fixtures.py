#!/usr/bin/env python3
"""Functional regression tests: run the embedded ASAR unpacker and the installer against generated fixtures."""
from __future__ import annotations

import json
import os
import pathlib
import re
import struct
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"{'ok  ' if ok else 'FAIL'} {name}" + (f"  ({detail})" if detail and not ok else ""))
    if not ok:
        failures.append(name)


def build_asar(path: pathlib.Path, json_len: int, payload: bytes = b"hello") -> None:
    tree = {"files": {"a.txt": {"size": len(payload), "offset": "0"},
                      "d": {"files": {"b.txt": {"size": 2, "offset": str(len(payload))}}}}}
    j = json.dumps(tree, separators=(",", ":"))
    j += " " * max(0, json_len - len(j))  # legal JSON whitespace pads to an exact length
    jb = j.encode()
    pad = (-len(jb)) % 4
    body = 4 + len(jb) + pad
    path.write_bytes(struct.pack("<IIII", 4, 4 + body, body, len(jb)) + jb + b"\0" * pad + payload + b"ZZ")


def asar_unpacker_code() -> str:
    md = (ROOT / "references" / "electron.md").read_text(encoding="utf-8")
    m = re.search(r"python3 - \"\$A\" \"\$D/asar\" <<'E'\n(.*?)\nE\n", md, re.DOTALL)
    assert m, "ASAR unpacker heredoc not found in electron.md"
    return m.group(1)


def test_asar() -> None:
    code = asar_unpacker_code()
    # 123 and 379 have low byte 0x7b ('{'), the case that used to be misparsed; 122/124 are controls.
    for n in (60, 122, 123, 124, 255, 379, 635):
        with tempfile.TemporaryDirectory() as d:
            a, out = pathlib.Path(d, "app.asar"), pathlib.Path(d, "out")
            out.mkdir()
            build_asar(a, n)
            r = subprocess.run([sys.executable, "-", str(a), str(out)], input=code, text=True, capture_output=True)
            ok = (r.returncode == 0 and (out / "a.txt").read_bytes() == b"hello"
                  and (out / "d" / "b.txt").read_bytes() == b"ZZ")
            check(f"asar unpack, json header {n} B (low byte {n & 255:#04x})", ok, r.stderr.strip()[-80:])


def run_installer(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(ROOT / "install.sh"), *args], text=True, capture_output=True)


def test_installer() -> None:
    with tempfile.TemporaryDirectory() as home:
        rules = pathlib.Path(home, ".cursor", "rules")
        (rules / "references").mkdir(parents=True)
        (rules / "references" / "my-notes.md").write_text("mine")
        (rules / "my-own.mdc").write_text("mine")
        (rules / "neemorea.mdc").write_text("legacy flat install")
        r = run_installer("--cursor", "--dir", home)
        check("cursor install succeeds", r.returncode == 0, r.stderr)
        check("cursor install keeps user's rules/references/", (rules / "references" / "my-notes.md").read_text() == "mine")
        check("cursor install keeps user's other rules", (rules / "my-own.mdc").read_text() == "mine")
        check("cursor install removes legacy flat neemorea.mdc", not (rules / "neemorea.mdc").exists())
        mdc = (rules / "neemorea" / "neemorea.mdc").read_text()
        check("cursor .mdc has exactly one frontmatter block", mdc.count("\n---\n") == 1 and "name: neemorea" not in mdc)
        check("cursor references installed", (rules / "neemorea" / "references" / "pe.md").is_file())
        r = run_installer("--cursor", "--uninstall", "--dir", home)
        check("cursor uninstall succeeds", r.returncode == 0, r.stderr)
        check("cursor uninstall removes neemorea/", not (rules / "neemorea").exists())
        check("cursor uninstall keeps user's rules/references/", (rules / "references" / "my-notes.md").is_file())

    # A Windows (CRLF) checkout of SKILL.md must still produce a clean .mdc.
    with tempfile.TemporaryDirectory() as work, tempfile.TemporaryDirectory() as home:
        wd = pathlib.Path(work)
        (wd / "references").mkdir()
        for ref in (ROOT / "references").glob("*.md"):
            (wd / "references" / ref.name).write_bytes(ref.read_bytes())
        (wd / "SKILL.md").write_bytes((ROOT / "SKILL.md").read_bytes().replace(b"\n", b"\r\n"))
        (wd / "install.sh").write_bytes((ROOT / "install.sh").read_bytes())
        r = subprocess.run(["bash", str(wd / "install.sh"), "--cursor", "--dir", home], text=True, capture_output=True)
        mdc = pathlib.Path(home, ".cursor", "rules", "neemorea", "neemorea.mdc").read_text()
        check("CRLF SKILL.md yields a single clean frontmatter", r.returncode == 0 and mdc.count("\n---\n") == 1
              and "name: neemorea" not in mdc, r.stderr)


if __name__ == "__main__":
    test_asar()
    test_installer()
    if failures:
        print(f"\n{len(failures)} test(s) failed", file=sys.stderr)
        raise SystemExit(1)
    print("\nall fixture tests passed")
