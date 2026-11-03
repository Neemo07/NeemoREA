#!/usr/bin/env python3
"""Zero-dependency validator for NeemoREA skill frontmatter, reference links, and embedded code blocks."""
from __future__ import annotations

import ast
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKILL_MAX_KB = 24.0


def fail(msg: str, errors: list[str]) -> None:
    errors.append(msg)


def check_frontmatter(skill_text: str, errors: list[str]) -> None:
    m = re.match(r"^---\n(.*?)\n---\n", skill_text, re.DOTALL)
    if not m:
        fail("SKILL.md: missing opening YAML frontmatter block (--- ... ---)", errors)
        return
    fm = {}
    for line in m.group(1).splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            fm[k.strip()] = v.strip()
    if fm.get("name") != "neemorea":
        fail(f"SKILL.md: expected frontmatter name 'neemorea', got {fm.get('name')!r}", errors)
    if len(fm.get("description", "")) < 40:
        fail("SKILL.md: frontmatter description is missing or too short", errors)


def check_references(errors: list[str]) -> int:
    ref_dir = ROOT / "references"
    if not ref_dir.is_dir():
        fail("references/ directory is missing", errors)
        return 0

    docs = [ROOT / "SKILL.md", ROOT / "README.md", *sorted(ref_dir.glob("*.md"))]
    mentioned: set[str] = set()
    for doc in docs:
        text = doc.read_text(encoding="utf-8")
        for match in re.finditer(r"\breferences/([A-Za-z0-9_.-]+\.md)\b", text):
            rel = f"references/{match.group(1)}"
            mentioned.add(match.group(1))
            target = ROOT / rel
            if not target.is_file() or target.stat().st_size < 100:
                fail(f"{doc.name}: broken or empty reference pointer '{rel}'", errors)

    actual = {p.name for p in ref_dir.glob("*.md")}
    for orphan in sorted(actual - mentioned):
        fail(f"references/{orphan}: never referenced from SKILL.md or README.md", errors)
    return len(actual)


def check_line_endings(errors: list[str]) -> None:
    """Shell scripts and awk/frontmatter parsing break on CRLF, so require LF everywhere."""
    targets = [ROOT / "SKILL.md", ROOT / "README.md", ROOT / "install.sh", ROOT / "scripts" / "validate.py",
               *sorted((ROOT / "references").glob("*.md"))]
    for f in targets:
        if f.is_file() and b"\r" in f.read_bytes():
            fail(f"{f.relative_to(ROOT)}: contains CR (CRLF line endings); use LF (see .gitattributes, `git add --renormalize .`)", errors)


def check_readme_layout(errors: list[str]) -> None:
    """The README layout tree must list every file in references/ and scripts/."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    m = re.search(r"## Repository layout\s+```text\n(.*?)```", text, re.DOTALL)
    if not m:
        fail("README.md: '## Repository layout' text block not found", errors)
        return
    tree = m.group(1)
    for sub in ("references", "scripts"):
        for p in sorted((ROOT / sub).iterdir()):
            if p.is_file() and p.name not in tree:
                fail(f"README.md: layout block does not list {sub}/{p.name}", errors)


def check_code_blocks(md_files: list[pathlib.Path], errors: list[str]) -> tuple[int, int]:
    sh_checked = 0
    py_checked = 0
    fence_re = re.compile(r"```(sh|bash)\n(.*?)```", re.DOTALL)
    py_heredoc_re = re.compile(r"python3\s+-[^\n]*<<'([A-Za-z0-9_]+)'\n(.*?)\n\1(?:\n|$)", re.DOTALL)

    for md in md_files:
        text = md.read_text(encoding="utf-8")
        for idx, m in enumerate(fence_re.finditer(text), 1):
            snippet = m.group(2)
            proc = subprocess.run(["bash", "-n"], input=snippet, text=True, capture_output=True)
            if proc.returncode != 0:
                fail(f"{md.relative_to(ROOT)} [sh block #{idx}]: bash -n failed: {proc.stderr.strip()}", errors)
            sh_checked += 1

            for py_idx, pm in enumerate(py_heredoc_re.finditer(snippet), 1):
                py_code = pm.group(2)
                try:
                    ast.parse(py_code, filename=f"{md.name}:block{idx}:py{py_idx}")
                except SyntaxError as exc:
                    fail(f"{md.relative_to(ROOT)} [sh #{idx} python heredoc #{py_idx}]: {exc}", errors)
                py_checked += 1

    return sh_checked, py_checked


def check_installer(errors: list[str]) -> bool:
    installer = ROOT / "install.sh"
    if not installer.is_file():
        return False
    proc = subprocess.run(["bash", "-n", str(installer)], text=True, capture_output=True)
    if proc.returncode != 0:
        fail(f"install.sh: bash -n failed: {proc.stderr.strip()}", errors)
        return True
    with tempfile.TemporaryDirectory() as tmp:
        r1 = subprocess.run(["bash", str(installer), "--all", "--dir", tmp], text=True, capture_output=True)
        if r1.returncode != 0:
            fail(f"install.sh --all failed: {r1.stderr.strip()}", errors)
            return True
        for rel in (
            ".config/opencode/skills/neemorea/SKILL.md",
            ".claude/skills/neemorea/SKILL.md",
            ".agents/skills/neemorea/SKILL.md",
            ".cursor/rules/neemorea/neemorea.mdc",
            ".cursor/rules/neemorea/references/pe.md",
        ):
            if not (pathlib.Path(tmp) / rel).is_file():
                fail(f"install.sh: missing expected installed file '{rel}'", errors)
        r2 = subprocess.run(["bash", str(installer), "--uninstall", "--all", "--dir", tmp], text=True, capture_output=True)
        if r2.returncode != 0:
            fail(f"install.sh --uninstall failed: {r2.stderr.strip()}", errors)
    return True


def main() -> int:
    errors: list[str] = []
    skill_path = ROOT / "SKILL.md"
    if not skill_path.is_file():
        print("FAIL: SKILL.md not found", file=sys.stderr)
        return 1

    skill_bytes = skill_path.stat().st_size
    skill_kb = skill_bytes / 1024.0
    if skill_kb > SKILL_MAX_KB:
        fail(f"SKILL.md is {skill_kb:.1f} KB > {SKILL_MAX_KB:.1f} KB budget; move detail to references/", errors)

    check_line_endings(errors)
    check_frontmatter(skill_path.read_text(encoding="utf-8"), errors)
    check_readme_layout(errors)
    n_refs = check_references(errors)
    md_files = [ROOT / "SKILL.md", ROOT / "README.md", *sorted((ROOT / "references").glob("*.md"))]
    n_sh, n_py = check_code_blocks(md_files, errors)
    has_installer = check_installer(errors)

    if errors:
        for e in errors:
            print(f"  ! {e}", file=sys.stderr)
        print(f"validation failed ({len(errors)} problem(s))", file=sys.stderr)
        return 1

    extra = ", install.sh verified" if has_installer else ""
    print(f"ok: SKILL.md {skill_kb:.1f} KB/{SKILL_MAX_KB:.0f} KB, {n_refs} ref(s), {n_sh} sh block(s), {n_py} python heredoc(s){extra}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
