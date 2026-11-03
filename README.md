# NeemoREA

Agent skill for reverse engineering shipped software with plain local CLI tools. No MCP server, no GUI decompiler required.

NeemoREA gives an agent the fastest known command path for each target type, the traps that waste time, and a routing table from file magic to workflow. It is for explaining how a feature works, extracting versions and dependencies, decompiling, comparing builds, and rebuilding a feature or a whole program.

## What it covers

- Electron apps (`app.asar`, Fuses, IPC surface, preload/main/renderer boundaries, native `.node` addons)
- Web bundles and minified JavaScript (source maps, webpack module ids, prettier)
- Native binaries: Mach-O, ELF, PE (`.exe` / `.dll`)
- Go binaries (`go version -m`, stripped symbols)
- Rust binaries (cargo-auditable deps, rustc commit, crate paths)
- .NET assemblies (`ilspycmd`, P/Invoke)
- Android APKs (`jadx`, `apktool`, Flutter / React Native / Hermes detection)
- Flutter Dart AOT snapshots (hash lookup)
- WASM (`wasm-objdump`, WABT)
- SQLite databases (read-only, WAL copied)
- plist / nib / asset catalogs
- pcaps / HAR files
- Firmware (`binwalk`, `unblob`)
- Websites and running apps (only on request, sandboxed)

## Repository layout

```text
SKILL.md            Entry point: rules, first-move commands, router, speed patterns
references/
  pe.md             PE triage, packer check, headless Ghidra decompile, rebuild-and-verify
```

`SKILL.md` is the fast path. `references/pe.md` is read only when the target is PE or the task is a rebuild / Ghidra pseudocode dump.

## How it works

1. **Work on a copy.** Every extraction goes under `${TMPDIR:-/tmp}/re/<name>`; the original is never modified.
2. **Static only by default.** The target is not executed on the host. Running it happens only if the user asks, and then inside a VM or sandbox.
3. **Route by magic first.** `file -b` and magic bytes decide the path; the cheapest inventory (headers, imports, strings) runs before any decompile.
4. **Search correctly.** Extracted trees are searched with `rg -uu`, because bundlers hide code in `.webpack/` and `.vite/`.
5. **Slice, never dump.** Big or minified files are read in narrow windows; tool output is written once to a file and grepped, not re-run.
6. **Evidence, not vibes.** Claims are tagged **seen** (with file:offset, address, symbol, string or command), **inferred** (with the basis), or **unknown** — never "absent".
7. **Few calls.** One batched recon call, one or two targeted slices, then answer.

## Install

Copy this folder into your agent's skills directory, preserving `SKILL.md` and `references/`:

```sh
cp -R NeemoREA ~/.claude/skills/neemorea
# or
cp -R NeemoREA ~/.agents/skills/neemorea
```

Any agent that loads markdown skills from a directory works the same way; the folder name becomes the skill name.

## Usage

Ask the agent to reverse engineer a target, for example:

- "What does this Electron app do with `getToken`?"
- "Which endpoints does this binary call?"
- "Compare v1.2 and v1.3 of this CLI."
- "Rebuild this PE's config parser and verify it against the original."

The skill routes the target, runs the cheapest inventory first, and reports findings tagged by evidence.

## Tooling

NeemoREA assumes common local CLI tools and uses whichever are present (`file`, `strings`, `rg`, `jq`, `objdump` / `readelf` / `otool`, `python3`, `npx`, `sqlite3`, `tshark`, `binwalk`, `jadx`, Ghidra headless). A missing tool is not a blocker — the skill lists a fallback for the same step, or installs it with the user's permission (`brew` / `apt` / `winget` / `pip`).

## Scope and safety

- Read-only analysis of shipped artifacts.
- No host execution of samples.
- Findings distinguish observation from inference; unknowns are reported as unknown.
- Use on software you are authorized to analyze.

## License

MIT — see [LICENSE](LICENSE).
