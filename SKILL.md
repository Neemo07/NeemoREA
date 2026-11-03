---
name: neemorea
description: Reverse engineer shipped software with plain local CLI tools, no MCP needed. Use whenever the user wants to unpack, inspect, decompile, explain, compare or rebuild a program, installer or package, even if they do not say "reverse engineering". Covers Electron/JS bundles, native Mach-O/ELF/PE (.exe/.dll), Go/Rust/.NET/Flutter/WASM binaries, APK/IPA/JAR, PyInstaller/Python bundles, Tauri/Wails, Unity, Node SEA, Chrome extensions (.crx), SQLite, pcaps, firmware and websites. Use to explain how a feature works, extract versions/deps, decompile, compare builds, or rebuild a feature or program.
---

# NeemoREA: fast path

You already know these tools. This file only lists the fastest command for each target, and the traps. Windows PE work and rebuild-and-verify loops live in `references/pe.md` (read it only when the target is PE/.exe/.dll or the task is a rebuild).

## Scope
Analyze only software the user owns or is authorized to analyze (own code, licensed or permitted analysis, security research, interoperability, CTF). If authorization is unclear, ask in one line. A rebuild of a third-party program raises licensing questions: say so, keep the rebuild to what the user is entitled to do, and do not help bypass licensing/DRM or build malware.

## Rules
- Work on a copy (`cp -c` on APFS is instant, else `cp -R`). Put each extraction in a new dir under `${TMPDIR:-/tmp}/re/<name>`. Reuse an extraction if one exists.
- Static only. Never execute the target on the host. Run it only if the user asks, and then inside a VM/sandbox.
- Route by `file -b T` and the magic bytes first. Run the cheapest inventory next. Only then decompile or read code.
- `rg` skips hidden and ignored files, and bundlers hide code (Electron: `.webpack/`, `.vite/`). Always search extracted trees with `rg -uu`.
- Never `cat` a big or minified file. Slice it: `rg -o '.{0,200}NEEDLE.{0,200}' F | head`. Dump a disassembly or tool output once to a file in `$D`, then grep that file instead of re-running the tool.
- Batch independent probes into ONE shell call with `;` and `echo '--- name'` markers (quoted: zsh expands a bare `==x`). Cap every output with `head` or `-m`. If one command would run over ~60 s or print over ~1 MB, narrow it (one function, one section) or run it in the background (`nohup ... > $D/x.log 2>&1 &`) and poll the log.
- Answer from evidence. In the answer, mark each claim as **seen** (cite file:offset, address, symbol, string or the command) or **inferred** (say from what). A fact you did not find is **unknown**, not "absent". Static reading is not observed execution.
- Versioned names: if a channel, symbol or endpoint exists in several versions (`-v2`, `.v3`, old and new), find which one the live code path sends or registers, report that one first, and name the others as legacy.
- Packed or encrypted? High entropy (`binwalk -E T`), tiny import table, section names like `UPX0`. Unpack first (`upx -d T`, or a sandbox dump) and analyze the unpacked file. State plainly that the original was packed. PE specifics are in `references/pe.md`.
- A missing tool is not a blocker. Use the fallback in the same row, or install it (`brew`/`apt`/`winget`/`pip`) if the user allows it.
- Downloads: `npx -y` and `pip install` fetch from the network. Use them only if the network is available and the user has not forbidden installs. If the network is restricted, use an installed equivalent or ask once.
- Turns cost more than bytes. Aim for 2-4 tool calls for an explain/inventory task: one batched recon call, one or two targeted slices, then answer. Stop when every item you were asked has evidence. Do not re-verify what you already saw. **Exempt:** rebuild tasks and multi-binary comparisons. They follow the loop in `references/pe.md` section 6 and need as many calls as the loop takes.

## macOS, Linux, and Windows tool map
Many first moves use macOS tools. On Linux sandboxes or native Windows hosts, use the matching column.

| macOS | Linux fallback | Windows native (VS / PowerShell) |
|---|---|---|
| `otool -L T` | `llvm-objdump --macho --dylibs-used T` or `llvm-otool -L T` | `dumpbin /dependents T` or `llvm-objdump -p T` |
| `otool -tV T` | `llvm-objdump -d --macho --no-show-raw-insn T` (ELF: `objdump -d`) | `dumpbin /disasm:nobytes T` or `llvm-objdump -d -M intel T` |
| `otool -ov T` (ObjC) | `llvm-objdump --macho --objc-meta-data T` | `llvm-objdump --macho --objc-meta-data T` |
| `lipo -info` / `-thin` | `llvm-lipo -info` / `llvm-lipo -thin arm64 -output T1 T` | `llvm-lipo -info` / `llvm-lipo -thin arm64 -output T1 T` |
| `nm -gU T` | `llvm-nm -gU T` (ELF: `nm -D --defined-only T`) | `dumpbin /exports T` or `llvm-nm -g T` |
| `xcrun dyld_info` | `llvm-objdump --macho --exports-trie --bind T` | `dumpbin /imports /exports T` (PE) |
| `codesign -d --entitlements :- T` | `rcodesign print-signature-info T` or `ldid -e T` | `Get-AuthenticodeSignature T \| Format-List *` or `sigcheck -a T` |
| `plutil -p F` | `plistutil -i F` or `python3 -c 'import plistlib,sys,pprint;pprint.pprint(plistlib.load(open(sys.argv[1],"rb")))' F` | `python -c "import plistlib,sys,pprint;pprint.pprint(plistlib.load(open(sys.argv[1],'rb')))" F` |
| `xcrun swift-demangle` | `swift-demangle` (Swift toolchain), else `c++filt` | `undname` (MSVC C++) or `llvm-cxxfilt` |
| `strings -a -el T` | `strings -a -el T` | `floss -q T` or `strings64 -accepteula -n 8 T` |
| `cp -c` | `cp -R` | `Copy-Item -Recurse` |
| `shasum -a 256` | `sha256sum` | `certutil -hashfile T SHA256` or `(Get-FileHash T).Hash` |

## First move: one call each, paste and run
Native (Mach-O):
```sh
T=./bin; D=${TMPDIR:-/tmp}/re/$(basename $T); mkdir -p $D; file $T; lipo -info $T; otool -L $T; echo '--- EXPORTS'; nm -gU $T | head -150; echo '--- IMPORTS'; nm -u $T | rg -v '^__Z|napi_' | tr '\n' ' '; echo; echo '--- STRINGS'; strings -a -n 6 $T | rg -v '^[_$.]' | head -400; otool -tV $T > $D/dis.txt; echo '--- FUNCS'; rg '^[_a-zA-Z].*:$' $D/dis.txt | rg -v '^_?_?Z?N?St3' | head -150
```
Then read one function:
```sh
awk '/^FUNC_LABEL:$/{p=1;next} p&&/^[_a-zA-Z].*:$/{exit} p' $D/dis.txt | rg 'bl|b\.|cmp|literal|mov\s+w2'
```

ELF / PE (also tells you which tools exist, so you pick once):
```sh
T=./bin; D=${TMPDIR:-/tmp}/re/$(basename $T); mkdir -p $D; file -b $T; (shasum -a 256 $T || sha256sum $T) 2>/dev/null | cut -c1-16; echo '--- TOOLS'; for t in rg jq r2 objdump llvm-objdump readelf diec floss analyzeHeadless ilspycmd upx python3; do command -v $t >/dev/null && echo -n "$t "; done; echo; echo '--- HEADERS'; (objdump -p -h $T 2>/dev/null || readelf -hlSW $T) | head -150; echo '--- STRINGS'; strings -a -n 8 $T | head -150; echo '--- UTF16'; strings -a -el -n 8 $T | head -150
```
PE next: `references/pe.md` (packer check, RTTI/PDB, headless Ghidra).

Electron:
```sh
A=./app.asar; X=${TMPDIR:-/tmp}/re/asar; rm -rf $X; npx -y @electron/asar extract $A $X && jq '{name,version,main}' $X/package.json; find $X -path '*/node_modules' -prune -o -type f \( -name '*.js' -o -name '*.node' \) -print | head -60; ls ${A}.unpacked/node_modules 2>/dev/null; rg -uu -l --glob '!node_modules' 'exposeInMainWorld' $X
```
Then slice the needle across the bundle: `rg -uu -o --glob '!node_modules' '.{0,250}NEEDLE.{0,250}' $X | head -20`.

Go: `go version -m T` alone usually answers the question.

## Router
Short pointers only. Longer commands are in "Recipes" below, where `|` is a real shell pipe.

| Target (detect) | Fastest path |
|---|---|
| Electron app (`*.app/Contents/Resources/app.asar`) | Extract with `@electron/asar` (also see `app.asar.unpacked/` for `.node` addons). Entry point: `jq .main X/package.json`. IPC and security surface: recipe **Electron surface**. Fuses: `npx -y @electron/fuses read --app A.app`. If extraction fails on integrity, retry with the tool's skip/continue flag rather than abandoning the route. |
| Node SEA / `pkg` single-file | Sentinel `NODE_SEA_FUSE_` or `NODE_SEA_BLOB` in `strings`. The embedded script is usually plain text inside the blob: slice it out with `rg -a -o`. |
| Web bundle / minified JS | Find `sourceMappingURL`. If the map has `sourcesContent`, dump the sources: `jq -r '.sources[]'`. For webpack, grep the module ids, then slice around the hit. For pretty-print: `npx -y prettier --parser babel F > F.pretty.js`, then read with line ranges. |
| Hermes / bytenode / V8 snapshot | Hermes magic is `c6 1f bc 03` (`index.android.bundle`): use `hermes-dec` / `hbc-decompiler`. `.jsc` (bytenode) cannot be decompiled: use strings and runtime hooks. |
| Chrome extension (`.crx`, `Cr24` magic) | `unzip` works (it warns about the header). Read `manifest.json` first: permissions, background/service worker, content scripts. Then treat the JS as a web bundle. |
| Mach-O (`file`: Mach-O) | First-move block above. Thin a fat binary first. Also: `xcrun dyld_info -exports -imports`, `otool -l` for `LC_RPATH`/`LC_BUILD_VERSION`, `codesign -d --entitlements :- T`, `otool -ov` for ObjC, `xcrun swift-demangle --compact`. See the Linux map for non-macOS hosts. |
| iOS IPA | `unzip a.ipa -d X`; app is `X/Payload/*.app`. `Info.plist` has bundle id, URL schemes, privacy strings. The main binary is Mach-O (often FairPlay-encrypted: run `otool -l T` and look at `cryptid`; `cryptid 1` means encrypted and static analysis of code is limited). Frameworks and `main.jsbundle`/`libapp.so` identify React Native/Flutter. |
| Native code logic | Recipe **Native function trail**. Real pseudocode only when needed: Ghidra headless (script in `references/pe.md`, works for any format) or `r2 -qc 'aaa; pdc @ sym.X' T`. |
| ELF | `readelf -hlSW`, `readelf -dW` (NEEDED), `nm -D --defined-only`, `objdump -d -M intel --no-show-raw-insn`. Stripped but Go/Rust: see those rows. checksec: `pwn checksec`. UPX: `upx -d`. |
| PE (`file`: PE32/PE32+) | ELF/PE first move, then `references/pe.md`: pefile triage, packer check, `-el` UTF-16 strings, RTTI, PDB path, headless Ghidra decompile-all. Managed PE is the .NET row. |
| Go (`__go_buildinfo`, `.go.buildinfo`) | `go version -m T` gives the toolchain, path, mod, deps and build flags in one call. Without Go: recipe **Go without toolchain**. Symbols survive stripping: `go tool nm T`, then filter `main\.`. |
| Wails / Tauri | Wails is Go and Tauri is Rust with the web frontend embedded in the binary. Use the Go or Rust row, then pull the frontend: `strings -a T`, filter `sourceMappingURL` and `<!doctype`. Tauri config: `strings -a T`, filter `tauri.conf` and `"identifier"`. Commands exposed to JS: filter `invoke` and `__TAURI__`. |
| Rust | Recipe **Rust deps and toolchain**. |
| .NET (`file`: Mono/.Net) | `ilspycmd -p -o X T.dll` (install: `dotnet tool install -g ilspycmd`), then `rg`. P/Invoke: `rg DllImport X`. NativeAOT/IL2CPP are native: use the native rows. |
| Unity | Mono build: `*_Data/Managed/Assembly-CSharp.dll`, use the .NET row. IL2CPP build: `GameAssembly.dll`/`.so` plus `*_Data/il2cpp_data/Metadata/global-metadata.dat`, use `Il2CppDumper` to recover names, then native rows. |
| Java (`.jar`, `.class`, `.war`) | `unzip -l a.jar`; read `META-INF/MANIFEST.MF` (Main-Class). Decompile: `jadx -d X a.jar` (or `cfr`, `fernflower`). Quick signatures without decompiling: `javap -p -c -classpath a.jar com.Foo`. |
| Python bundle (PyInstaller, `.pyc`) | PyInstaller: `strings -a T`, filter `pyi-` or `PYZ`; extract with `pyinstxtractor.py`. Then decompile `.pyc` with `pycdc` or `decompyle3` (the pyc magic number tells the Python version; newer versions are poorly supported, fall back to `python3 -m dis`). Nuitka and Cython output is native: use the native rows. |
| Android APK | `jadx -d X --show-bad-code a.apk` then `rg`. Resources/manifest only: `apktool d --no-src -o X a.apk`. Quick look: `unzip -l a.apk`. `lib/*/libflutter.so` means Flutter (Dart AOT: `blutter`); `libhermes.so` means React Native (Hermes row). |
| Flutter snapshot hash | In `libapp.so`, find magic `f5 f5 dc dc`; the 32 hex chars at +20 are the snapshot hash. Map it to a Dart version. Deeper APK/IPA, FairPlay `cryptid`, `blutter`, Hermes HBC, Xamarin `XALZ` & IL2CPP workflows: `references/mobile.md`. |
| WASM | `wasm-objdump -x`, `wasm2wat`, `wasm-decompile` (WABT). |
| SQLite | Copy the db, plus the `-wal` file if present. `sqlite3 'file:C?mode=ro' '.schema'`, then `SELECT * FROM t LIMIT 20`. |
| plist / nib / car | `plutil -p F` (Linux: see the map). Info.plist holds the bundle id, URL schemes and privacy strings. Asset catalogs: `assetutil --info Assets.car`. |
| pcap / HAR | Recipe **pcap and HAR**. |
| Firmware | `binwalk -e F` or `unblob -e X F`. Then route each extracted binary through this table. |
| Website | `curl -sL URL` for the HTML and script srcs, then fetch the JS and slice it. For runtime behavior, use a headless browser with a network log (Playwright `page.on('request')`) or Chrome `--remote-debugging-port`. |
| Running app / runtime | Only on request, in a sandbox. macOS: `lldb -p PID`, `dtrace`/`fs_usage`/`log stream --predicate 'process=="X"'`. Electron main: `--inspect` (only if the RunAsNode/inspect fuses allow it). Android: `adb logcat`, `frida -U -f pkg -l hook.js`. |

## Recipes
Real shell pipes below. Copy as is.

**Electron surface** (X is the extracted asar dir; offline Python ASAR unpacker, Fuse byte-vector reader, `.node` addons & Bytenode/SEA in `references/electron.md`)
```sh
rg -n -o -uu --glob '!node_modules' '.{0,120}(ipcMain\.(handle|handleOnce|on|once)|ipcRenderer\.(invoke|send|sendSync|on)|contextBridge\.exposeIn(Main|Isolated)World|webPreferences|preload:|nodeIntegration|contextIsolation|sandbox|\.node\b).{0,160}' $X | head -80
# App-specific IPC wrappers often hide the channels, so also list channel-like strings in the main file:
rg -uu -o '"[a-z]+:[a-z0-9:-]+"' $X/MAIN_FILE | sort -u | head -100
```

**Native function trail** (works on `otool -tV` or `llvm-objdump -d` output in `$D/dis.txt`)
```sh
rg -n '^_?.*NAME.*:$' $D/dis.txt | head                      # find the function label
awk '/^FUNC:/{p=1} p&&/^[_a-zA-Z].*:$/&&!/FUNC/{exit} p' $D/dis.txt | rg 'bl|call|literal|cmp'   # read its call/string trail
rg -n 'literal pool for: "NEEDLE' $D/dis.txt | head         # who uses a string: then find the label above that line
```
otool labels string literals and stubs inline, which is often enough.

**Go without toolchain**
```sh
strings -a T | rg -m1 -A200 'Go buildinf' | head -250
```

**Rust deps and toolchain**
```sh
cargo audit bin T                                            # if the binary is cargo-auditable
strings -a T | rg -o '/rustc/[0-9a-f]{40}' | sort -u         # compiler commit
strings -a T | rg -o '[a-z0-9_-]+-[0-9]+\.[0-9]+\.[0-9]+/src' | sort -u   # crates from paths
# or extract the .dep-v0 section (Mach-O: __DATA,.dep-v0) and zlib-inflate it
```

**pcap and HAR**
```sh
tshark -r C -q -z conv,tcp
tshark -r C -T fields -e dns.qry.name -e tls.handshake.extensions_server_name -e http.request.full_uri | sort -u
jq -r '.log.entries[].request | .method+" "+.url' file.har | head -100
```

## Speed patterns
- Strings and imports first. On a small binary, `nm -u` + `strings` + the export list usually answer "what does it do" with no disassembly.
- To find who uses a string: get its address from the "literal pool for" comments in `otool -tV` output, then find the enclosing function label above that line. On PE/ELF use `r2 axt` or Ghidra "References to".
- A C++ name in a `bl` target already tells you the protocol (for example `getpeereid`, `write`, `std::hash`). Read the call sequence, not every instruction.
- For JS, go from the native/JS boundary inward: find the native call, then its caller class, then the IPC registration, then the renderer/preload.
- Comparing versions: diff the inventories (`nm`, the module list, `go version -m`) before you diff any code.
- Rebuilding: build the inventory first, write the minimal reimplementation, then test it against the original (same inputs, same outputs). For whole-program rebuilds use the verify loop in `references/pe.md`.

## Install (only on request)
`brew install jadx apktool radare2 binwalk wabt wireshark ghidra` (Linux: `apt install` equivalents plus `llvm`; Windows: `winget`/scoop) · `npm i -g @electron/asar` · `dotnet tool install -g ilspycmd` · `cargo install cargo-audit` · `pip install pefile decompyle3` (`pycdc` is built from source).
