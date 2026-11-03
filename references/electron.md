# Electron, ASAR, Fuses, Native `.node` Addons, Bytenode & Node SEA

Read only when the target is an Electron desktop app, `.asar` archive, `.node` N-API addon, Bytenode `.jsc` snapshot, or Node SEA binary. Static analysis only; never execute the sample on the host. Only analyze software the user is authorized to work on (see Scope in `SKILL.md`).

Contents: 1 Bundle layout & Fuses · 2 Offline/stdlib ASAR unpack · 3 IPC & preload security audit · 4 Native `.node` addons · 5 Bytenode (`.jsc`) & Node SEA

## 0. Setup
```sh
A=./app.asar; D="${TMPDIR:-/tmp}/re/electron"; mkdir -p "$D"
```
Where `app.asar` lives: macOS `App.app/Contents/Resources/app.asar`, Windows/Linux `resources/app.asar` (or unpacked directory `resources/app/`). Always also check `app.asar.unpacked/` right next to it — native `.node` addons and helper binaries cannot run from inside ASAR and are placed there.

## 1. Electron Fuses (check before assuming `--inspect` or ASAR edits)
Electron's fuse wire (`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX` sentinel inside the Electron binary) flips compile-time security bits (`RunAsNode`, `EnableNodeCliInspectArguments`, `EnableEmbeddedAsarIntegrityValidation`, `OnlyLoadAppFromAsar`, `EnableCookieEncryption`).
```sh
npx -y @electron/fuses read --app ./App.app 2>/dev/null
# Offline / no npx: locate the sentinel in the main Electron binary and inspect the fuse byte vector right after it:
python3 - ./Electron <<'E'
import mmap, sys
SENT = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
NAMES = ["RunAsNode", "EnableCookieEncryption", "EnableNodeOptionsEnv", "EnableNodeCliInspectArgs",
         "EnableEmbeddedAsarIntegrityValidation", "OnlyLoadAppFromAsar", "LoadBrowserProcessSpecificV8Snapshot"]
with open(sys.argv[1], "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
  i = m.find(SENT)
  if i < 0: sys.exit("fuse sentinel not found")
  ver, sz = m[i + len(SENT)], m[i + len(SENT) + 1]
  vec = m[i + len(SENT) + 2 : i + len(SENT) + 2 + sz]
  for idx, name in enumerate(NAMES[:len(vec)]):
    print(f"{name}: {'ENABLED(1)' if vec[idx] == 49 else 'DISABLED(0)' if vec[idx] == 48 else vec[idx]}")
E
```

## 2. Offline / zero-dependency `app.asar` unpacker
When the network is restricted (`npx -y @electron/asar` unavailable) or header integrity blocks standard CLI flags, unpack directly with stdlib Python (handles both standard 16-byte Chromium double-pickle headers and 12-byte single-pickle headers):
```sh
mkdir -p "$D/asar" && python3 - "$A" "$D/asar" <<'E'
import json, os, struct, sys
with open(sys.argv[1], "rb") as f:
  hdr = f.read(16)
  _, hsz, u2, u3 = struct.unpack("<IIII", hdr)
  joff, jlen = (12, u2) if hdr[12:13] == b"{" else (16, u3)
  f.seek(joff); tree = json.loads(f.read(jlen).decode("utf-8"))
  base = 8 + hsz
  def walk(node, rel=""):
    for k, v in node.get("files", {}).items():
      p = os.path.normpath(os.path.join(rel, k)).lstrip("/\\")
      if p.startswith(".."): continue
      if "files" in v: walk(v, p)
      elif not v.get("unpacked") and "offset" in v:
        dst = os.path.join(sys.argv[2], p); os.makedirs(os.path.dirname(dst), exist_ok=True)
        f.seek(base + int(v["offset"])); open(dst, "wb").write(f.read(int(v["size"])))
  walk(tree)
print("extracted to", sys.argv[2])
E
```

## 3. IPC, preload & privilege-boundary audit
1. Read `jq '{name,version,main,dependencies}' "$D/asar/package.json"`.
2. Check every `new BrowserWindow` / `WebContentsView` for dangerous flags: `nodeIntegration: true`, `contextIsolation: false`, `sandbox: false`, `webSecurity: false`, custom `preload`, and `setWindowOpenHandler` / `will-navigate` -> `shell.openExternal` URL validation gaps.
3. Trace `contextBridge.exposeInMainWorld("<api>", { ... })` in preload scripts -> match `ipcRenderer.invoke/send` channel names -> locate `ipcMain.handle/on` handlers in main bundle (`rg -uu --glob '!node_modules'`).

## 4. Native `.node` addons (`N-API` / `NAN`)
`.node` files are Mach-O / ELF / PE shared libraries loaded by V8/Node. Do not start at `_start`:
1. List exported JS method names registered via `napi_define_properties` / `napi_create_function` (their C string names sit directly adjacent to the function pointers in `.rodata` / `__cstring`):
```sh
strings -a -n 4 addon.node | rg -v '^(napi_|uv_|_Z|__cxa|NODE_)' | head -120
```
2. Check OS capabilities via imports (`nm -u` / `readelf -Ws` / `pefile`): macOS TCC (`TCCAccessPreflight`, `CGWindowListCopyWindowInfo`, `ScreenCaptureKit`), Windows Win32/COM, or Unix domain sockets (`getpeereid`).

## 5. Bytenode (`.jsc`) & Node SEA
- **Bytenode (`.jsc`):** V8 bytecode cache tied to the exact Electron V8 version (`process.versions.v8`). Static decompilers are incomplete (`View8` recovers structure for matching V8 versions); extract string literals from the snapshot first, and if authorized in a sandbox, hook `Module._extensions['.jsc']` or V8 `--print-bytecode` with the matching Electron binary.
- **Node SEA (`Single Executable Applications`):** check `strings -a T | rg 'NODE_SEA_(BLOB|FUSE)'`. On PE the blob lives in the `NODE_SEA_BLOB` RCData resource; on Mach-O in segment `__NODE_SEA,__NODE_SEA_BLOB`; on ELF in note/section `NODE_SEA_BLOB`. Slice out the embedded JS script or V8 code cache from that section.
