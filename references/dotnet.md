# .NET (Managed IL, Single-File AppHost, WPF, Costura, R2R/NativeAOT)

Read only when the target is .NET, a native PE/ELF/Mach-O suspected of bundling .NET (`PublishSingleFile` / WPF desktop app), or Unity Mono. Static analysis only; never run the sample on the host. Only analyze or rebuild software the user is authorized to work on (see Scope in `SKILL.md`).

Contents: 1 Flavor triage · 2 Single-file AppHost unpack · 3 Decompile & slice · 4 WPF (BAML -> XAML & resources) · 5 Costura & embedded DLLs · 6 ReadyToRun & NativeAOT · 7 Obfuscators

## 0. Setup (run first, every command below assumes it)
```sh
T=./App.exe; D="${TMPDIR:-/tmp}/re/$(basename "$T")"; mkdir -p "$D"
```

## 1. Flavor triage (do not trust `file` alone)
`file -b "$T"` only reports `Mono/.Net` when the outer binary carries a CLR header (`DATA_DIRECTORY[14]`). Modern `.NET 6+` apps published with `PublishSingleFile=true` ship as a **native `apphost`** (`PE32+`, `ELF`, or `Mach-O`) with no outer CLR header — `file` calls them native C++, and Ghidra wastes 20 minutes on the Microsoft host stub while the real C# DLLs sit inside an appended bundle.

Classify in one call:
```sh
python3 - "$T" <<'E'
import mmap, sys
SIG = bytes.fromhex("8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae")
with open(sys.argv[1], "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
  i = m.find(SIG)
  print("single-file-bundle @" + hex(i) if i >= 0 else "no-apphost-bundle")
  for k, pat in [("clr-bsjb", b"BSJB"), ("r2r-rtr", b"RTR\x00"), ("native-aot", b"DotNetRuntimeDebugHeader"), ("costura", b"costura."), ("wpf-baml", b".g.resources")]:
    p = m.find(pat)
    if p >= 0: print(k, "@" + hex(p))
E
```
Route from the output:
- `single-file-bundle` -> **Section 2** first (extract the real `.dll` files, then decompile `AppName.dll`).
- `clr-bsjb` (and not `native-aot`) -> **Section 3** (`ilspycmd` on `"$T"` or the companion `AppName.dll`).
- `native-aot` (no `BSJB`, or `System.Private.CoreLib` native code) -> there is **no IL**; route to `references/pe.md` (or ELF/Mach-O native plan).

## 2. Unpack `.NET 5–9+` Single-File `AppHost` (zero dependencies)
The 32-byte SHA-256 marker above is preceded (`sig - 8`) by the `int64` bundle manifest offset. Extract every embedded `.dll`, `.deps.json`, `.runtimeconfig.json`, and PDB (including `.NET 6+` Deflate-compressed entries) with stdlib Python:
```sh
mkdir -p "$D/bundle" && python3 - "$T" "$D/bundle" <<'E'
import mmap, os, struct, sys, zlib
SIG = bytes.fromhex("8b1202b96a612038727b930214d7a03213f5b9e6efae3318ee3b2dce24b36aae")
def r7(b, o):
  n = s = 0
  while True:
    c = b[o]; o += 1; n |= (c & 0x7f) << s
    if not (c & 0x80): return n, o
    s += 7
with open(sys.argv[1], "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
  p = m.find(SIG)
  if p < 8: sys.exit("no .NET single-file signature found")
  ho, = struct.unpack_from("<q", m, p - 8)
  maj, minv, cnt = struct.unpack_from("<IIi", m, ho); o = ho + 12
  ln, o = r7(m, o); bid = bytes(m[o:o+ln]).decode("utf-8", "replace"); o += ln
  if maj >= 2: o += 40  # deps(16) + runtimeconfig(16) + flags(8)
  print(f"bundle v{maj}.{minv} id={bid} files={cnt}")
  for _ in range(cnt):
    foff, fsz = struct.unpack_from("<qq", m, o); o += 16
    csz = 0
    if maj >= 6: csz, = struct.unpack_from("<q", m, o); o += 8
    ftype = m[o]; o += 1
    pln, o = r7(m, o); rel = bytes(m[o:o+pln]).decode("utf-8", "replace"); o += pln
    safe = os.path.normpath(rel).lstrip("/\\")
    if safe.startswith(".."): continue
    raw = zlib.decompress(m[foff:foff+csz], -15) if csz > 0 else bytes(m[foff:foff+fsz])
    dst = os.path.join(sys.argv[2], safe); os.makedirs(os.path.dirname(dst), exist_ok=True)
    open(dst, "wb").write(raw)
    print(f"  [{ftype}] {safe} ({len(raw)} B)")
E
```
Read `"$D/bundle/"*.runtimeconfig.json` and `*.deps.json` first to separate first-party assemblies from NuGet packages, then decompile only the app's own `.dll`.

## 3. Decompile & slice Managed IL
Install once if allowed: `dotnet tool install -g ilspycmd` (ensure `~/.dotnet/tools` is on `PATH`). Fallbacks: `monodis` (Mono) or `javap`-style metadata dump via Python `dnfile`.
```sh
# List types first so you do not decompile 200 vendor namespaces:
ilspycmd -l c,i,s,d,e "$T" | head -120
# Whole-project C# dump (creates .csproj + namespace folders + embedded resources):
ilspycmd -p -o "$D/src" "$T"
# High-signal sweep across decompiled C#:
rg -uu -n '(DllImport|LibraryImport|Process\.Start|HttpClient|WebRequest|Registry\.|ProtectedData|Aes|Rsa|Assembly\.Load| Type\.GetType)' "$D/src" | head -80
```
Decompile a single type when the assembly is huge: `ilspycmd -t MyApp.Services.LicenseClient "$T" > "$D/LicenseClient.cs"`.

## 4. WPF desktop apps (`BAML` -> `XAML`, `ICommand`, resources)
WPF compiles `*.xaml` into binary **`BAML`** streams inside `<AssemblyName>.g.resources`.
- `ilspycmd -p -o "$D/src" "$T"` (with ILSpy's BAML decompiler plugin bundled in modern `ilspycmd`) automatically reconstructs `*.xaml` files alongside `*.xaml.cs` code-behind.
- Map UI actions fast without reading layout noise:
```sh
rg -uu -n '(x:Class=|Command="|Click="|RoutedEvent|DataContext|Binding )' "$D/src" --glob '*.xaml' | head -80
rg -uu -n '(RelayCommand|DelegateCommand|ICommand|INotifyPropertyChanged)' "$D/src" --glob '*.cs' | head -80
```
- Check `App.xaml` (`StartupUri`) or `App.xaml.cs` (`OnStartup`) for the real entry window, DI container registration (`ServiceCollection`, `Prism`, `Autofac`), and unhandled-exception / update hooks (`Squirrel`, `Velopack`, `ClickOnce`).

## 5. `Costura.Fody` & embedded resource DLLs
Many `.NET Framework` / WPF tools merge dependencies as Deflate-compressed manifest resources named `costura.<name>.dll.compressed` (hooked in `<Module>.cctor` via `AppDomain.CurrentDomain.AssemblyResolve`). After `ilspycmd -p -o "$D/src" "$T"`, decompress any `.compressed` resources:
```sh
python3 - "$D/src" "$D/costura" <<'E'
import glob, os, sys, zlib
os.makedirs(sys.argv[2], exist_ok=True)
for f in glob.glob(os.path.join(sys.argv[1], "**", "costura.*.compressed"), recursive=True):
  out = os.path.join(sys.argv[2], os.path.basename(f)[:-len(".compressed")])
  open(out, "wb").write(zlib.decompress(open(f, "rb").read(), -15))
  print("unpacked", out)
E
```

## 6. `ReadyToRun (R2R)` vs `NativeAOT`
- **ReadyToRun (`RTR\0` signature + `BSJB` present):** precompiled native code *plus* full IL metadata. `ilspycmd` still decompiles cleanly to C# — ignore the native R2R sections unless auditing a compiler/runtime discrepancy.
- **NativeAOT (`DotNetRuntimeDebugHeader` / hydrated `System.Private.CoreLib`, **no** `BSJB`):** compiled straight to native machine code with no IL. Use `references/pe.md` (Ghidra headless) + scan UTF-16 strings (`strings -a -el -n 6 "$T"`) and MethodTable / reflection map strings to recover class and method names.

## 7. Obfuscators (detect before reading garbage C#)
Check custom attributes and section/stream names (`#Strings`, `#GUID`, non-printable identifiers) before spending turns on mangled control flow:

| Marker in strings / attributes / sections | Obfuscator | First move |
|---|---|---|
| `ConfusedByAttribute`, `.text` + encrypted `#~` / KoiVM | ConfuserEx / beds | Identify version string; unpack constants/anti-tamper in a Windows sandbox (`de4dot-cex` / memory dump) if authorized, else trace P/Invoke & runtime boundaries |
| `DotNetReactor`, `__` resource decryption methods, native stub | .NET Reactor | Check if native stub wraps a managed PE (`binwalk` / `pefile` overlay); `NETReactorSlayer` in an isolated VM only when authorized |
| `SmartAssembly.Attributes.PoweredByAttribute` | SmartAssembly | String table is usually RC4/AES-encoded in a single resource; decompile the helper class called by every string site |
| `ObfuscatedByGoliath`, `BabelObfuscatorAttribute`, `YanoAttribute` | Goliath / Babel / Yano | `de4dot` handles standard renaming/string encryption; even without it, BCL / P/Invoke / XAML property names stay cleartext |
| Unprintable Unicode type names (`\u0001`, `\u200b`) without packing | Renamer only (Obfuscar) | `ilspycmd -p` still emits valid C#; trace from cleartext strings, `DllImport`, HTTP routes, and XAML bindings inward |
