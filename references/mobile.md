# Mobile & Cross-Platform Bundles (Android APK, iOS IPA, Flutter, Hermes, IL2CPP)

Read only when the target is an `.apk`/`.aab`/`.dex`, `.ipa`, Flutter (`libapp.so` / `App.framework`), React Native (`index.android.bundle` / `main.jsbundle`), or Unity IL2CPP. Static analysis only; never install or execute untrusted packages on a host or personal device. Only analyze software the user is authorized to work on (see Scope in `SKILL.md`).

Contents: 1 Container shape first · 2 Android APK/DEX · 3 iOS IPA & FairPlay · 4 Flutter (Dart AOT) · 5 React Native (Hermes HBC) & Unity IL2CPP

## 0. Setup
```sh
T=./app.apk; D="${TMPDIR:-/tmp}/re/$(basename "$T")"; mkdir -p "$D"
```

## 1. Inspect the ZIP shape before decompiling (decides the real framework in <1 s)
```sh
unzip -l "$T" | rg '(AndroidManifest\.xml|classes[0-9]*\.dex|lib/[^/]+/[^ ]+\.so|assets/index\.android\.bundle|global-metadata\.dat|Payload/[^/]+\.app/|Frameworks/[^/]+\.framework/)' | head -80
```
Route immediately from what is inside:
- `lib/*/libflutter.so` + `libapp.so` (or `Flutter.framework` + `App.framework`) -> **Flutter** (Java/ObjC shell is thin glue; real app logic is Dart AOT in **Section 4**).
- `assets/index.android.bundle` / `libhermes.so` / `main.jsbundle` -> **React Native** (**Section 5**).
- `lib/*/libil2cpp.so` + `assets/bin/Data/Managed/Metadata/global-metadata.dat` -> **Unity IL2CPP** (**Section 5**).
- `assemblies/*.dll` or `libmonodroid.so` -> **.NET MAUI / Xamarin** (extract DLLs; Note: Xamarin Android sometimes LZ4-packs DLLs with `XALZ` header — decompress `XALZ` payload after the 12-byte header `[b"XALZ", idx, uncompressed_len]`, then read `references/dotnet.md`).
- Pure `classes*.dex` (+ optional JNI `.so`) -> **Native Android** (**Section 2**).

## 2. Android APK / DEX
```sh
# Manifest, exported components, deep links, permissions without decompiling Java:
apktool d --no-src -f -o "$D/res" "$T" && rg -n '(exported="true"|android:scheme|android:host|uses-permission|application )' "$D/res/AndroidManifest.xml"
# Full Java/Kotlin decompile:
jadx -d "$D/jadx" --show-bad-code "$T"
# High-signal sweep (endpoints, signing/pinning, JNI bridges, WebViews, storage):
rg -uu -n '(Retrofit|@GET|@POST|OkHttpClient|CertificatePinner|X509TrustManager|System\.loadLibrary|external fun | native |addJavascriptInterface|SharedPreferences|EncryptedSharedPreferences)' "$D/jadx/sources" | head -80
```
JNI bridge rule: match `Java_<pkg>_<Class>_<method>` exports in `lib/arm64-v8a/*.so` (`nm -D --defined-only`), or find `RegisterNatives` inside `JNI_OnLoad` via Ghidra (`references/pe.md` Section 5 works identically on `.so` ELF files).

## 3. iOS IPA & FairPlay check
```sh
unzip -q "$T" -d "$D/ipa"
APP=$(echo "$D/ipa/Payload/"*.app)
plutil -p "$APP/Info.plist" | head -80   # Linux: python3 plistlib (see SKILL.md tool map)
```
**Always check FairPlay encryption (`LC_ENCRYPTION_INFO_64`) before disassembling:**
```sh
(otool -l "$APP/$(basename "$APP" .app)" 2>/dev/null || llvm-objdump --macho --private-headers "$APP/$(basename "$APP" .app)") | rg -A4 'LC_ENCRYPTION_INFO'
```
- `cryptid 0` -> unencrypted Mach-O; proceed with `nm`, `otool -ov` (ObjC selectors), `swift-demangle`, and Ghidra.
- `cryptid 1` -> App Store FairPlay-encrypted `__TEXT`. Code disassembly/strings inside `__TEXT` are ciphertext: state that plainly as **seen** (`cryptid 1`), inspect unencrypted `Info.plist`, entitlements, ObjC metadata, bundled configs/frameworks, and report code-level behavior as **unknown** without an authorized decrypted build.

## 4. Flutter (`libapp.so` / `App.framework/App`)
Dart AOT compiles into `libapp.so` (ELF on Android) or `App.framework/App` (Mach-O on iOS). Standard Java/ObjC decompilers show almost nothing.
1. Extract the 32-hex **Dart VM snapshot hash** right after magic `f5 f5 dc dc` to identify the exact Dart SDK version:
```sh
python3 - "$D/libapp.so" <<'E'
import mmap, re, sys
with open(sys.argv[1], "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
  i = m.find(b"\xf5\xf5\xdc\xdc")
  if i >= 0:
    m2 = re.search(rb"[0-9a-f]{32}", m[i:i+128])
    print("snapshot magic @" + hex(i), "hash:", m2.group(0).decode() if m2 else "unknown")
E
```
2. Run **`blutter`** (`blutter.py path/to/lib/arm64-v8a out_dir`) to reconstruct Dart Object Pool (`pp.txt`), package/class/method hierarchy (`asm/*`), and Frida scripts.
3. Without `blutter`: `strings -a -n 6 libapp.so | rg '(package:[a-z0-9_]+/|https?://|/api/)' | sort -u | head -120` recovers Dart package names, routes, and string constants from the object pool.

## 5. React Native (`Hermes` HBC) & Unity `IL2CPP`
- **Hermes (`index.android.bundle` / `main.jsbundle`):** check magic `python3 -c 'import sys;b=open(sys.argv[1],"rb").read(12);print(b[:8].hex(), "HBC" if b[:4]==b"\xc6\x1f\xbc\x03" else "plain-JS")' "$B"`. If plain JS, treat as a minified web bundle; if HBC, read bytecode version (`int32` LE at offset 8) and decompile with `hermes-dec` / `hbctool` (or grep cleartext string tables inside the bundle).
- **Unity IL2CPP (`libil2cpp.so` / `GameAssembly.dll` + `global-metadata.dat`):** verify `global-metadata.dat` starts with `af 1b b1 fa` (if not, metadata is encrypted/obfuscated — report it before running tools). Run `Il2CppDumper <bin> global-metadata.dat "$D/il2cpp"` -> grep C# class/method prototypes & RVAs in `dump.cs`, then decompile only the target RVA in Ghidra.
