# PE (.exe/.dll), headless Ghidra, rebuild-and-verify

Read only when the target is PE, or when Ghidra pseudocode or a rebuild is needed. Static analysis only; never run the sample on the host.

## 1. Triage (one call)
```sh
T=./x.exe; python3 - $T <<'E'
import sys,pefile
p=pefile.PE(sys.argv[1]); o=p.OPTIONAL_HEADER
print("machine",hex(p.FILE_HEADER.Machine),"subsys",o.Subsystem,"ts",p.FILE_HEADER.TimeDateStamp,"entry",hex(o.AddressOfEntryPoint),"base",hex(o.ImageBase))
print("managed(.NET)" if o.DATA_DIRECTORY[14].VirtualAddress else "native")
for s in p.sections: print(s.Name.rstrip(b'\0').decode(),hex(s.VirtualAddress),"raw",s.SizeOfRawData,"ent",round(s.get_entropy(),2))
for d in getattr(p,"DIRECTORY_ENTRY_IMPORT",[]): print(d.dll.decode(),[i.name.decode() for i in d.imports if i.name][:30])
for e in getattr(getattr(p,"DIRECTORY_ENTRY_EXPORT",None),"symbols",[])[:80]: print("exp",e.name,hex(e.address))
E
diec $T 2>/dev/null; floss -q $T 2>/dev/null | head -150
```
No pefile: `objdump -p -h $T` (or `llvm-objdump -p`). Windows programs mostly use UTF-16, so always also run `strings -a -el -n 8 $T`.

## 2. Packed?
Suspect packing if section entropy > 7.2, names like `UPX0`/`.vmp0`/`.themida`, `.text` raw size 0, or an import table with only `LoadLibrary`/`GetProcAddress`. Unpack first (`upx -d`, or a sandbox dump) and analyze the unpacked file. State plainly that the original was packed.

## 3. Structure for free
- PDB path and source paths: `strings -a T | rg -i '\.pdb|\.(cpp|h|cs)\b|__FILE__'`
- C++ classes: `strings -a T | rg '\.\?AV[A-Za-z0-9_@]+'` (MSVC RTTI)
- Toolchain: Rich header / CRT strings (`MSVCP`, `VCRUNTIME`), `strings T | rg -i 'msvc|mingw|gcc'`
- Resources: `7z l T` or `wrestool -l T`

## 4. Locate behavior by evidence
Imports and strings first. Networking: `WSAStartup connect send recv WSASend WinHttp* InternetOpen*`. Files: `CreateFileW ReadFile`. Registry: `RegOpenKeyEx*`. Crypto: `BCrypt* Crypt*`. Process: `CreateProcessW VirtualAlloc WriteProcessMemory`. Then open the function that references them and read its call sequence. For a wire protocol, read the struct writes just before `send`/`WSASend` (opcode, length, field order) and confirm with a pcap if available.

## 5. Decompile everything (Ghidra headless)
```sh
mkdir -p $D/gh $D/scripts && cat > $D/scripts/DumpDecomp.java <<'J'
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;
public class DumpDecomp extends GhidraScript {
  public void run() throws Exception {
    String out = getScriptArgs().length > 0 ? getScriptArgs()[0] : "decomp.c";
    DecompInterface d = new DecompInterface();
    d.openProgram(currentProgram);
    try (PrintWriter w = new PrintWriter(out)) {
      for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
        DecompileResults r = d.decompileFunction(f, 60, monitor);
        if (r.decompileCompleted())
          w.println("// " + f.getName() + " @ " + f.getEntryPoint() + "\n" + r.getDecompiledFunction().getC());
      }
    }
  }
}
J
analyzeHeadless $D/gh proj -import $T -scriptPath $D/scripts -postScript DumpDecomp.java $D/decomp.c -deleteProject
```
Then `rg -n NEEDLE $D/decomp.c` and read only the matching functions. Fallbacks: `r2 -qc 'aaa; afl; pdc @ main' T`, or `objdump -d -M intel`.

## 6. Rebuild a program (e.g. C++20 or C#) and verify
1. Inventory first, saved to `$D/inventory.md`: exports, imports, classes (RTTI), strings, resources, section sizes, paths.
2. Mirror the original's folder/file layout and names exactly where evidenced (PDB paths, `__FILE__` strings, resource names). Mark any guessed name **inferred**.
3. Write module by module. Do not paste raw decompiler output: rename, type and idiomatize (RAII, `std::span`, `std::string_view`, `enum class`).
4. After each module: compile, then diff inventories of the original vs the rebuilt binary (imports, exported symbols, string set, resource list). Each missing item is a TODO. Loop until the diff is empty or each remainder is **unknown** with a reason.
5. Finish with a coverage table: functions rebuilt/total, strings matched/total, imports matched/total.
