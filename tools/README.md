# dexshell_unpack_all.py — DexShell Universal Unpacker

Standalone, single-file unpacker for **DexShell v29+** (native AOT-compiled VMP).  
No additional Python packages needed — only external tools: `adb`, `java`, `radare2`.

---

## What it produces

```
<pkg>_unpack/
├── asm/                        # Per-method ARM64 disassembly
│   ├── com/pkg/Class/
│   │   ├── methodName__00a1.asm   # named (Java sig in header)
│   │   └── ...
│   └── unknown/
│       └── unknown_deadbeef__00ff.asm  # unresolved stubs
├── classes_smali/              # Full baksmali output of decrypted DEX
├── libdexshellx.so             # VMP engine (NDK-compiled)
├── libdexshell.so              # DexShell loader (native)
├── classes.dex                 # Fully-decrypted protected DEX
└── libdexshellx.r2             # radare2 project (function names + metadata)
<pkg>_unpack.zip                # Everything above in one zip
```

Each `.asm` file looks like:
```asm
// original: Lcom/example/Auth;->checkToken(Ljava/lang/String;)Z
// methodId: 0xa1  vaddr: 0x4b8f0  size: 612

0x0004b8f0  ff4301d1    sub sp, sp, #0x50
0x0004b8f4  f35701a9    stp x19, x21, [sp, #0x10]
...
0x0004b910  08000090    adrp x8, 0x60000
0x0004b914  087842f9    ldr x8, [x8, #0x4f0]  ; JNIEnv->GetStringUTFChars
0x0004b918  adrp x0, 0x4f000
0x0004b91c  00181591    add x0, x0, #0x546    ; "Authorization"
...
0x0004b930  00013fd6    blr x8                 ; JNIEnv->GetStringUTFChars
```

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Python | 3.8+ | standard library only |
| adb | any | must be in PATH |
| java | 8+ | for baksmali |
| radare2 | 5.x+ | ARM64 disassembly |
| Root + su | — | device must have root access |

**Device state required before running:**
- The target app must be **running and fully initialized** (so DexShell has written its runtime files)
- `adb` must be able to reach the device (USB or TCP)

---

## Quick Start

### Full automatic run (requires Frida-captured SO)

DexShell v29 **encrypts `libdexshellx.so` on disk**. The script must receive a
decrypted copy from memory. Use `capture_libdexshellx.js` (in `frida/`) to dump it
once, then pass it with `--so`.

```powershell
# 1. Forward Frida port and start the app
adb forward tcp:14725 tcp:14725
adb shell am start -n com.x.dexprotectx/com.x.dexprotectx.activities.SplashActivity
Start-Sleep -Seconds 1

# 2. Dump libdexshellx.so from memory via Frida (one-time capture)
frida -H 127.0.0.1:14725 -n Gadget `
    -l frida\bypass_v29_minimal.js `
    -l frida\capture_libdexshellx.js

# 3. Pull the captured SO from device
adb shell su -c "cp /data/data/com.x.dexprotectx/files/capture/libdexshellx.so /sdcard/"
adb pull /sdcard/libdexshellx.so

# 4. Run the unpacker with the decrypted SO + clean DEX
#    (always pass --dex too; the device classes2.dex has obfuscated internal offsets
#     that baksmali can't handle, so smali stubs won't resolve without a clean DEX)
python dexshell_unpack_all.py `
    --pkg com.x.dexprotectx `
    --device 10.210.3.226:5555 `
    --so  libdexshellx.so `
    --dex dexshellx_unpack\classes.dex

# 5. Output is in:  dexprotectx_unpack/  and  dexprotectx_unpack.zip
```

### If you already have the SO + DEX (no device needed)

```powershell
python dexshell_unpack_all.py `
    --pkg com.x.dexprotectx `
    --so  dexshellx_unpack\libdexshellx.so `
    --dex dexshellx_unpack\classes.dex `
    --out my_new_unpack
```

### Device-only run (without pre-captured SO)

The unpacker will find the SO at `txt/%s` in app data, but since it is encrypted
on disk, ELF parsing will fail. Use `--skip-asm` to still get the loader
(`libdexshell.so`) and a best-effort `classes.dex`:

```powershell
python dexshell_unpack_all.py --pkg com.x.dexprotectx --skip-asm
```

### Override tool paths

```powershell
python dexshell_unpack_all.py `
    --pkg com.x.dexprotectx `
    --r2exe  "C:\radare2\bin\radare2.exe" `
    --baksmali "C:\tools\baksmali.jar"
```

---

## CLI Reference

```
usage: dexshell_unpack_all.py [-h] --pkg PKG [--device DEVICE] [--out OUT]
                               [--batch BATCH] [--skip-asm]
                               [--so SO] [--dex DEX]
                               [--r2exe R2EXE] [--baksmali BAKSMALI]

options:
  --pkg PKG          Target Android package name (required)
  --device DEVICE    ADB device serial or IP:PORT (auto-detected if omitted)
  --out OUT          Output directory (default: ./<last_pkg_segment>_unpack/)
  --batch BATCH      Functions per radare2 invocation (default: 100)
  --skip-asm         Only pull files + fix DEX headers; skip disassembly stages
  --so SO            Pre-captured libdexshellx.so path (RECOMMENDED — on-disk
                     SO is encrypted; provide memory dump from Frida capture)
  --dex DEX          Pre-captured classes.dex path (skip device DEX extraction)
  --r2exe R2EXE      Path to radare2 executable
  --baksmali JAR     Path to baksmali.jar
```

---

## Pipeline

```
Stage 1  ADB      Connect device; find all zer0.txt paths under app data
Stage 2  zer0     Pull each zer0.txt; auto-detect format (DSLB / XOR-DSLB / ZIP / XOR-ZIP)
                  Extract: libdexshell.so, libdexshellx.so, classes.dex
Stage 3  LIBS     If SOs not in zer0: scan app data for large ELF files
Stage 3b DEX      If DEX not in zer0: try Frida dump dir or app-root classes*.dex
                  Repair DexShell header obfuscation (magic "DexShell" → "dex\n035\0",
                  zeroed offsets recomputed from sizes)
Stage 4  SMALI    baksmali decompile → classes_smali/
Stage 5  ELF      Parse libdexshellx.so:
                    - RELA relocations → reconstruct VMP dispatch table (funcVaddr[methodId])
                    - VMP signature filter (golden-ratio constants + GetArrayLength vtable)
                    - .rodata string scan → {vaddr: "string"} for annotation
Stage 6  STUBS    Scan classes_smali/ for N.invoke() call stubs
                  Map: methodId → Java class / method / full descriptor
Stage 7  DISASM   Batch radare2 disassembly of all VMP native functions
                  Annotate: JNI vtable calls (ldr+blr → JNIEnv->Method)
                            string literals (adrp+add → "string value")
                  Emit: libdexshellx.r2 (radare2 project for later re-use)
Stage 8  ZIP      Package everything → <pkg>_unpack.zip
```

---

## Using the .r2 output in radare2

```bash
# Open with project loaded (all function names + metadata)
radare2 -i libdexshellx.r2 libdexshellx.so

# Inside r2:
aaa           # analyse (already done by the .r2 script)
pdf @ vm.com.dexshell.x.InstrumentationHijacker.isInstalled_003f
```

## Re-generating asm/ without re-running the device pipeline

```powershell
# Use gen_asm_from_r2.py (needs existing .r2 + .so, no device)
python gen_asm_from_r2.py `
    --so dexprotectx_unpack\libdexshellx.so `
    --r2 dexprotectx_unpack\libdexshellx.r2 `
    --out dexprotectx_unpack\asm_rebuilt\
```

---

## Compatibility

| DexShell version | Status |
|-----------------|--------|
| v29.0 | Fully supported (native AOT VMP) |
| v26.x | Partial — zer0/DEX extraction works; VMP dispatch table may differ |
| < v26 | Not tested |

---

## Default tool paths (edit at top of script)

```python
R2_EXE       = r"C:\radare2\bin\radare2.exe"
BAKSMALI_JAR = r"Z:\WorkSpace\Practice Testing\APK.Tool.GUI.v3.3.2.1\Resources\baksmali.jar"
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `No zer0.txt found` | App not running or not fully initialized. Start app, wait ~5s, retry. |
| `libdexshellx.so not found` | See **Note on encrypted SO** below. |
| `ELF No executable section found` | The on-disk `txt/%s` SO is encrypted. Use `--so <frida_dump.so>`. |
| `VMP dispatch table not found` | SO version mismatch — the VMP signatures may differ. Inspect with `r2 libdexshellx.so` and update `VMP_SIG1/2/3`. |
| `baksmali ArrayIndexOutOfBoundsException` | DEX internal offsets are still obfuscated (only magic fixed). Pass a clean DEX with `--dex`, or run `deobfuscate_dexheader.py` first. |
| `r2 batch timed out` | Reduce `--batch` (e.g. `--batch 20`) or check radare2 installation. |
| No named functions in asm/ | DEX decompile failed (baksmali skipped). Check java / baksmali.jar path. |

### Note on encrypted SO

DexShell v29 stores `libdexshellx.so` as `txt/%s` inside app data, **encrypted on disk**.
The file looks like a large ELF (2.1 MB) but has no readable sections until decrypted by the
DexShell native loader at runtime. Attempting to parse it directly produces
`ELF No executable section found`.

To get a decrypted copy:
- **Option A:** Run `frida/capture_libdexshellx.js` while the app is running
  to dump the in-memory image (writes to `/data/data/<pkg>/files/capture/`)
- **Option B:** Extract `libdexshellx.so` from a previous `dexshellx_unpack*.zip`
  captured during a Frida session

Then pass it with `--so libdexshellx.so`.
