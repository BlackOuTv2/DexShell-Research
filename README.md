<div align="center">

# 🔬 DexShell Android Packer — Deep Reverse Engineering

![Platform](https://img.shields.io/badge/Platform-Android%20ARM64-3fb950?style=flat-square&logo=android)
![Frida](https://img.shields.io/badge/Frida-16.x-ff6b35?style=flat-square)
![radare2](https://img.shields.io/badge/radare2-5.x-58a6ff?style=flat-square)
![Status](https://img.shields.io/badge/Status-Fully%20Bypassed-3fb950?style=flat-square)
![Methods](https://img.shields.io/badge/VMP%20Methods-1%2C448-bc8cff?style=flat-square)
![License](https://img.shields.io/badge/Research-Educational-d29922?style=flat-square)

**Complete reverse engineering of DexShell / DexProtectX — a commercial Android packer.**  
v26 bytecode interpreter → v29 native AOT compiler. All 11 anti-tamper layers documented and bypassed.

[📊 **Visual Research (HTML + Flowcharts)**](https://BlackOuTv2.github.io/DexShell-Research) · [🛠️ Tools](#-tools) · [🔓 Bypasses](#-bypass-techniques)

---

### 👤 Researcher

| | |
|---|---|
| **Author** | [@BlackOuTv2](https://github.com/BlackOuTv2) |
| **GitHub** | https://github.com/BlackOuTv2 |
| **Research type** | Independent Android security research |
| **Scope** | Static + dynamic analysis, Frida instrumentation, native disassembly |

</div>

---

## 📋 Table of Contents

| | |
|---|---|
| [What is DexShell?](#what-is-dexshell) | [APK Structure](#apk-structure) |
| [Bootstrap Sequence](#bootstrap-sequence) | [Anti-Tamper (11 layers)](#anti-tamper-mechanisms) |
| [VMP Architecture](#vmp-architecture-v26-vs-v29) | [InstrumentationHijacker](#instrumentationhijacker-new-v29) |
| [DEX Header Obfuscation](#dex-header-obfuscation-new-v29) | [String Encryption](#string-encryption) |
| [Runic Unicode Names](#runic-unicode-obfuscation-new-v29) | [Network & Backend](#network--backend) |
| [AOSP Keys Found](#aosp-platform-keys-found-in-apk) | [Bypass Techniques](#bypass-techniques) |
| [Tools Built](#-tools) | [v26 → v29 Diff](#v26--v29-diff) |

---

## What is DexShell?

**DexShell** (sold as [DexProtectX](https://dexprotectx.pro)) is a commercial Android packer that protects app DEX through:

- **DEX encryption** — protected code decrypted only at runtime
- **VMP (Virtual Machine Protection)** — v26: bytecode interpreter · v29: native AOT compilation
- **11-layer anti-tamper** — Frida, Xposed, root, debugger, MTE-aware detection
- **InstrumentationHijacker** — replaces Android `Instrumentation` to catch analysis frameworks

> **Target:** `com.x.dexprotectx` wrapping a Blinkit delivery app  
> **Device:** Pixel 6a, Android 13, ARM64  
> **Versions:** DexShell v26.0 + v29.0

---

## APK Structure

```
DexShellx_V29.0.apk  (33.74 MB)
├── assets/
│   ├── DexShell.mp3            ← 9.2MB XOR-encrypted VMP container
│   │                              (3 embedded ELFs: arm64/arm32/x86, DT_SONAME=libdexshellx.so)
│   ├── dexshellx.pro           ← Config: 2.6KB (v26) → 21KB (v29), DXHD5 format
│   ├── libVMDexShellx.so       ← 465KB PairIP anti-tamper SDK (DT_SONAME=libpairipcore.so)
│   └── dexshell/arm64-v8a/
│       └── libdexshell.so      ← Core loader, decrypted at runtime, XOR key: 27d39683cc50fcba
│
├── unknown/keys/               ← ⚠️  AOSP platform.pk8 / media.pk8 / shared.pk8 bundled
│
├── classes.dex                 ← DexShell runtime (only 15 visible classes in v29)
└── classes5–16.dex             ← Protected app — method bodies replaced with N.invoke(idx) stubs
```

> **v29 change:** 514 DexShell support classes moved from static smali into an encrypted runtime DEX — including `okhttp3.*`, `org.bouncycastle.*`, `kotlin.*`, `okio.*`

---

## Bootstrap Sequence

```
App spawn
 └─ DexShellxApplication.attachBaseContext()
     ├─ Load libVMDexShellx.so (PairIP)
     │    └─ JNI_OnLoad: install all detection hooks
     │       (dl_iterate_phdr · /proc scan · stat · opendir · tgkill)
     │
     ├─ Load libdexshell.so (decrypted from assets at runtime)
     │    ├─ Decrypt DexShell.mp3 → extract libdexshellx.so to txt/%s  [encrypted on disk]
     │    ├─ dlopen → decrypt in memory → valid ELF in RAM only
     │    └─ ART ClassLinker::DefineClass → load 514 hidden classes
     │
 └─ Application.onCreate()
     ├─ InstrumentationHijacker.ᛱ᛽᛽ᲅ()   [NEW v29]
     │    └─ Reflect ActivityThread.mInstrumentation → swap ProxyInstrumentation
     │         └─ Now monitors ALL activity calls, polls execStartActivity 28×/4s
     │
     └─ DREXz delayed_detection starts (~4s timer)
         └─ K.ᛳᲆᛲ(Context, String)V → load protected app
```

---

## Anti-Tamper Mechanisms

> **All 11 layers bypassed.** See `frida/bypass_v29_minimal.js`

| # | Mechanism | Library | Detection method |
|---|-----------|---------|-----------------|
| 1 | `/proc/self/maps` scan | libdexshell.so | Frida agent region names in memory map |
| 2 | `TracerPid` check | libdexshell.so | Non-zero in `/proc/self/status` |
| 3 | **GOT corruption trap** | libdexshell.so | Overwrites libart GOT → SIGSEGV at `0x77d61f0220` |
| 4 | `dl_iterate_phdr` | libVMDexShellx.so | ByteHook enumerates ELFs for frida-agent |
| 5 | `opendir/readdir` | libVMDexShellx.so | Directory scan for Frida files on disk |
| 6 | `stat()` | libVMDexShellx.so | Frida filenames on filesystem |
| 7 | `__system_property_get` | libVMDexShellx.so | `ro.debuggable`, `ro.build.tags` |
| 8 | `syscall(SYS_tgkill=131)` | libdexshell.so | Raw syscall bypasses `kill()` hook |
| 9 | **VMP dispatch integrity** | libdexshellx.so | Golden-ratio counter + LR thunk check per method |
| 10 | **InstrumentationHijacker** | Runtime DEX | ProxyInstrumentation monitors all activity hooks |
| 11 | `delayed_detection` | DREXz | ~4s deferred full scan |

### GOT Trap Bypass

```javascript
// DexShell overwrites libart.so GOT with 0x77d61f0220 on Frida detection.
// Any JNI call through that stub crashes. Catch and resume at LR:
Process.setExceptionHandler(details => {
    if (details.address.equals(ptr('0x77d61f0220'))) {
        details.context.pc = details.context.lr;
        details.context.x0 = ptr(1);
        return true; // handled, resume
    }
});
```

### `dl_iterate_phdr` Bypass

```javascript
// ByteHook calls dl_iterate_phdr to find frida-agent-64.so.
// Interceptor.replace causes infinite recursion here — must use Interceptor.attach:
Interceptor.attach(Module.findExportByName(null, 'dl_iterate_phdr'), {
    onEnter(args) {
        this._origCallback = args[0];
        const filtered = new NativeCallback((info, size, data) => {
            const name = info.add(16).readCString() || '';
            if (name.includes('frida') || name.includes('frijia')) return 0;
            return this._origCallback(info, size, data);
        }, 'int', ['pointer','size_t','pointer']);
        args[0] = filtered;
    }
});
```

---

## VMP Architecture: v26 vs v29

### v26 — Threaded Bytecode Interpreter

```
Protected Java method → N.invoke(methodIndex, args[])
    ↓
libdexshellx.so: fetch bytecode record from DexShell.mp3 container @ offset[idx]
    ↓
256-opcode threaded interpreter loop
    ↓
Return result via JNI
```

**DexShell.mp3 container binary format** (data section @ `0xD1051`):
```c
// Per-class (repeating):
uint16  name_len;
char[]  class_descriptor;   // e.g. "La/o/MainActivety;"
uint16  method_count;       // ⚠️  uint16 NOT uint32 — critical for parsing
repeat method_count:
  uint32  global_method_idx;
  uint32  vm_bytecode_offset;
// Total: 1,395 classes, ~14,375 methods across 3 ELFs (arm64/arm32/x86)
```

### v29 — Native AOT Compiler

> **Key insight:** Each protected Java method is **compiled ahead-of-time to a native ARM64 JNI function**. The Java side is a stub; the logic is in `libdexshellx.so`.

```
Protected Java method → N.ᛱᛱ᛽(methodIndex, args[])   (Runic-named dispatcher)
    ↓
libdexshellx.so: funcVaddr[methodIndex]  ← dispatch table from RELA relocs
    ↓
Integrity checks:
  - Golden-ratio counter: counter * 0x9e3779b9 ^ 0x61c88646 at fixed .data slot
  - Dispatch return addr: LR must match expected thunk
    ↓ (any mismatch → JNIEnv->FatalError)
Execute compiled ARM64 native function (1,448 methods, 1,140 named)
```

**Dispatch table extraction:**
```python
# Apply R_AARCH64_RELATIVE relocs to .data.rel.ro → get funcVaddr[methodId]
for r_off, r_type, _, r_addend in elf.rela_entries('.rela.dyn'):
    if r_type == 1027:  # R_AARCH64_RELATIVE
        struct.pack_into('<Q', sec_data, r_off - sec_vaddr, r_addend)

# Find longest run of code pointers → dispatch table (1,817 entries → 1,462 VMP candidates)
# VMP signature filter: golden-ratio constants + GetArrayLength vtable access in first 256B
```

**Sample disassembly** — `InstrumentationHijacker.isInstalled()` (methodId `0x3f`):
```asm
// original: Lcom/dexshell/x/InstrumentationHijacker;->isInstalled()Z
// methodId: 0x3f  vaddr: 0xff0b8  size: 732

0x000ff0b8  ff8303d1    sub  sp, sp, 0xe0
0x000ff0e4  08fd9152    movk w8, #0x9e37, lsl#16   ; golden ratio check
0x000ff0e8  e8b97272    movk w8, #0x61c8
0x000ff0ec  08783cf9    ldr  x8, [x8, #0x6f0]      ; JNIEnv->GetPrimitiveArrayCritical
0x000ff0f4  00181591    add  x0, x0, 0x546          ; "isInstalled"  ← string annotated
0x000ff0fc  089842f9    ldr  x8, [x8, #0x530]       ; JNIEnv->NewStringUTF
```

---

## InstrumentationHijacker (NEW v29)

Replaces `ActivityThread.mInstrumentation` with `ProxyInstrumentation` — intercepts all activity lifecycle events.

**Install chain (reconstructed from ASM disassembly):**
```java
// methodId 0x58 — ᛱ᛽᛽ᲅ()V — called from Application.onCreate
if (!installGuard.compareAndSet(false, true)) return;  // one-time guard
Object thread = getActivityThread();                   // methodId 0x5c
Field f = ActivityThread.class.getDeclaredField("mInstrumentation");
f.setAccessible(true);
Instrumentation orig = (Instrumentation) f.get(thread);
injectProxy(thread, orig);                            // methodId 0x56 — swap
```

**Method map:**

| methodId | Name | Purpose |
|----------|------|---------|
| `0x3f` | `isInstalled()Z` | Check if proxy is active |
| `0x41` | `uninstall()V` | Restore original Instrumentation |
| `0x42–44` | `ᛱᛱᛱ/ᛱᛱᛲ/ᛱᛱᛳ ()Z` | Detection flag booleans |
| `0x56` | `ᛱ᛼᲋ᲊ(Object,Instrumentation)V` | **Inject** ProxyInstrumentation |
| **`0x58`** | **`ᛱ᛽᛽ᲅ()V`** | **Install** — entry from `onCreate` |
| `0x5c` | `ᛱᲆ᲋ᛳ()Object` | Get current `ActivityThread` |

**Bypass:**
```javascript
const IH = Java.use('com.dexshell.x.InstrumentationHijacker');
IH['ᛱ᛽᛽ᲅ'].implementation = function() {};          // block install
IH['ᛱ᛼᲋ᲊ'].implementation = function(a, b) {};      // block inject
IH['isInstalled'].implementation = () => false;
['ᛱᛱᛱ','ᛱᛱᛲ','ᛱᛱᛳ','ᛱᛱᛶ','ᛱᛱᛸ'].forEach(m =>
    IH[m].implementation = () => false);
```

---

## DEX Header Obfuscation (NEW v29)

`DexHeaderRestore` obfuscates headers on disk and restores them just-in-time for ART.

| Field | Original | Obfuscated |
|-------|----------|-----------|
| `magic[0:8]` | `dex\n035\0` | `"DexShell"` |
| All `*_off` fields | Valid offsets | Sentinel `0xffff0Xc0` |
| `map_off` | Valid | `0` |
| `file_size` | Actual size | Bogus smaller value |
| `header_size`, `endian_tag`, checksum, SHA-1 | ✅ **Unchanged** | — |

**Full reconstruction** (tool: `tools/deobfuscate_dexheader.py`):
```python
def deobfuscate_dex(data):
    d = bytearray(data)
    d[0:8] = b'dex\n035\x00'
    off = 0x70
    for sz_off, id_off, entry_size in SIZE_OFF_PAIRS:
        count = struct.unpack_from('<I', d, sz_off)[0]
        if count > 0:
            struct.pack_into('<I', d, id_off, off)
            off += count * entry_size
            off = (off + 3) & ~3      # 4-byte align
    struct.pack_into('<I', d, 32, len(d))  # restore file_size
    # recompute adler32 checksum + sha1 signature
    return bytes(d)
```

---

## String Encryption

**Algorithm:** XOR with cycling key  
**Decryptor:** `com.dexshell.x.shell.ᛱᛱᛳ.ᛱᛶᲃᲁ([B ciphertext, [B key) → String`

```python
def xor_decrypt(ciphertext: bytes, key: bytes) -> str:
    return bytes(c ^ key[i % len(key)] for i, c in enumerate(ciphertext)).decode()
```

**Captured keys (runtime Frida hook on `ᛱᲄ᛽ᛵ([B)[B`):**

| Key | Plaintext |
|-----|-----------|
| `6df83e88e674e688` | `execStartActivity` |
| `fb6c2ac32deba7f8` | `dex_login_panel_bypass` |
| `79c7185ad295af69` | `ACCESS_EXPIRED` |
| `eac89a5c67793e66` | `DEVELOPER_MODE` |
| `fc78d4510348f4ca` | `USB_DEBUG` |
| `a51c418694382ceb` | `VPN` |
| `b66c9b19ed84993e` | `DexShellx-Instr` |

---

## Runic Unicode Obfuscation (NEW v29)

All JNI method names in `com.dexshell.x.shell.K` renamed from ASCII to **Runic Unicode (U+16A0–U+16FF)**. Defeats `\w+` regex patterns and ASCII-assumption tools.

| v26 ASCII | v29 Runic | Signature | Bypass |
|-----------|-----------|-----------|--------|
| `K.s` | `K.ᛴᲆᛶ` | `()Z` | `return true` |
| `K.b` | `K.ᛴᲆᛷ` | `(String)Z` | `return true` |
| `K.j` | `K.ᛴᲆᛵ` | `(String)Object` | passthrough |
| `N.invoke` | `N.ᛱᛱ᛽` | `(I,[Object)Object` | VMP dispatcher |

---

## Network & Backend

**Confirmed endpoints (`dexprotectx.pro`):**
```
POST /dex/mobile/login          ← authentication
GET  /dex/analytics/check       ← license check (every launch)
GET  /dex/update?version=29.0   ← triggers UpdateActivity + auto-download
POST /dex/register              ← ⚠️  PLAINTEXT registration
```

**IP changes v26 → v29:**
| Version | IPv4 | CDN IPv4 | IPv6 |
|---------|------|----------|------|
| v26 | `172.67.151.252` | `104.21.65.118` | — |
| v29 | `172.67.151.252` | `104.21.33.246` | `2606:4700:3032::6815:21f6` + `2606:4700:3031::ac43:97fc` |

> ⚠️ v26 iptables block was IPv4-only — v29 used the IPv6 path to reach the update server until patched.

**Blocking (Magisk service.d):**
```bash
iptables  -I OUTPUT -d 172.67.151.252 -j DROP
iptables  -I OUTPUT -d 104.21.33.246  -j DROP
ip6tables -I OUTPUT -d 2606:4700:3032::6815:21f6 -j DROP
ip6tables -I OUTPUT -d 2606:4700:3031::ac43:97fc  -j DROP
```

**Credentials found in plaintext SharedPreferences:**
> `USER=blackout@007` · `PASS=qwerty321` — no encryption, accessible to any root/backup tool.

---

## AOSP Platform Keys Found in APK

`decoded/unknown/keys/` contains:

| File | Risk |
|------|------|
| `platform.pk8` | 🔴 **System-level** — APKs signed with this can request `sharedUserId="android.uid.system"` |
| `media.pk8` | 🟡 Media process access |
| `shared.pk8` | 🟡 Shared UID access |
| `testkey.pk8` | ⚪ Low risk on production |
| `keystore.ks` (JKS) | 🟡 All keys bundled |

`platform.pk8` DER header confirmed: `30 82 04 bc 02 01 00 ...`

---

## Bypass Techniques

**Connection (v29 uses Zygisk Gadget, not frida-server):**
```powershell
adb forward tcp:14725 tcp:14725
# Start app manually, wait ~1.3s
frida -H 127.0.0.1:14725 -n Gadget -l frida/bypass_v29_minimal.js
```
> `-f` spawn and `-F` frontmost both fail — only `-n Gadget` works.

**Complete bypass order in `frida/bypass_v29_minimal.js`:**
```javascript
// 1. GOT trap exception handler
// 2. /proc/self/maps + TracerPid + port 14725 filter
// 3. dl_iterate_phdr wrapper (hide Frida from ByteHook)
// 4. stat() → ENOENT, opendir/readdir filter, __system_property_get spoof
// 5. syscall(SYS_tgkill) self-kill block
// 6. K.ᛴᲆᛶ()Z → true,  K.ᛴᲆᛷ(String)Z → true
// 7. InstrumentationHijacker: ᛱ᛽᛽ᲅ no-op, ᛱ᛼᲋ᲊ no-op, isInstalled→false
// 8. System.exit / Process.killProcess / exit/_exit/abort → no-op
```

---

## 🛠️ Tools

| Tool | Description |
|------|-------------|
| [`tools/dexshell_unpack_all.py`](tools/dexshell_unpack_all.py) | Standalone VMP unpacker: ADB pull → ELF analysis → radare2 disasm → annotated ASM + r2 project |
| [`tools/gen_asm_from_r2.py`](tools/gen_asm_from_r2.py) | Regenerate `asm/` from `.r2` project + SO without device |
| `tools/deobfuscate_dexheader.py` | Full DEX header reconstruction (recomputes all offsets, adler32, SHA-1) |
| `tools/decode_config_v29.py` | DXHD5 config static analysis + decryption |
| [`frida/bypass_v29_minimal.js`](frida/bypass_v29_minimal.js) | Complete v29 bypass script |

**Quick start (no device needed — uses pre-captured files):**
```powershell
python tools/dexshell_unpack_all.py `
    --pkg  com.x.dexprotectx `
    --so   dexshellx_unpack/libdexshellx.so `
    --dex  dexshellx_unpack/classes.dex `
    --out  my_unpack
# Output: 1,448 ARM64 asm files + libdexshellx.r2 + classes_smali/
```

---

## v26 → v29 Diff

| Area | v26 | v29 |
|------|-----|-----|
| `libdexshell.so` | 1,225 KB | **1,374 KB (+12%)** |
| `dexshellx.pro` | 2,662 B | **21,283 B (8×)** |
| Visible smali classes | 529 | **15 (−514)** |
| JNI method names | ASCII | **Runic Unicode** |
| VMP mechanism | Bytecode interpreter | **Native AOT compiler** |
| `InstrumentationHijacker` | Absent | **Present** |
| `DexHeaderRestore` | Absent | **Present** |
| `delayed_detection` | Absent | **Present** |
| Backend CDN | `104.21.65.118` | **`104.21.33.246` + IPv6** |
| AOSP keys bundled | No | **Yes (platform.pk8 etc.)** |
| libdexshell XOR key | `106b07245fa133cd` | `27d39683cc50fcba` |

---

## Repository Structure

```
DexShell-Research/
├── index.html               ← Visual HTML with flowcharts & diagrams (open in browser)
├── README.md
├── frida/
│   └── bypass_v29_minimal.js
└── tools/
    ├── dexshell_unpack_all.py
    ├── gen_asm_from_r2.py
    └── README.md
```

---

<div align="center">

*Research for educational purposes.*  
**[@BlackOuTv2](https://github.com/BlackOuTv2)** · Frida · radare2 · baksmali · Python

</div>
