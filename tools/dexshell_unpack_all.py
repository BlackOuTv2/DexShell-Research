#!/usr/bin/env python3
"""
dexshell_unpack_all.py -- Standalone DexShell universal unpacker

ONE script. No external dependencies except adb, java (baksmali), and radare2.

Usage:
    python dexshell_unpack_all.py --pkg com.x.dexprotectx
    python dexshell_unpack_all.py --pkg com.x.dexprotectx --device 10.210.3.226:5555
    python dexshell_unpack_all.py --pkg com.x.dexprotectx --out ./my_unpack --skip-asm

Pipeline:
    1. ADB   -- connect device, find + pull zer0.txt files
    2. LIBS  -- extract libdexshell.so (loader) and libdexshellx.so (VMP engine)
    3. DEX   -- extract classes.dex; fix DexShell header obfuscation
    4. SMALI -- decompile DEX with baksmali
    5. ELF   -- parse libdexshellx.so: dispatch table (RELA) + string scan (.rodata)
    6. STUBS -- parse smali stubs: map methodId -> Java class/method
    7. DISASM-- batch-disassemble all VMP functions via radare2
               annotate: JNI vtable calls + ADRP/ADD string literals
               emit: libdexshellx.r2 (radare2 project with function names + metadata)
    8. ZIP   -- package asm/ + libdexshellx.r2 + classes.dex + SOs

Supported: DexShell v29+ (native AOT-compiled VMP)
"""

import argparse, io, os, re, struct, subprocess, sys, tempfile, time, zipfile
from pathlib import Path

# ── Tool paths ────────────────────────────────────────────────────────────────
R2_EXE       = r"C:\radare2\bin\radare2.exe"
BAKSMALI_JAR = r"Z:\WorkSpace\Practice Testing\APK.Tool.GUI.v3.3.2.1\Resources\baksmali.jar"
JAVA_EXE     = "java"
ADB_EXE      = "adb"

# ── DexShell constants ────────────────────────────────────────────────────────
ASSET_KEY  = bytes([0x10, 0x6B, 0x07, 0x24, 0x5F, 0xA1, 0x33, 0xCD])
DSLB_MAGIC = b"DSLB"
ZIP_MAGIC  = b"PK\x03\x04"
ELF_MAGIC  = b"\x7fELF"
DEX_MAGIC  = b"dex\n"

# ELF relocation type
R_AARCH64_RELATIVE = 1027

# VMP signature bytes (both must be present within first 256 bytes of each VMP function)
VMP_SIG1 = bytes([0xC6, 0xB3, 0x72])   # movk wR, #0x9e37, lsl#16 (golden ratio)
VMP_SIG2 = bytes([0x39, 0xAC, 0x72])   # movk wR, #0x61c8, lsl#16 (golden ratio)
VMP_SIG3 = bytes([0xAD, 0x42, 0xF9])   # ldr  xR, [xR, #0x558]   (GetArrayLength)

# Smali VMP dispatcher pattern
DISPATCHER_CLASS_PAT = r'Lcom/dexshell/x/N;->'
DISPATCHER_SIG_PAT   = r'\(I\[Ljava/lang/Object;\)Ljava/lang/Object;'

# JNIEnv vtable (ARM64, 8 bytes/entry)
JNI_ENV = {
    0x20:"GetVersion",         0x28:"DefineClass",
    0x30:"FindClass",          0x38:"FromReflectedMethod",
    0x40:"FromReflectedField", 0x48:"ToReflectedMethod",
    0x50:"GetSuperclass",      0x58:"IsAssignableFrom",
    0x60:"ToReflectedField",   0x68:"Throw",
    0x70:"ThrowNew",           0x78:"ExceptionOccurred",
    0x80:"ExceptionDescribe",  0x88:"ExceptionClear",
    0x90:"FatalError",         0x98:"PushLocalFrame",
    0xa0:"PopLocalFrame",      0xa8:"NewGlobalRef",
    0xb0:"DeleteGlobalRef",    0xb8:"DeleteLocalRef",
    0xc0:"IsSameObject",       0xc8:"NewLocalRef",
    0xd0:"EnsureLocalCapacity",0xd8:"AllocObject",
    0xe0:"NewObject",          0xe8:"NewObjectV",
    0xf0:"NewObjectA",         0xf8:"GetObjectClass",
    0x100:"IsInstanceOf",      0x108:"GetMethodID",
    0x110:"CallObjectMethod",  0x118:"CallObjectMethodV",
    0x120:"CallObjectMethodA", 0x128:"CallBooleanMethod",
    0x130:"CallBooleanMethodV",0x138:"CallBooleanMethodA",
    0x140:"CallByteMethod",    0x148:"CallByteMethodV",
    0x150:"CallByteMethodA",   0x158:"CallCharMethod",
    0x160:"CallCharMethodV",   0x168:"CallCharMethodA",
    0x170:"CallShortMethod",   0x178:"CallShortMethodV",
    0x180:"CallShortMethodA",  0x188:"CallIntMethod",
    0x190:"CallIntMethodV",    0x198:"CallIntMethodA",
    0x1a0:"CallLongMethod",    0x1a8:"CallLongMethodV",
    0x1b0:"CallLongMethodA",   0x1b8:"CallFloatMethod",
    0x1c0:"CallFloatMethodV",  0x1c8:"CallFloatMethodA",
    0x1d0:"CallDoubleMethod",  0x1d8:"CallDoubleMethodV",
    0x1e0:"CallDoubleMethodA", 0x1e8:"CallVoidMethod",
    0x1f0:"CallVoidMethodV",   0x1f8:"CallVoidMethodA",
    0x200:"CallNonvirtualObjectMethod",  0x208:"CallNonvirtualObjectMethodV",
    0x210:"CallNonvirtualObjectMethodA", 0x218:"CallNonvirtualBooleanMethod",
    0x2d8:"CallNonvirtualVoidMethod",    0x2e0:"CallNonvirtualVoidMethodV",
    0x2e8:"CallNonvirtualVoidMethodA",
    0x2f0:"GetFieldID",        0x2f8:"GetObjectField",
    0x300:"GetBooleanField",   0x308:"GetByteField",
    0x310:"GetCharField",      0x318:"GetShortField",
    0x320:"GetIntField",       0x328:"GetLongField",
    0x330:"GetFloatField",     0x338:"GetDoubleField",
    0x340:"SetObjectField",    0x348:"SetBooleanField",
    0x350:"SetByteField",      0x358:"SetCharField",
    0x360:"SetShortField",     0x368:"SetIntField",
    0x370:"SetLongField",      0x378:"SetFloatField",
    0x380:"SetDoubleField",
    0x388:"GetStaticMethodID",
    0x390:"CallStaticObjectMethod",  0x398:"CallStaticObjectMethodV",
    0x3a0:"CallStaticObjectMethodA", 0x3a8:"CallStaticBooleanMethod",
    0x3b0:"CallStaticBooleanMethodV",0x3b8:"CallStaticBooleanMethodA",
    0x3c0:"CallStaticByteMethod",    0x3c8:"CallStaticByteMethodV",
    0x3d0:"CallStaticByteMethodA",   0x3d8:"CallStaticCharMethod",
    0x3e0:"CallStaticCharMethodV",   0x3e8:"CallStaticCharMethodA",
    0x3f0:"CallStaticShortMethod",   0x3f8:"CallStaticShortMethodV",
    0x400:"CallStaticShortMethodA",  0x408:"CallStaticIntMethod",
    0x410:"CallStaticIntMethodV",    0x418:"CallStaticIntMethodA",
    0x420:"CallStaticLongMethod",    0x428:"CallStaticLongMethodV",
    0x430:"CallStaticLongMethodA",   0x438:"CallStaticFloatMethod",
    0x440:"CallStaticFloatMethodV",  0x448:"CallStaticFloatMethodA",
    0x450:"CallStaticDoubleMethod",  0x458:"CallStaticDoubleMethodV",
    0x460:"CallStaticDoubleMethodA", 0x468:"CallStaticVoidMethod",
    0x470:"CallStaticVoidMethodV",   0x478:"CallStaticVoidMethodA",
    0x480:"GetStaticFieldID",        0x488:"GetStaticObjectField",
    0x490:"GetStaticBooleanField",   0x498:"GetStaticByteField",
    0x4a0:"GetStaticCharField",      0x4a8:"GetStaticShortField",
    0x4b0:"GetStaticIntField",       0x4b8:"GetStaticLongField",
    0x4c0:"GetStaticFloatField",     0x4c8:"GetStaticDoubleField",
    0x4d0:"SetStaticObjectField",    0x4d8:"SetStaticBooleanField",
    0x4e0:"SetStaticByteField",      0x4e8:"SetStaticCharField",
    0x4f0:"SetStaticShortField",     0x4f8:"SetStaticIntField",
    0x500:"SetStaticLongField",      0x508:"SetStaticFloatField",
    0x510:"SetStaticDoubleField",
    0x518:"NewString",         0x520:"GetStringLength",
    0x528:"GetStringChars",    0x530:"ReleaseStringChars",
    0x538:"NewStringUTF",      0x540:"GetStringUTFLength",
    0x548:"GetStringUTFChars", 0x550:"ReleaseStringUTFChars",
    0x558:"GetArrayLength",    0x560:"NewObjectArray",
    0x568:"GetObjectArrayElement",   0x570:"SetObjectArrayElement",
    0x578:"NewBooleanArray",   0x580:"NewByteArray",
    0x588:"NewCharArray",      0x590:"NewShortArray",
    0x598:"NewIntArray",       0x5a0:"NewLongArray",
    0x5a8:"NewFloatArray",     0x5b0:"NewDoubleArray",
    0x5b8:"GetBooleanArrayElements", 0x5c0:"GetByteArrayElements",
    0x5c8:"GetCharArrayElements",    0x5d0:"GetShortArrayElements",
    0x5d8:"GetIntArrayElements",     0x5e0:"GetLongArrayElements",
    0x5e8:"GetFloatArrayElements",   0x5f0:"GetDoubleArrayElements",
    0x5f8:"ReleaseBooleanArrayElements", 0x600:"ReleaseByteArrayElements",
    0x608:"ReleaseCharArrayElements",    0x610:"ReleaseShortArrayElements",
    0x618:"ReleaseIntArrayElements",     0x620:"ReleaseLongArrayElements",
    0x628:"ReleaseFloatArrayElements",   0x630:"ReleaseDoubleArrayElements",
    0x638:"GetBooleanArrayRegion",  0x640:"GetByteArrayRegion",
    0x648:"GetCharArrayRegion",     0x650:"GetShortArrayRegion",
    0x658:"GetIntArrayRegion",      0x660:"GetLongArrayRegion",
    0x668:"GetFloatArrayRegion",    0x670:"GetDoubleArrayRegion",
    0x678:"SetBooleanArrayRegion",  0x680:"SetByteArrayRegion",
    0x688:"SetCharArrayRegion",     0x690:"SetShortArrayRegion",
    0x698:"SetIntArrayRegion",      0x6a0:"SetLongArrayRegion",
    0x6a8:"SetFloatArrayRegion",    0x6b0:"SetDoubleArrayRegion",
    0x6b8:"RegisterNatives",        0x6c0:"UnregisterNatives",
    0x6c8:"MonitorEnter",           0x6d0:"MonitorExit",
    0x6d8:"GetJavaVM",              0x6e0:"GetStringRegion",
    0x6e8:"GetStringUTFRegion",
    0x6f0:"GetPrimitiveArrayCritical", 0x6f8:"ReleasePrimitiveArrayCritical",
    0x700:"GetStringCritical",      0x708:"ReleaseStringCritical",
    0x710:"NewWeakGlobalRef",       0x718:"DeleteWeakGlobalRef",
    0x720:"ExceptionCheck",         0x728:"NewDirectByteBuffer",
    0x730:"GetDirectBufferAddress", 0x738:"GetDirectBufferCapacity",
    0x740:"GetObjectRefType",
}


# ════════════════════════════════════════════════════════════════════════════
# STAGE 1 — ADB utilities
# ════════════════════════════════════════════════════════════════════════════

def adb_run(args, device=None, capture=True):
    cmd = [ADB_EXE]
    if device:
        cmd += ["-s", device]
    cmd += args
    if capture:
        return subprocess.check_output(cmd)
    subprocess.run(cmd, check=True)

def adb_su_cat(remote, device=None):
    return adb_run(["exec-out", "su", "-c", f"cat {remote}"], device=device)

def adb_su_find(pattern, base, device=None):
    try:
        out = adb_run(["shell", "su", "-c",
                       f"find {base} -name '{pattern}' 2>/dev/null"], device=device)
        return [l.strip() for l in out.decode(errors='replace').splitlines() if l.strip()]
    except Exception:
        return []

def find_device(explicit=None):
    if explicit:
        adb_run(["connect", explicit], capture=False)
        time.sleep(1)
    out = adb_run(["devices"]).decode(errors='replace')
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            dev = parts[0]
            print(f"[ADB] Device: {dev}")
            return dev
    return None


# ════════════════════════════════════════════════════════════════════════════
# STAGE 2 — zer0.txt pull and parse
# ════════════════════════════════════════════════════════════════════════════

def _xor(data, key=ASSET_KEY):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def _classify(blob):
    if blob.startswith(DSLB_MAGIC): return "dslb_plain"
    dec = _xor(blob[:8])
    if dec.startswith(DSLB_MAGIC):  return "dslb_xor"
    if dec.startswith(ZIP_MAGIC):   return "zip_xor"
    if blob.startswith(ZIP_MAGIC):  return "zip_plain"
    return "unknown"

def _parse_dslb(buf):
    assert buf[:4] == DSLB_MAGIC
    count = struct.unpack_from("<H", buf, 5)[0]
    off   = 7
    out   = {}
    for _ in range(count):
        nl  = struct.unpack_from("<H", buf, off)[0]; off += 2
        nm  = buf[off:off+nl].decode("utf-8"); off += nl
        dl  = struct.unpack_from("<I", buf, off)[0]; off += 4
        out[nm] = _xor(buf[off:off+dl]); off += dl
    return out

def pull_zer0_files(pkg, device, out_dir):
    """Pull all zer0.txt files and return extracted entries {name: bytes}."""
    extracted = {}
    paths = adb_su_find("zer0.txt", f"/data/data/{pkg}", device=device)
    # Also search for hidden .zer0.txt.SUFFIX files (v29 stores DEX there)
    hidden = adb_su_find(".zer0.txt*", f"/data/data/{pkg}", device=device)
    paths = paths + [p for p in hidden if p not in paths]
    if not paths:
        print(f"[zer0] No zer0.txt found under /data/data/{pkg}")
        print(f"[zer0] Make sure the app is running and has fully initialized")
        return extracted

    for i, rpath in enumerate(paths, 1):
        blob = adb_su_cat(rpath, device=device)
        if len(blob) < 64:
            continue  # skip tiny placeholder/lock files silently
        print(f"[zer0] Pulling {rpath} ...")
        kind = _classify(blob)
        print(f"[zer0]   {len(blob):,} bytes  format={kind}")

        if kind == "dslb_plain":
            entries = _parse_dslb(blob)
        elif kind == "dslb_xor":
            entries = _parse_dslb(_xor(blob))
        elif kind in ("zip_xor", "zip_plain"):
            zb = _xor(blob) if kind == "zip_xor" else blob
            try:
                with zipfile.ZipFile(io.BytesIO(zb)) as z:
                    entries = {info.filename: z.read(info.filename) for info in z.infolist()}
            except Exception as e:
                print(f"[zer0]   ZIP parse failed: {e}")
                entries = {}
        else:
            print(f"[zer0]   Unrecognised format — saving raw")
            raw_path = out_dir / f"zer0_{i}.raw"
            raw_path.write_bytes(blob)
            continue

        for name, data in entries.items():
            magic = "ELF" if data.startswith(ELF_MAGIC) else \
                    "DEX" if data.startswith(DEX_MAGIC)  else "?"
            print(f"[zer0]   [{magic}] {name}  {len(data):,} bytes")
            dst = out_dir / Path(name).name
            dst.write_bytes(data)
            extracted[name] = data

    return extracted


# ════════════════════════════════════════════════════════════════════════════
# STAGE 3 — library discovery
# ════════════════════════════════════════════════════════════════════════════

def find_libdexshellx(pkg, device, out_dir):
    """Find libdexshellx.so — VMP engine, lives in app data as txt/%s."""
    so_path = out_dir / "libdexshellx.so"

    # Check txt/%s pattern (DexShell stores VMP engine here)
    dirs = adb_su_find("%s", f"/data/data/{pkg}", device=device)
    for p in dirs:
        if "/txt/" in p:
            print(f"[SO] Found libdexshellx.so at {p}")
            data = adb_su_cat(p, device=device)
            if data.startswith(ELF_MAGIC) and len(data) > 1_000_000:
                so_path.write_bytes(data)
                print(f"[SO] Saved libdexshellx.so ({len(data):,} bytes)")
                return so_path

    # Fallback: scan app data for large ARM64 ELF
    print("[SO] Scanning for large ELF files in app data...")
    big_files = adb_su_find("*", f"/data/data/{pkg}", device=device)
    for p in big_files:
        try:
            header = adb_run(["shell", "su", "-c", f"dd if={p} bs=4 count=1 2>/dev/null"],
                             device=device)
            if header.startswith(ELF_MAGIC):
                data = adb_su_cat(p, device=device)
                if 1_500_000 < len(data) < 4_000_000:
                    so_path.write_bytes(data)
                    print(f"[SO] Found at {p} ({len(data):,} bytes)")
                    return so_path
        except Exception:
            pass

    print("[SO] libdexshellx.so not found")
    return None


def find_classes_dex(pkg, device, zer0_entries, out_dir):
    """Get classes.dex from zer0 entries or Frida dump."""
    dex_path = out_dir / "classes.dex"

    # Priority 1: from zer0 entries
    for name, data in zer0_entries.items():
        if name.endswith(".dex") or name == "classes.dex":
            if data.startswith(DEX_MAGIC):
                dex_path.write_bytes(data)
                print(f"[DEX] classes.dex from zer0: {len(data):,} bytes")
                return dex_path

    # Priority 2: from Frida dump directory on device
    dump_paths = adb_su_find("scan_2s_*.dex", f"/data/data/{pkg}", device=device)
    if dump_paths:
        # Pick largest (most class coverage)
        sizes = []
        for p in dump_paths:
            try:
                sz = int(adb_run(["shell", "su", "-c", f"wc -c < {p} 2>/dev/null"],
                                 device=device).decode().strip())
                sizes.append((sz, p))
            except Exception:
                pass
        if sizes:
            _, best = max(sizes)
            print(f"[DEX] Using Frida dump: {best}")
            data = adb_su_cat(best, device=device)
            dex_path.write_bytes(data)
            return dex_path

    # Priority 3: from app data root (DexShell writes obfuscated DEX there)
    for fname in ["classes2.dex", "classes1.dex", "classes3.dex"]:
        remote = f"/data/data/{pkg}/{fname}"
        try:
            data = adb_su_cat(remote, device=device)
            if len(data) > 100_000:
                fixed = fix_dex_header(data)
                if fixed:
                    dex_path.write_bytes(fixed)
                    print(f"[DEX] {fname} fixed: {len(fixed):,} bytes")
                    return dex_path
        except Exception:
            pass

    print("[DEX] classes.dex not found on device")
    return None


# ════════════════════════════════════════════════════════════════════════════
# STAGE 3b — DEX header repair
# ════════════════════════════════════════════════════════════════════════════

def fix_dex_header(data):
    """
    DexShell obfuscates DEX headers in two ways:
      - Changes magic to "DexShell" (restored: check header_size/endian at shifted offset)
      - Inserts \\r before \\n in "dex\\n..." (1-byte shift, standard for app root DEX)
    Returns fixed bytes or None if not fixable.
    """
    if data[:4] == DEX_MAGIC:
        return data  # already clean

    # Attempt: "DexShell" magic, standard offsets
    if data[:8] == b"DexShell":
        fixed = bytearray(data)
        fixed[0:8] = b'dex\n035\x00'
        if struct.unpack_from('<I', fixed, 36)[0] == 0x70 and \
           struct.unpack_from('<I', fixed, 40)[0] == 0x12345678:
            return bytes(fixed)
        # Try to restore header via deobfuscate_dexheader logic
        return _restore_dexshell_header(data)

    # Attempt: "dex\r\n..." (1-byte shift obfuscation)
    if data[:3] == b'dex' and data[3] == 0x0d:
        fixed = bytearray(data[:3]) + b'\x0a' + data[5:]  # remove \r, keep \n
        if struct.unpack_from('<I', fixed, 36)[0] == 0x70 and \
           struct.unpack_from('<I', fixed, 40)[0] == 0x12345678:
            return bytes(fixed)

    return None


def _restore_dexshell_header(data):
    """Minimal DEX header restoration for 'DexShell' magic obfuscation."""
    d = bytearray(data)
    # Restore magic
    d[0:8] = b'dex\n035\x00'
    # Restore header_size (0x70) and endian_tag (0x12345678)
    struct.pack_into('<I', d, 36, 0x70)
    struct.pack_into('<I', d, 40, 0x12345678)
    # Check if the rest looks sane (file_size field)
    file_size = struct.unpack_from('<I', d, 32)[0]
    if file_size == len(data) or abs(file_size - len(data)) < 100_000:
        return bytes(d)
    # Try setting file_size to actual size
    struct.pack_into('<I', d, 32, len(data))
    return bytes(d)


# ════════════════════════════════════════════════════════════════════════════
# STAGE 4 — baksmali
# ════════════════════════════════════════════════════════════════════════════

def run_baksmali(dex_path, smali_dir):
    smali_dir.mkdir(parents=True, exist_ok=True)
    print(f"[SMALI] Decompiling {dex_path.name} ...")
    try:
        subprocess.run([JAVA_EXE, "-jar", BAKSMALI_JAR, "d",
                        str(dex_path), "-o", str(smali_dir)],
                       check=True, capture_output=True)
        count = sum(1 for _ in smali_dir.rglob("*.smali"))
        print(f"[SMALI] {count:,} smali files -> {smali_dir}")
        return count > 0
    except subprocess.CalledProcessError as e:
        print(f"[SMALI] baksmali failed: {e.stderr.decode(errors='replace')[:200]}")
        return False


# ════════════════════════════════════════════════════════════════════════════
# STAGE 5 — ELF dispatch table (from gen_asm_universal.py)
# ════════════════════════════════════════════════════════════════════════════

class ELF64:
    def __init__(self, path):
        self.data = Path(path).read_bytes()
        self._parse_header()
        self._parse_sections()

    def _u(self, fmt, off):
        return struct.unpack_from(fmt, self.data, off)

    def _parse_header(self):
        if self.data[:4] != b'\x7fELF' or self.data[4] != 2:
            raise ValueError("Not ELF64")
        self.e_shoff     = self._u('<Q', 0x28)[0]
        self.e_shentsize = self._u('<H', 0x3a)[0]
        self.e_shnum     = self._u('<H', 0x3c)[0]
        self.e_shstrndx  = self._u('<H', 0x3e)[0]

    def _parse_sections(self):
        shstrtab = self._shdr(self.e_shstrndx)
        ss_off   = shstrtab['sh_offset']
        self.sections = {}
        for i in range(self.e_shnum):
            hdr  = self._shdr(i)
            name = self._read_str(ss_off + hdr['sh_name'])
            hdr['name'] = name
            self.sections[name] = hdr

    def _shdr(self, idx):
        off  = self.e_shoff + idx * self.e_shentsize
        keys = ['sh_name','sh_type','sh_flags','sh_addr','sh_offset',
                'sh_size','sh_link','sh_info','sh_addralign','sh_entsize']
        return dict(zip(keys, self._u('<IIQQQQIIQQ', off)))

    def _read_str(self, off):
        end = self.data.index(b'\x00', off)
        return self.data[off:end].decode('utf-8', errors='replace')

    def section_data(self, name):
        s = self.sections.get(name)
        if not s: return None, 0, 0
        return self.data[s['sh_offset']:s['sh_offset']+s['sh_size']], s['sh_addr'], s['sh_size']

    def rela_entries(self, sec_name):
        s = self.sections.get(sec_name)
        if not s: return
        es = s['sh_entsize'] or 24
        for i in range(s['sh_size'] // es):
            off = s['sh_offset'] + i * es
            r_offset, r_info, r_addend = self._u('<QQq', off)
            yield r_offset, r_info & 0xffffffff, r_info >> 32, r_addend


def find_dispatch_table(so_path, elf=None):
    print("[ELF] Parsing libdexshellx.so ...")
    if elf is None:
        elf = ELF64(so_path)

    text_vaddr = text_size = text_foff = 0
    for sec in elf.sections.values():
        if sec['sh_flags'] & 0x4 and sec['sh_size'] > text_size:
            text_vaddr = sec['sh_addr']
            text_size  = sec['sh_size']
            text_foff  = sec['sh_offset']
    if not text_size:
        print("[ELF] No executable section found"); return []
    text_end = text_vaddr + text_size
    print(f"[ELF] .text: 0x{text_vaddr:x}-0x{text_end:x} ({text_size:,} B)")

    for sec_name in ('.data.rel.ro', '.data'):
        sec_bytes, sec_vaddr, sec_size = elf.section_data(sec_name)
        if sec_bytes and sec_size >= 16: break
    else:
        print("[ELF] No data section"); return []

    # Apply RELA relocations
    sec_data = bytearray(sec_bytes)
    applied  = 0
    for r_off, r_type, _, r_addend in elf.rela_entries('.rela.dyn'):
        if r_type != R_AARCH64_RELATIVE: continue
        loc = r_off - sec_vaddr
        if 0 <= loc < sec_size - 7:
            struct.pack_into('<Q', sec_data, loc, r_addend & 0xffffffffffffffff)
            applied += 1
    print(f"[ELF] Applied {applied} RELATIVE relocs to {sec_name}")

    # Find longest run of code pointers
    n = sec_size // 8
    best_start = best_len = cur_start = cur_len = 0
    for i in range(n):
        ptr = struct.unpack_from('<Q', sec_data, i * 8)[0]
        if text_vaddr <= ptr < text_end:
            if cur_len == 0: cur_start = i
            cur_len += 1
            if cur_len > best_len:
                best_len  = cur_len
                best_start = cur_start
        else:
            cur_len = 0

    if best_len < 10:
        print(f"[ELF] Dispatch table not found (best={best_len})"); return []

    coarse = [struct.unpack_from('<Q', sec_data, (best_start+i)*8)[0]
              for i in range(best_len)]
    print(f"[ELF] Coarse run: {best_len} entries at array index {best_start}")

    # VMP signature filter
    so_bytes = elf.data
    def is_vmp(vaddr):
        foff = text_foff + (vaddr - text_vaddr)
        if foff < 0 or foff + 256 > len(so_bytes): return False
        s = so_bytes[foff:foff+256]
        return VMP_SIG1 in s and VMP_SIG2 in s and VMP_SIG3 in s

    vmp_start = vmp_end = None
    for i, va in enumerate(coarse):
        if is_vmp(va):
            vmp_start = i; break
    for i in range(len(coarse)-1, -1, -1):
        if is_vmp(coarse[i]):
            vmp_end = i + 1; break

    if vmp_start is None:
        print("[ELF] No VMP functions detected"); return coarse
    vaddrs = coarse[vmp_start:vmp_end]
    pre  = vmp_start
    post = len(coarse) - (vmp_end or len(coarse))
    print(f"[ELF] VMP candidates: {len(vaddrs)} (trimmed {pre} pre / {post} post)")
    return vaddrs


# ════════════════════════════════════════════════════════════════════════════
# STAGE 5b — ELF string scanner
# ════════════════════════════════════════════════════════════════════════════

def scan_elf_strings(elf, min_len=4):
    """
    Scan .rodata (and .data.rel.ro) for null-terminated ASCII strings.
    Returns {vaddr: str} for strings of length >= min_len.
    """
    str_map = {}
    for sec_name in ('.rodata', '.data.rel.ro', '.data'):
        sec_data, sec_va, sec_size = elf.section_data(sec_name)
        if sec_data is None:
            continue
        i = 0
        while i < sec_size:
            j = i
            while j < sec_size and 0x20 <= sec_data[j] <= 0x7e:
                j += 1
            if j - i >= min_len and (j >= sec_size or sec_data[j] == 0):
                str_map[sec_va + i] = sec_data[i:j].decode('ascii')
            i = j + 1
    if str_map:
        print(f"[STR] Found {len(str_map):,} strings in ELF")
    return str_map


# ════════════════════════════════════════════════════════════════════════════
# STAGE 6 — smali stub parser
# ════════════════════════════════════════════════════════════════════════════

_CONST_RE  = re.compile(
    r'^\s+const(?:/4|/16|/high16|)?\s+(v\d+|p\d+),\s+(-?0x[0-9a-fA-F]+|-?\d+)',
    re.MULTILINE)
_INVOKE_RE = re.compile(DISPATCHER_CLASS_PAT + r'\S+' + DISPATCHER_SIG_PAT)
_LOW_PRIO  = ('java/', 'android/', 'kotlin/', 'okhttp3/', 'okio/', 'org/')


def parse_smali_stubs(smali_dir):
    print(f"[SMALI] Parsing stubs in {smali_dir} ...")
    stub_map  = {}
    ambiguous = 0
    total     = 0

    smali_root = Path(smali_dir)
    for smali_file in smali_root.rglob('*.smali'):
        try:
            text = smali_file.read_text(encoding='utf-8', errors='replace')
        except Exception:
            continue
        # Use FILE path for class name (immune to obfuscated .class directives)
        class_path = smali_file.relative_to(smali_root).with_suffix('').as_posix()

        for method_block in re.finditer(
                r'(\.method\s+(.+?)\n)(.*?)(\.end method)', text, re.DOTALL):
            header = method_block.group(2).strip()
            body   = method_block.group(3)
            total += 1

            if not _INVOKE_RE.search(body): continue

            nm = re.search(r'(\S+)\(([^)]*)\)(\S+)$', header)
            if not nm: continue
            method_name = nm.group(1)
            full_sig    = f"L{class_path};->{method_name}({nm.group(2)}){nm.group(3)}"

            inv = re.search(r'invoke-static\s+\{([^}]+)\}', body)
            if not inv: continue
            mid_reg = [r.strip() for r in inv.group(1).split(',')][0]

            body_pre  = body[:inv.start()]
            method_id = None
            for cm in _CONST_RE.finditer(body_pre):
                if cm.group(1) == mid_reg:
                    try:
                        raw = int(cm.group(2), 16) if cm.group(2).startswith(('0x','-0x')) \
                              else int(cm.group(2))
                        method_id = raw & 0xffffffff
                    except ValueError:
                        pass
            if method_id is None: continue

            entry = {'class': class_path, 'method': method_name, 'sig': full_sig}
            if method_id in stub_map:
                ambiguous += 1
                cur_low = stub_map[method_id]['class'].startswith(_LOW_PRIO)
                new_low = class_path.startswith(_LOW_PRIO)
                if cur_low and not new_low:
                    stub_map[method_id] = entry
            else:
                stub_map[method_id] = entry

    named = len(stub_map)
    print(f"[SMALI] {total:,} methods scanned  ->  {named} VMP stubs "
          + (f" ({ambiguous} ambiguous resolved)" if ambiguous else ""))
    return stub_map


def align_table(vaddrs, stub_map):
    if not stub_map: return vaddrs
    max_mid = max(stub_map.keys())
    exact   = max_mid + 1
    if len(vaddrs) > exact:
        overflow = len(vaddrs) - exact
        print(f"[ELF] Alignment: skip {overflow} pre-table entries -> {exact} VMP functions")
        return vaddrs[overflow:]
    return vaddrs


def build_func_map(vaddrs, stub_map):
    sorted_unique = sorted(set(vaddrs))
    gap_size = {va: sorted_unique[i+1] - va
                for i, va in enumerate(sorted_unique[:-1])}
    funcs = []
    for mid, va in enumerate(vaddrs):
        sz   = max(8, min(gap_size.get(va, 512), 65536))
        info = stub_map.get(mid, {})
        funcs.append({'method_id': mid, 'vaddr': va, 'size': sz,
                      'java_sig': info.get('sig'),
                      'class_path': info.get('class'),
                      'method_name': info.get('method')})
    named = sum(1 for f in funcs if f['java_sig'])
    print(f"[MAP] {len(funcs)} functions: {named} named, {len(funcs)-named} unnamed")
    return funcs


# ════════════════════════════════════════════════════════════════════════════
# STAGE 7 — radare2 disassembly + JNI annotation
# ════════════════════════════════════════════════════════════════════════════

_ANSI     = re.compile(r'\x1b\[[0-9;]*m')
_LDR_VTBL = re.compile(r'ldr\s+(x\d+),\s+\[(x\d+),\s+#?(0x[0-9a-f]+)\]')
_BLR_RE   = re.compile(r'\b(blr|br)\s+\w+')


def disasm_all(so_path, funcs, batch_size=100):
    print(f"[DISASM] Disassembling {len(funcs)} functions (batch={batch_size}) ...")
    results = {}
    for start in range(0, len(funcs), batch_size):
        batch  = funcs[start:start+batch_size]
        raw    = _r2_batch(so_path, batch)
        parsed = _split_r2(raw)
        results.update(parsed)
        done = min(start+batch_size, len(funcs))
        print(f"    [{done}/{len(funcs)}]", end='\r', flush=True)
    print()
    return results


def _r2_batch(so_path, funcs):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.r2',
                                     delete=False, encoding='utf-8') as tf:
        tf.write('e asm.arch=arm\ne asm.bits=64\ne asm.comments=false\ne scr.color=0\n')
        for fn in funcs:
            tf.write(f"pD 0x{fn['size']:x} @ 0x{fn['vaddr']:x}\n")
            tf.write(f"echo ===END_{fn['vaddr']:x}===\n")
        script = tf.name
    try:
        proc = subprocess.run(
            [R2_EXE, '-q', '-e', 'scr.color=0', '-i', script, str(so_path)],
            capture_output=True, text=True, timeout=120,
            encoding='utf-8', errors='replace')
        return proc.stdout
    except subprocess.TimeoutExpired:
        return ''
    finally:
        os.unlink(script)


def _split_r2(raw):
    raw   = _ANSI.sub('', raw)
    parts = re.split(r'===END_([0-9a-f]+)===', raw)
    out   = {}
    i = 1
    while i < len(parts):
        try:
            va    = int(parts[i], 16)
            lines = [l+'\n' for l in parts[i-1].splitlines()
                     if l.strip() and not l.startswith('[')]
            out[va] = lines
        except ValueError:
            pass
        i += 2
    return out


def annotate_jni(asm_lines):
    out, pending = [], None
    for line in asm_lines:
        s = line.rstrip()
        m = _LDR_VTBL.search(s)
        if m and m.group(1) == m.group(2):
            off = int(m.group(3), 16) if m.group(3) else -1
            if off in JNI_ENV:
                pending = JNI_ENV[off]
                s = s + f'  ; JNIEnv->{pending}'
            else:
                pending = None
        elif _BLR_RE.search(s) and pending:
            s = s + f'  ; JNIEnv->{pending}'
            pending = None
        else:
            pending = None
        out.append(s + '\n')
    return out


_ADRP_RE    = re.compile(r'\badrp\s+(x\d+),\s+(0x[0-9a-f]+)')
_ADD_OFF_RE = re.compile(r'\badd\s+(x\d+),\s+(x\d+),\s+(?:#)?(0x[0-9a-f]+|\d+)')


def annotate_strings(asm_lines, str_map):
    """
    Annotate ADRP+ADD pairs whose resolved address maps to a known ELF string.

    ADRP loads a 4KB-aligned page address; the subsequent ADD (same dst=src reg)
    adds the within-page offset to form the final pointer.
    """
    if not str_map:
        return asm_lines
    out      = []
    adrp_reg = {}  # register -> page_base
    for line in asm_lines:
        s = line.rstrip()
        m = _ADRP_RE.search(s)
        if m:
            adrp_reg[m.group(1)] = int(m.group(2), 16)
        else:
            m2 = _ADD_OFF_RE.search(s)
            if m2 and m2.group(1) == m2.group(2) and m2.group(2) in adrp_reg:
                reg  = m2.group(1)
                off_s = m2.group(3)
                off  = int(off_s, 16) if off_s.startswith('0x') else int(off_s)
                addr = adrp_reg.pop(reg) + off
                if addr in str_map:
                    snippet = str_map[addr][:80].replace('\n', '\\n')
                    s = s + f'  ; "{snippet}"'
            else:
                # Non-ADRP/ADD instruction; don't clear adrp_reg so multi-use pages work
                pass
        out.append(s + '\n')
    return out


# ════════════════════════════════════════════════════════════════════════════
# STAGE 8 — write asm files + package zip
# ════════════════════════════════════════════════════════════════════════════

def write_asm(out_dir, fn, asm_lines):
    mid  = fn['method_id']
    hid  = f'{mid:04x}'
    cp   = fn.get('class_path')
    mn   = fn.get('method_name')

    if cp and mn:
        safe = ''.join(c if (0x20 <= ord(c) < 0x7f and c not in '/\\:\0') else '_' for c in mn)
        fpath = Path(out_dir) / cp / f'{safe}__{hid}.asm'
    else:
        fpath = Path(out_dir) / 'unknown' / f'unknown_{fn["vaddr"]:08x}__{hid}.asm'

    fpath.parent.mkdir(parents=True, exist_ok=True)
    header = []
    if fn.get('java_sig'):
        header.append(f"// original: {fn['java_sig']}\n")
    header.append(f"// methodId: 0x{mid:x}  vaddr: 0x{fn['vaddr']:x}  size: {fn['size']}\n\n")

    with open(fpath, 'w', encoding='utf-8') as f:
        f.writelines(header)
        f.writelines(asm_lines)


def write_r2_project(r2_path, funcs):
    """
    Generate a radare2 .r2 script from the func map.
    Produces afu (boundary) + afn (name) + CCu (Java sig metadata) per function.
    Compatible with gen_asm_from_r2.py for later re-disassembly.
    """
    import base64
    with open(r2_path, 'w', encoding='utf-8') as f:
        f.write('# DexShell VMP function map\n')
        f.write(f'# Generated by dexshell_unpack_all.py  functions={len(funcs)}\n\n')
        for fn in funcs:
            va  = fn['vaddr']
            end = va + fn['size']
            mid = fn['method_id']
            sig = fn.get('java_sig')
            f.write(f"afu 0x{end:x} @ 0x{va:x}\n")
            if sig:
                m = re.match(r'L([^;]+);->([^(]+)\(', sig)
                if m:
                    cls_dot = m.group(1).replace('/', '.')
                    meth    = m.group(2)
                    safe    = ''.join(
                        c if (0x20 <= ord(c) < 0x7f and c not in '/\\:.\0') else '_'
                        for c in meth)
                    hid  = f'{mid:04x}' if mid is not None else '????'
                    name = f'vm.{cls_dot}.{safe}_{hid}'
                    f.write(f"afn {name} @ 0x{va:x}\n")
            if sig or mid is not None:
                ccu = '\n'.join([
                    f"methodId 0x{mid:x}  blob 0x0  units 0 ===" if mid is not None
                    else "methodId ????  blob 0x0  units 0 ===",
                    sig or '',
                    '',
                ])
                b64 = base64.b64encode(ccu.encode('utf-8')).decode('ascii')
                f.write(f"CCu base64:{b64} @ 0x{va:x}\n")
            f.write('\n')
    print(f"[R2] Project written: {r2_path}")


def build_zip(out_dir, zip_path):
    import zipfile as zf
    print(f"[ZIP] Packaging {zip_path} ...")
    with zf.ZipFile(zip_path, 'w', zf.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(out_dir):
            dirs.sort()
            for fname in sorted(files):
                full = os.path.join(root, fname)
                arc  = os.path.relpath(full, out_dir)
                z.write(full, arc)
    size = os.path.getsize(zip_path)
    print(f"[ZIP] Done: {zip_path} ({size/1e6:.1f} MB)")


# ════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════

def main():
    global R2_EXE, BAKSMALI_JAR
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--pkg',     required=True, help='Target package name')
    ap.add_argument('--device',  help='ADB device (IP:PORT or serial; auto-detected if omitted)')
    ap.add_argument('--out',     default=None, help='Output directory (default: ./<pkg>_unpack/)')
    ap.add_argument('--batch',   type=int, default=100, help='r2 batch size (default 100)')
    ap.add_argument('--skip-asm', action='store_true', help='Skip disassembly (only pull + DEX)')
    ap.add_argument('--so',      default=None,
                    help='Pre-captured libdexshellx.so path (skip device extraction; '
                         'needed because on-disk SO is encrypted)')
    ap.add_argument('--dex',     default=None,
                    help='Pre-captured classes.dex path (skip device extraction)')
    ap.add_argument('--r2exe',   default=R2_EXE)
    ap.add_argument('--baksmali',default=BAKSMALI_JAR)
    args = ap.parse_args()
    R2_EXE       = args.r2exe
    BAKSMALI_JAR = args.baksmali

    out_dir  = Path(args.out) if args.out else Path(f"{args.pkg.split('.')[-1]}_unpack")
    zip_path = str(out_dir) + '.zip'
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  DexShell Universal Unpacker")
    print(f"  Target:  {args.pkg}")
    print(f"  Output:  {out_dir}")
    print(f"{'='*60}\n")

    # ── Stage 1: Device ──────────────────────────────────────────────────────
    device = None
    if not (args.so and args.dex):
        device = find_device(args.device)
        if not device:
            sys.exit("[!] No ADB device found. Connect device and try again.")

    # ── Stage 2: zer0.txt files ───────────────────────────────────────────────
    zer0_entries = {}
    if device:
        print(f"\n[1/7] Pulling zer0.txt files ...")
        zer0_entries = pull_zer0_files(args.pkg, device, out_dir)
    else:
        print(f"\n[1/7] Skipping zer0 pull (--so + --dex provided)")

    # ── Stage 3: libdexshellx.so ──────────────────────────────────────────────
    print(f"\n[2/7] Finding libdexshellx.so (VMP engine) ...")
    so_path = None

    # --so override: use pre-captured decrypted SO (on-disk SO is encrypted)
    if args.so:
        src = Path(args.so)
        if src.is_file() and src.stat().st_size > 1_000_000:
            import shutil
            so_path = out_dir / "libdexshellx.so"
            shutil.copy2(str(src), str(so_path))
            print(f"[SO] Using pre-captured SO: {src.name} ({src.stat().st_size:,} bytes)")
        else:
            sys.exit(f"[!] --so file not found or too small: {args.so}")

    if so_path is None:
        # From zer0 entries
        for name, data in zer0_entries.items():
            if data.startswith(ELF_MAGIC) and len(data) > 1_500_000:
                so_path = out_dir / "libdexshellx.so"
                so_path.write_bytes(data)
                print(f"[SO] Found in zer0: {len(data):,} bytes")
                break
        # From device txt/%s (note: encrypted on disk — may fail ELF validation)
        if so_path is None and device:
            so_path = find_libdexshellx(args.pkg, device, out_dir)
    if not so_path:
        sys.exit("[!] libdexshellx.so not found.\n"
                 "    Tip: capture from memory via Frida, then pass with --so <path>")

    # ── Stage 3b: libdexshell.so (loader) ────────────────────────────────────
    for name, data in zer0_entries.items():
        if 'libdexshell.so' in name and data.startswith(ELF_MAGIC):
            p = out_dir / "libdexshell.so"
            p.write_bytes(data)
            print(f"[SO] libdexshell.so saved ({len(data):,} bytes)")

    # ── Stage 3c: classes.dex ────────────────────────────────────────────────
    print(f"\n[3/7] Getting classes.dex ...")
    dex_path = None
    if args.dex:
        import shutil as _sh
        src = Path(args.dex)
        if src.is_file():
            dex_path = out_dir / "classes.dex"
            _sh.copy2(str(src), str(dex_path))
            print(f"[DEX] Using pre-captured DEX: {src.name} ({src.stat().st_size:,} bytes)")
        else:
            print(f"[!] --dex file not found: {args.dex}")
    if dex_path is None and device:
        dex_path = find_classes_dex(args.pkg, device, zer0_entries, out_dir)
    if not dex_path:
        print("[!] classes.dex not available — smali will be empty, ASM unnamed")

    if args.skip_asm:
        print("\n[--skip-asm] Skipping disassembly stages.")
        build_zip(out_dir, zip_path)
        return 0

    # ── Stage 4: baksmali ─────────────────────────────────────────────────────
    smali_dir = out_dir / 'classes_smali'
    if dex_path and Path(BAKSMALI_JAR).is_file():
        print(f"\n[4/7] Running baksmali ...")
        run_baksmali(dex_path, smali_dir)
    else:
        print(f"\n[4/7] Skipping baksmali (dex={dex_path}, jar={Path(BAKSMALI_JAR).is_file()})")

    # ── Stage 5: ELF dispatch table + string scan ─────────────────────────────
    print(f"\n[5/7] Analyzing libdexshellx.so ...")
    if not Path(R2_EXE).is_file():
        sys.exit(f"[!] radare2 not found: {R2_EXE}  (use --r2exe)")
    elf = ELF64(so_path)
    dispatch_vaddrs = find_dispatch_table(so_path, elf=elf)
    if not dispatch_vaddrs:
        sys.exit("[!] Failed to find VMP dispatch table")
    str_map = scan_elf_strings(elf)

    # ── Stage 6: smali correlation ────────────────────────────────────────────
    print(f"\n[6/7] Correlating smali stubs ...")
    stub_map = parse_smali_stubs(smali_dir) if smali_dir.exists() else {}
    aligned  = align_table(dispatch_vaddrs, stub_map)
    funcs    = build_func_map(aligned, stub_map)

    # ── Stage 7: disassemble + write ─────────────────────────────────────────
    print(f"\n[7/7] Disassembling VMP functions ...")
    asm_dir = out_dir / 'asm'
    asm_dir.mkdir(exist_ok=True)
    asm_map = disasm_all(so_path, funcs, batch_size=args.batch)

    written = missing = 0
    for fn in funcs:
        raw = asm_map.get(fn['vaddr'], [])
        if not raw:
            missing += 1
            continue
        annotated = annotate_strings(annotate_jni(raw), str_map)
        write_asm(asm_dir, fn, annotated)
        written += 1

    named = sum(1 for f in funcs if f.get('java_sig'))
    print(f"\n[+] Written: {written} asm files ({named} named, {len(funcs)-named} unnamed)")
    if missing:
        print(f"[!] Missing disassembly: {missing} functions")

    # ── R2 project ────────────────────────────────────────────────────────────
    r2_path = out_dir / 'libdexshellx.r2'
    write_r2_project(str(r2_path), funcs)

    # ── Package ───────────────────────────────────────────────────────────────
    build_zip(out_dir, zip_path)
    print(f"\n{'='*60}")
    print(f"  Output: {zip_path}")
    print(f"  Contents:")
    print(f"    asm/             {written} ARM64 disassembly files (JNI + string annotated)")
    print(f"    libdexshellx.r2  radare2 project ({len(funcs)} functions)")
    if dex_path: print(f"    classes.dex      {os.path.getsize(dex_path):,} bytes")
    print(f"    libdexshellx.so  VMP engine")
    print(f"    libdexshell.so   loader")
    print(f"{'='*60}\n")
    return 0


if __name__ == '__main__':
    sys.exit(main())
