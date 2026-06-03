#!/usr/bin/env python3
"""
gen_asm_from_r2.py — Regenerate asm/ from libdexshellx.r2 + libdexshellx.so

Works on existing files in dexshellx_unpack/ — no device or runtime capture needed.

Pipeline:
  1. Parse .r2 -> extract (vaddr, size, Java signature, methodId, pseudo-smali) per function
  2. Batch-disassemble all functions via a single r2 invocation
  3. Post-process: add JNI vtable annotations
  4. Write asm/<pkg>/<Class>/<method>__<hexId>.asm

Usage:
  python gen_asm_from_r2.py
  python gen_asm_from_r2.py --so dexshellx_unpack/libdexshellx.so \
                             --r2 dexshellx_unpack/libdexshellx.r2 \
                             --out dexshellx_unpack/asm_rebuilt/
"""

import sys, os, re, base64, subprocess, argparse, tempfile, shutil

# ── radare2 path ─────────────────────────────────────────────────────────────
R2_EXE = r"C:\radare2\bin\radare2.exe"

# ── JNIEnv vtable (ARM64, 8 bytes / entry, offset = index * 8) ───────────────
JNI_ENV = {
    0x20: "GetVersion",         0x28: "DefineClass",
    0x30: "FindClass",          0x38: "FromReflectedMethod",
    0x40: "FromReflectedField", 0x48: "ToReflectedMethod",
    0x50: "GetSuperclass",      0x58: "IsAssignableFrom",
    0x60: "ToReflectedField",   0x68: "Throw",
    0x70: "ThrowNew",           0x78: "ExceptionOccurred",
    0x80: "ExceptionDescribe",  0x88: "ExceptionClear",
    0x90: "FatalError",         0x98: "PushLocalFrame",
    0xa0: "PopLocalFrame",      0xa8: "NewGlobalRef",
    0xb0: "DeleteGlobalRef",    0xb8: "DeleteLocalRef",
    0xc0: "IsSameObject",       0xc8: "NewLocalRef",
    0xd0: "EnsureLocalCapacity",0xd8: "AllocObject",
    0xe0: "NewObject",          0xe8: "NewObjectV",
    0xf0: "NewObjectA",         0xf8: "GetObjectClass",
    0x100:"IsInstanceOf",       0x108:"GetMethodID",
    0x110:"CallObjectMethod",   0x118:"CallObjectMethodV",
    0x120:"CallObjectMethodA",  0x128:"CallBooleanMethod",
    0x130:"CallBooleanMethodV", 0x138:"CallBooleanMethodA",
    0x140:"CallByteMethod",     0x148:"CallByteMethodV",
    0x150:"CallByteMethodA",    0x158:"CallCharMethod",
    0x160:"CallCharMethodV",    0x168:"CallCharMethodA",
    0x170:"CallShortMethod",    0x178:"CallShortMethodV",
    0x180:"CallShortMethodA",   0x188:"CallIntMethod",
    0x190:"CallIntMethodV",     0x198:"CallIntMethodA",
    0x1a0:"CallLongMethod",     0x1a8:"CallLongMethodV",
    0x1b0:"CallLongMethodA",    0x1b8:"CallFloatMethod",
    0x1c0:"CallFloatMethodV",   0x1c8:"CallFloatMethodA",
    0x1d0:"CallDoubleMethod",   0x1d8:"CallDoubleMethodV",
    0x1e0:"CallDoubleMethodA",  0x1e8:"CallVoidMethod",
    0x1f0:"CallVoidMethodV",    0x1f8:"CallVoidMethodA",
    0x200:"CallNonvirtualObjectMethod",  0x208:"CallNonvirtualObjectMethodV",
    0x210:"CallNonvirtualObjectMethodA", 0x218:"CallNonvirtualBooleanMethod",
    0x2d8:"CallNonvirtualVoidMethod",    0x2e0:"CallNonvirtualVoidMethodV",
    0x2e8:"CallNonvirtualVoidMethodA",
    0x2f0:"GetFieldID",         0x2f8:"GetObjectField",
    0x300:"GetBooleanField",    0x308:"GetByteField",
    0x310:"GetCharField",       0x318:"GetShortField",
    0x320:"GetIntField",        0x328:"GetLongField",
    0x330:"GetFloatField",      0x338:"GetDoubleField",
    0x340:"SetObjectField",     0x348:"SetBooleanField",
    0x350:"SetByteField",       0x358:"SetCharField",
    0x360:"SetShortField",      0x368:"SetIntField",
    0x370:"SetLongField",       0x378:"SetFloatField",
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
    0x518:"NewString",          0x520:"GetStringLength",
    0x528:"GetStringChars",     0x530:"ReleaseStringChars",
    0x538:"NewStringUTF",       0x540:"GetStringUTFLength",
    0x548:"GetStringUTFChars",  0x550:"ReleaseStringUTFChars",
    0x558:"GetArrayLength",     0x560:"NewObjectArray",
    0x568:"GetObjectArrayElement",   0x570:"SetObjectArrayElement",
    0x578:"NewBooleanArray",    0x580:"NewByteArray",
    0x588:"NewCharArray",       0x590:"NewShortArray",
    0x598:"NewIntArray",        0x5a0:"NewLongArray",
    0x5a8:"NewFloatArray",      0x5b0:"NewDoubleArray",
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


# ── .r2 parser ────────────────────────────────────────────────────────────────

def parse_r2(r2_path):
    """
    Parse .r2 project file and return a list of function dicts:
      {
        'vaddr': int,
        'end'  : int,
        'size' : int,
        'r2name': str,
        'method_id': int | None,
        'java_sig' : str | None,
        'pseudo_smali': str | None,
        'ccu_addr': int | None,
      }
    """
    print(f"[*] Parsing {r2_path}...")
    funcs   = {}   # vaddr -> dict
    ccus    = []   # [(addr, decoded_text)]

    with open(r2_path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.rstrip()

            # afu <end> @ <start>
            m = re.match(r'afu (0x[0-9a-f]+) @ (0x[0-9a-f]+)', line)
            if m:
                end   = int(m.group(1), 16)
                start = int(m.group(2), 16)
                size  = end - start
                if size > 0:
                    funcs[start] = {
                        'vaddr': start, 'end': end, 'size': size,
                        'r2name': None, 'method_id': None,
                        'java_sig': None, 'pseudo_smali': None,
                        'ccu_addr': None,
                    }
                continue

            # afn <name> @ <addr>
            m = re.match(r'afn (\S+) @ (0x[0-9a-f]+)', line)
            if m:
                name = m.group(1)
                addr = int(m.group(2), 16)
                if addr in funcs:
                    funcs[addr]['r2name'] = name
                continue

            # CCu base64:<data> @ <addr>
            m = re.match(r'CCu base64:(\S+) @ (0x[0-9a-f]+)', line)
            if m:
                try:
                    text = base64.b64decode(m.group(1)).decode('utf-8', errors='replace')
                except Exception:
                    text = ''
                addr = int(m.group(2), 16)
                ccus.append((addr, text))
                continue

    # Associate each CCu with its enclosing function
    for ccu_addr, ccu_text in ccus:
        for start, fn in funcs.items():
            if start <= ccu_addr < fn['end']:
                fn['ccu_addr'] = ccu_addr
                _parse_ccu(fn, ccu_text)
                break

    result = [fn for fn in funcs.values() if fn['r2name'] and fn['size'] > 0]
    result.sort(key=lambda x: x['vaddr'])
    print(f"[*] Found {len(result)} VMP functions")
    return result


def _parse_ccu(fn, text):
    """
    Parse CCu comment body:
      Line 0: "methodId 0xNN  blob 0xXXX  units N ==="
      Line 1: Java descriptor  "L<pkg>/<Class>;-><method>(...)ret"
      Line 2: blank
      Lines 3+: pseudo-smali
    """
    lines = text.splitlines()
    if not lines:
        return
    # Header line
    m = re.search(r'methodId\s+(0x[0-9a-f]+)', lines[0])
    if m:
        fn['method_id'] = int(m.group(1), 16)
    if len(lines) > 1:
        fn['java_sig'] = lines[1].strip()
    if len(lines) > 3:
        fn['pseudo_smali'] = '\n'.join(lines[3:])


# ── path derivation ───────────────────────────────────────────────────────────

def sig_to_file_path(java_sig, method_id):
    """
    'Lcom/pkg/Class;->method(...)ret'  +  methodId
    -> ('com/pkg/Class', 'method__00xx.asm')
    Returns (dir_path, filename) or None on parse failure.
    """
    if not java_sig:
        return None
    m = re.match(r'L([^;]+);->([^(]+)\(', java_sig)
    if not m:
        return None
    class_path  = m.group(1)                  # e.g. com/dexshell/x/InstrumentationHijacker
    method_name = m.group(2)                  # e.g. isInstalled  or  ᛱ᛽᛽ᲅ
    hex_id      = f'{method_id:04x}' if method_id is not None else '????'
    # Sanitize method name: keep ASCII printable, replace non-ASCII with '_'
    # (matches original unpacker convention: Runic chars -> underscores)
    safe_method = ''.join(
        c if (0x20 <= ord(c) < 0x7f and c not in '/\\:\0') else '_'
        for c in method_name
    )
    filename    = f'{safe_method}__{hex_id}.asm'
    return class_path, filename


# ── r2 disassembly ────────────────────────────────────────────────────────────

SENTINEL = '===FUNC_END_{addr}==='

def disasm_all(so_path, funcs, batch_size=100):
    """
    Disassemble all functions via radare2.
    Returns {vaddr: [asm_line, ...]} dict.
    """
    print(f"[*] Disassembling {len(funcs)} functions via r2 (batches of {batch_size})...")
    results = {}

    # Split into batches to avoid overly large command files
    for batch_start in range(0, len(funcs), batch_size):
        batch = funcs[batch_start:batch_start + batch_size]
        raw   = _run_r2_batch(so_path, batch)
        parsed = _split_r2_output(raw, batch)
        results.update(parsed)
        done = min(batch_start + batch_size, len(funcs))
        print(f"    [{done}/{len(funcs)}] done", end='\r', flush=True)

    print()
    return results


def _run_r2_batch(so_path, funcs):
    with tempfile.NamedTemporaryFile(mode='w', suffix='.r2',
                                     delete=False, encoding='utf-8') as tf:
        tf.write('e asm.arch=arm\n')
        tf.write('e asm.bits=64\n')
        tf.write('e asm.comments=false\n')
        tf.write('e asm.flags=false\n')
        for fn in funcs:
            tf.write(f"pD 0x{fn['size']:x} @ 0x{fn['vaddr']:x}\n")
            tf.write(f"echo ===FUNC_END_{fn['vaddr']:x}===\n")
        script_path = tf.name

    try:
        proc = subprocess.run(
            [R2_EXE, '-q', '-e', 'scr.color=0', '-i', script_path, so_path],
            capture_output=True, text=True, timeout=120,
            encoding='utf-8', errors='replace'
        )
        return proc.stdout
    except subprocess.TimeoutExpired:
        print("[!] r2 batch timed out")
        return ''
    finally:
        os.unlink(script_path)


_ANSI = re.compile(r'\x1b\[[0-9;]*m')

def _strip_ansi(text):
    return _ANSI.sub('', text)

def _split_r2_output(raw, funcs):
    """Split r2 stdout on sentinel markers and return {vaddr: lines}."""
    results = {}
    raw = _strip_ansi(raw)
    # re.split with capturing group produces:
    #   [text_before_sentinel1, vaddr1, text_before_sentinel2, vaddr2, ...]
    # Each function's disasm is the text BEFORE its sentinel (parts[i-1]).
    parts = re.split(r'===FUNC_END_([0-9a-f]+)===', raw)
    i = 1
    while i < len(parts):
        vaddr_str = parts[i]
        asm_text  = parts[i - 1]   # text BEFORE this sentinel
        try:
            vaddr = int(vaddr_str, 16)
            results[vaddr] = [l + '\n' for l in asm_text.splitlines()
                              if l.strip() and not l.startswith('[')]
        except ValueError:
            pass
        i += 2
    return results


# ── JNI annotation ────────────────────────────────────────────────────────────

# JNI vtable pattern: ldr xR, [xR, offset]  (self-referential — same dest & base)
# This is the canonical AArch64 JNI vtable access. Using different regs is not JNI.
_LDR_VTBL = re.compile(
    r'ldr\s+(x\d+),\s+\[(x\d+),\s+#?(0x[0-9a-f]+)\]'
)
_BLR = re.compile(r'\b(blr|br)\s+\w+')


def annotate_jni(asm_lines):
    """Add '; JNIEnv->Method' on ldr+blr lines that match known vtable offsets."""
    out     = []
    pending = None

    for line in asm_lines:
        stripped = line.rstrip()

        m = _LDR_VTBL.search(stripped)
        if m:
            dst, base, off_str = m.group(1), m.group(2), m.group(3)
            if dst == base:   # self-referential -> vtable dereference
                try:
                    offset = int(off_str, 16)
                except ValueError:
                    offset = -1
                if offset in JNI_ENV:
                    method  = JNI_ENV[offset]
                    pending = method
                    stripped = stripped + f'  ; JNIEnv->{method}'
                else:
                    pending = None
            # else: different regs -> not JNI
        elif _BLR.search(stripped) and pending:
            stripped = stripped + f'  ; JNIEnv->{pending}'
            pending  = None
        else:
            pending = None

        out.append(stripped + '\n')
    return out


# ── file writer ───────────────────────────────────────────────────────────────

def write_asm(out_dir, fn, asm_lines):
    """Write one .asm file. Returns the path written or None on error."""
    fp = sig_to_file_path(fn['java_sig'], fn['method_id'])
    if fp is None:
        # Fallback: derive from r2 name
        r2n = fn['r2name'] or f'unknown_{fn["vaddr"]:x}'
        name_part = r2n[3:] if r2n.startswith('vm.') else r2n
        parts = name_part.rsplit('.', 1)
        if len(parts) == 2:
            class_path, method_id_str = parts
            class_path = class_path.replace('.', os.sep)
            m = re.match(r'^(.+)_([0-9a-f]{4})$', method_id_str)
            if m:
                fp = (class_path, f'{m.group(1)}__{m.group(2)}.asm')
            else:
                fp = (class_path, f'{method_id_str}.asm')
        else:
            fp = ('unknown', f'{name_part}.asm')

    class_path, filename = fp
    full_dir  = os.path.join(out_dir, class_path)
    full_path = os.path.join(full_dir, filename)
    os.makedirs(full_dir, exist_ok=True)

    # Build header
    header_lines = []
    if fn['java_sig']:
        header_lines.append(f"// original: {fn['java_sig']}\n")
    mid = fn['method_id']
    header_lines.append(
        f"// methodId: 0x{mid:x}  vaddr: 0x{fn['vaddr']:x}  size: {fn['size']}\n"
        if mid is not None else
        f"// vaddr: 0x{fn['vaddr']:x}  size: {fn['size']}\n"
    )
    if fn['pseudo_smali']:
        header_lines.append('//\n')
        for sl in fn['pseudo_smali'].splitlines():
            header_lines.append(f'//     {sl}\n')
    header_lines.append('\n')

    with open(full_path, 'w', encoding='utf-8') as f:
        f.writelines(header_lines)
        f.writelines(asm_lines)

    return full_path


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    global R2_EXE

    script_dir = os.path.dirname(os.path.abspath(__file__))
    unpack_dir = os.path.join(script_dir, '..', 'dexshellx_unpack')

    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--so',  default=os.path.join(unpack_dir, 'libdexshellx.so'))
    ap.add_argument('--r2',  default=os.path.join(unpack_dir, 'libdexshellx.r2'))
    ap.add_argument('--out', default=os.path.join(unpack_dir, 'asm_rebuilt'))
    ap.add_argument('--batch', type=int, default=100,
                    help='Functions per r2 invocation (default: 100)')
    ap.add_argument('--r2exe', default=R2_EXE)
    args = ap.parse_args()

    R2_EXE = args.r2exe

    for path, label in [(args.so, 'libdexshellx.so'), (args.r2, 'libdexshellx.r2')]:
        if not os.path.isfile(path):
            sys.exit(f"[!] {label} not found: {path}")
    if not os.path.isfile(R2_EXE):
        sys.exit(f"[!] radare2 not found: {R2_EXE}\n    Pass --r2exe <path>")

    os.makedirs(args.out, exist_ok=True)

    # 1. Parse .r2
    funcs = parse_r2(args.r2)

    # 2. Disassemble all
    asm_map = disasm_all(args.so, funcs, batch_size=args.batch)

    # 3. Annotate + write
    written = 0
    missing = 0
    for fn in funcs:
        raw_lines = asm_map.get(fn['vaddr'], [])
        if not raw_lines:
            missing += 1
            continue
        annotated = annotate_jni(raw_lines)
        path = write_asm(args.out, fn, annotated)
        if path:
            written += 1

    print(f"\n[+] Written: {written} asm files  ->  {args.out}")
    if missing:
        print(f"[!] Missing disassembly: {missing} functions (r2 timeout/error)")

    # 4. Summary
    print(f"\nTo compare with original:\n"
          f"  dir \"{args.out}\" /s /b | find /c \".asm\"\n"
          f"  dir \"{os.path.join(unpack_dir, 'asm')}\" /s /b | find /c \".asm\"")


if __name__ == '__main__':
    main()
