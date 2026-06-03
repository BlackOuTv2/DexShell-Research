#!/usr/bin/env python3
import io, os, struct, subprocess, sys, zipfile
from pathlib import Path

ASSET_KEY = bytes([0x10, 0x6B, 0x07, 0x24, 0x5F, 0xA1, 0x33, 0xCD])
DSLB_MAGIC = b"DSLB"
ZIP_MAGIC  = b"PK\x03\x04"
ELF_MAGIC  = b"\x7fELF"
DEX_MAGIC  = b"dex\n"

PKG = "com.x.dexprotectx"
OUTDIR = "unpacked"

def xor(data: bytes, key: bytes = ASSET_KEY) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def adb(args: list[str]) -> bytes:
    return subprocess.check_output(["adb", *args])


def adb_pull_via_su(remote: str, local: Path) -> None:
    local.parent.mkdir(parents=True, exist_ok=True)
    data = adb(["exec-out", "su", "-c", f"cat {remote}"])
    local.write_bytes(data)


def find_remote_zer0(pkg: str) -> list[str]:
    out = adb(["shell", "su", "-c",
               f"find /data/data/{pkg} -name 'zer0.txt' -size +1k 2>/dev/null"])
    return [line.strip() for line in out.decode().splitlines() if line.strip()]


def classify(blob: bytes) -> str:
    if blob.startswith(DSLB_MAGIC):
        return "dslb_plain"
    dec = xor(blob[:8])
    if dec.startswith(DSLB_MAGIC):
        return "dslb_xor"
    if dec.startswith(ZIP_MAGIC):
        return "zip_xor"
    return "unknown"


def parse_dslb(buf: bytes) -> list[tuple[str, bytes]]:
    assert buf[:4] == DSLB_MAGIC, "not a DSLB blob"
    version = buf[4]
    if version != 1:
        print(f"  warning: DSLB version {version}, expected 1", file=sys.stderr)
    count = struct.unpack_from("<H", buf, 5)[0]
    off = 7
    entries = []
    for i in range(count):
        name_len = struct.unpack_from("<H", buf, off)[0]; off += 2
        name = buf[off:off + name_len].decode("utf-8"); off += name_len
        data_len = struct.unpack_from("<I", buf, off)[0]; off += 4
        entries.append((name, buf[off:off + data_len]))
        off += data_len
    return entries


def magic_label(data: bytes) -> str:
    if data.startswith(ELF_MAGIC): return "ELF"
    if data.startswith(DEX_MAGIC): return "DEX"
    if data.startswith(ZIP_MAGIC): return "ZIP"
    return "?"


def handle_blob(blob: bytes, label: str, outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    raw_path = outdir / f"{label}.raw"
    raw_path.write_bytes(blob)
    print(f"[{label}] {len(blob)} bytes -> {raw_path}")

    kind = classify(blob)
    print(f"  format: {kind}")

    if kind == "dslb_plain":
        dslb = blob
    elif kind == "dslb_xor":
        dslb = xor(blob)
        (outdir / f"{label}.dslb").write_bytes(dslb)
    elif kind == "zip_xor":
        zip_bytes = xor(blob)
        zip_path = outdir / f"{label}.zip"
        zip_path.write_bytes(zip_bytes)
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
            for info in z.infolist():
                content = z.read(info.filename)
                dst = outdir / info.filename
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(content)
                print(f"  extracted {info.filename} ({len(content)} bytes, {magic_label(content)})")
        return
    else:
        print(f"  unrecognised; first 16 bytes: {blob[:16].hex()}")
        return

    entries = parse_dslb(dslb)
    print(f"  DSLB version=1, entries={len(entries)}")
    for name, raw in entries:
        plain = xor(raw)
        dst = outdir / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(plain)
        print(f"  [{magic_label(plain)}] {name}  raw={len(raw)}  plain={len(plain)}")


def main() -> int:
    sources: list[tuple[str, bytes]] = []
    
    remote_paths = find_remote_zer0(PKG)
    if not remote_paths:
        print(f"no zer0.txt > 1k found under /data/data/{PKG}", file=sys.stderr)
    for i, rpath in enumerate(remote_paths, 1):
        print(f"pulling {rpath}")
        local = Path(os.path.join(OUTDIR, "pulled", f"zer0_{i}.txt"))
        adb_pull_via_su(rpath, local)
        sources.append((f"zer0_{i}", local.read_bytes()))

    if not sources:
        return 1

    for label, blob in sources:
        handle_blob(blob, label, Path(os.path.join(OUTDIR, label)))
        print()

    print(f"done — output in {OUTDIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
