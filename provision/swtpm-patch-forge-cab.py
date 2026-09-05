#!/usr/bin/env python3
"""swtpm-patch-forge-cab.py - rebuild TrustedTpm.cab with the issuer CA injected (MSZIP)."""
import struct, zlib, os, sys, subprocess, tempfile, shutil

CHUNK = 32768

def compress_block(data):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return b"CK" + c.compress(data) + c.flush()

def build_mszip_cab(files, out):
    n = len(files)
    off = 36 + 8
    for name, data in files:
        off += 4 + 4 + 2 + 6 + len(name.encode()) + 1
    data_off = off

    all_blocks = []
    uoff = 0
    file_meta = []
    for name, data in files:
        file_meta.append((len(data), uoff, name))
        uoff += len(data)
        for i in range(0, len(data), CHUNK):
            c = data[i:i+CHUNK]
            all_blocks.append((compress_block(c), len(c)))

    for b, u in all_blocks:
        off += 8 + len(b)
    total = off

    with open(out, "wb") as f:
        f.write(b"MSCF")
        f.write(struct.pack("<IIII", 0, total, 0, 44))
        f.write(struct.pack("<I", 0))
        f.write(struct.pack("<BB", 3, 1))
        f.write(struct.pack("<HHH", 1, n, 0))
        f.write(struct.pack("<HH", 0x4d53, 0))
        f.write(struct.pack("<IHH", data_off, len(all_blocks), 0x0001))
        for size, u, name in file_meta:
            f.write(struct.pack("<IIH", size, u, 0))
            f.write(struct.pack("<HHH", 0, 0, 0x20))
            f.write(name.encode() + b"\x00")
        for b, u in all_blocks:
            f.write(struct.pack("<IHH", 0, len(b), u))
            f.write(b)
    return total

def to_der(data):
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        return x509.load_pem_x509_certificate(data).public_bytes(Encoding.DER)
    except Exception:
        return data

def main():
    orig, extra, out = sys.argv[1], sys.argv[2], sys.argv[3]
    tmp = tempfile.mkdtemp()
    subprocess.run(["cabextract", "-q", "-d", f"{tmp}/x", orig], check=True)
    files = []
    for root, _, names in os.walk(f"{tmp}/x"):
        for nm in sorted(names):
            p = os.path.join(root, nm)
            rel = os.path.relpath(p, f"{tmp}/x").replace("/", "\\")
            files.append((rel, open(p, "rb").read()))
    files.append(("AMD\\RootCA\\AMD-fTPM-CA.cer", to_der(open(extra, "rb").read())))
    total = build_mszip_cab(files, out)
    print(f"mszip cab: {len(files)} files, {total} bytes")
    shutil.rmtree(tmp)

if __name__ == "__main__":
    main()
