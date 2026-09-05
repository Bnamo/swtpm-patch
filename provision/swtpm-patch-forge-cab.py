#!/usr/bin/env python3
"""swtpm-patch-forge-cab.py - rebuild TrustedTpm.cab with the issuer CA injected."""
import os, struct, sys, subprocess, tempfile, shutil

CHUNK = 32000

def build_stored_cab(files, out):
    # CFFILE = cbFile(4) uoff(4) iFolder(2) date(2) time(2) attribs(2) name\0
    def cfdata_blocks(data):
        return [data[i:i+CHUNK] for i in range(0, len(data), CHUNK)]

    n = len(files)
    off = 36 + 8                       # header + one folder entry
    for name, data in files:
        off += 4 + 4 + 2 + 6 + len(name.encode()) + 1
    data_off = off
    for _, data in files:
        for c in cfdata_blocks(data):
            off += 8 + len(c)
    total = off

    total_blocks = sum(len(cfdata_blocks(d)) for _, d in files)
    with open(out, 'wb') as f:
        f.write(b'MSCF')
        f.write(struct.pack('<IIII', 0, total, 0, 44))   # r1, cbCabinet, r2, coffFiles
        f.write(struct.pack('<I', 0))                    # r3
        f.write(struct.pack('<BB', 1, 3))                # ver
        f.write(struct.pack('<HHH', 1, n, 0))            # cFolders, cFiles, flags
        f.write(struct.pack('<HH', 0x4d53, 0))           # setID, iCabinet
        f.write(struct.pack('<IHH', data_off, total_blocks, 0))  # CFFOLDER: coff, cCFData, type=stored
        uoff = 0
        for name, data in files:
            f.write(struct.pack('<IIH', len(data), uoff, 0))
            uoff += len(data)
            f.write(struct.pack('<HHH', 0, 0, 0x20))     # date, time, attribs
            f.write(name.encode() + b'\x00')
        for _, data in files:
            for c in cfdata_blocks(data):
                f.write(struct.pack('<IHH', 0, len(c), len(c)))
                f.write(c)
    return total

def main():
    orig, extra, out = sys.argv[1], sys.argv[2], sys.argv[3]
    # argv kept positional for direct use; see tpm-provision.sh
    tmp = tempfile.mkdtemp()
    subprocess.run(['cabextract', '-q', '-d', f'{tmp}/x', orig], check=True)
    files = []
    for root, _, names in os.walk(f'{tmp}/x'):
        for nm in sorted(names):
            p = os.path.join(root, nm)
            rel = os.path.relpath(p, f'{tmp}/x').replace('/', '\\')
            files.append((rel, open(p, 'rb').read()))
    files.append(('AMD\\RootCA\\AMD-fTPM-CA.cer', open(extra, 'rb').read()))
    total = build_stored_cab(files, out)
    print(f'repacked {len(files)} files, {total} bytes -> {out}')
    shutil.rmtree(tmp)

if __name__ == '__main__':
    main()
