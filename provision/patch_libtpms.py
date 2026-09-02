#!/usr/bin/env python3
"""patch_libtpms.py - replace the TPM identity in every libtpms copy, incl. swtpm's bundled one. --vendor {amd,intel} [--verify-only]."""

import argparse
import glob
import os
import re
import shutil
import subprocess
import sys

_VALID_LIBTPMS = re.compile(r'/lib(?:swtpm_lib)?tpms\.so\.0(?:\.\d+){0,3}$')

IBM_MFR = b"IBM\x00"
IBM_ID = b"id:00001014"
IBM_MFR_LE = bytes((0x00, 0x4D, 0x42, 0x49))

SW_VS1_LE = bytes((0x20, 0x20, 0x57, 0x53))
SW_VS2_LE = bytes((0x4D, 0x50, 0x54, 0x20))
FW_SRC_LE = bytes((0x25, 0x01, 0x24, 0x20))

VENDORS = {
    "amd":   {"mfr": b"AMD\x00", "id": b"id:414D4400", "name": "AMD",
              "mfr_le": bytes((0x00, 0x44, 0x4D, 0x41)),
              "vs1_le": bytes((0x00, 0x44, 0x4D, 0x41)),
              "vs2_le": bytes((0x00, 0x00, 0x00, 0x00)),
              "fw_le":  bytes((0x00, 0x03, 0x06, 0x00))},
    "intel": {"mfr": b"INTC",    "id": b"id:00008086", "name": "Intel",
              "mfr_le": bytes((0x43, 0x54, 0x4E, 0x49)),
              "vs1_le": bytes((0x43, 0x54, 0x4E, 0x49)),
              "vs2_le": bytes((0x00, 0x00, 0x00, 0x00)),
              "fw_le":  bytes((0x6B, 0x00, 0x07, 0x00))},
}

OLD_MODEL = b"swtpm"
NEW_MODEL = b"fTPM "
MODEL_MAX = 8

BACKUP_DIR = "/var/lib/swtpm-patch/libtpms-backups"
LINKER_DIRS = ("/usr/lib", "/usr/lib64", "/usr/lib/swtpm", "/usr/lib64/swtpm")

def find_all_libtpms():
    """Every libtpms-family .so: the system libtpms AND swtpm's bundled copy."""
    pats = [
        "/usr/lib/libtpms.so.0*", "/usr/lib64/libtpms.so.0*",
        "/usr/lib/swtpm/libswtpm_libtpms.so.0*", "/usr/lib64/swtpm/libswtpm_libtpms.so.0*",
        "/usr/lib/*/libtpms.so.0*",
    ]
    seen, libs = set(), []
    for p in pats:
        for m in sorted(glob.glob(p)):
            rp = os.path.realpath(m)
            if not _VALID_LIBTPMS.search(rp):
                continue
            if rp in seen or not os.path.isfile(rp):
                continue
            seen.add(rp)
            libs.append(rp)
    return libs

def patch_one(lib_path, vendor, verify_only):
    """Returns one of: already | needs | patched | n/a | noroot."""
    tgt = VENDORS[vendor]
    tgt_mfr, tgt_id, tgt_name = tgt["mfr"], tgt["id"], tgt["name"]
    src_mfrs = [IBM_MFR] + [v["mfr"] for k, v in VENDORS.items() if k != vendor]
    src_ids = [IBM_ID] + [v["id"] for k, v in VENDORS.items() if k != vendor]

    with open(lib_path, "rb") as f:
        data = f.read()
    orig_len = len(data)

    tgt_mfr_le = tgt["mfr_le"]
    src_mfr_les = [IBM_MFR_LE] + [v["mfr_le"] for k, v in VENDORS.items() if k != vendor]

    mfr_now = data.count(tgt_mfr)
    id_now = data.count(tgt_id)
    foreign = sum(data.count(s) for s in src_mfrs)
    le_now = data.count(tgt_mfr_le)
    le_foreign = sum(data.count(s) for s in src_mfr_les)

    sw_vs1 = data.count(SW_VS1_LE)
    sw_vs2 = data.count(SW_VS2_LE)
    fw_src = data.count(FW_SRC_LE)
    fw_patchable = 0 < fw_src <= 4

    if foreign == 0 and mfr_now == 0 and le_foreign == 0 and le_now == 0:
        print(f"  {lib_path}: no TPM manufacturer bytes - skipping")
        return "n/a"

    already = (le_foreign == 0 and le_now >= 1 and foreign == 0
               and sw_vs1 == 0 and sw_vs2 == 0
               and (fw_src == 0 or not fw_patchable))
    print(f"  {lib_path}: target={tgt_name} mfr_str={mfr_now} mfr_u32={le_now} "
          f"id={id_now} vs1={sw_vs1} vs2={sw_vs2} fw={fw_src} "
          f"foreign_str={foreign} foreign_u32={le_foreign} "
          f"-> {'already ' + tgt_name if already else 'needs patch'}")
    if already:
        return "already"
    if verify_only:
        return "needs"
    if os.geteuid() != 0:
        print("    ERROR: must run as root to patch.")
        return "noroot"

    os.makedirs(BACKUP_DIR, exist_ok=True)
    backup = os.path.join(BACKUP_DIR, os.path.basename(lib_path) + ".ORIG")
    if not os.path.exists(backup):
        shutil.copy2(lib_path, backup)
        print(f"    backup: {backup}")

    total = 0
    for src in src_mfrs:
        if len(src) != len(tgt_mfr):
            continue
        n = data.count(src)
        if n:
            data = data.replace(src, tgt_mfr)
            print(f"    mfr string (cosmetic): {n} ({src.decode('latin1').rstrip(chr(0))} -> {tgt_name})")
            total += n
    for src in src_mfr_les:
        n = data.count(src)
        if n:
            data = data.replace(src, tgt_mfr_le)
            print(f"    TPM2_PT_MANUFACTURER uint32: {n} ({src.hex()} -> {tgt_mfr_le.hex()})")
            total += n
    for src, dst, label in ((SW_VS1_LE, tgt["vs1_le"], "TPM_PT_VENDOR_STRING_1"),
                            (SW_VS2_LE, tgt["vs2_le"], "TPM_PT_VENDOR_STRING_2")):
        n = data.count(src)
        if n:
            data = data.replace(src, dst)
            print(f"    {label}: {n} ({src.hex()} -> {dst.hex()})")
            total += n
    fw_n = data.count(FW_SRC_LE)
    if 0 < fw_n <= 4:
        data = data.replace(FW_SRC_LE, tgt["fw_le"])
        print(f"    TPM_PT_FIRMWARE_VERSION: {fw_n} ({FW_SRC_LE.hex()} -> {tgt['fw_le'].hex()})")
        total += fw_n
    elif fw_n > 4:
        print(f"    firmware-version stamp: {fw_n} occurrences > 4 - left untouched (ambiguous)")
    for src in src_ids:
        n = data.count(src)
        if n:
            data = data.replace(src, tgt_id)
            print(f"    cert mfr id: {n} ({src.decode()} -> {tgt_id.decode()})")
            total += n
    m = data.count(OLD_MODEL)
    if 0 < m <= MODEL_MAX:
        data = data.replace(OLD_MODEL, NEW_MODEL)
        print(f"    model string: {m} (swtpm -> fTPM)")
        total += m
    elif m > MODEL_MAX:
        print(f"    model string: {m} occurrences > {MODEL_MAX} - left untouched (bundled lib)")

    if total == 0:
        print("    nothing to patch")
        return "n/a"

    if len(data) != orig_len:
        print(f"    ABORT: patched buffer {len(data)} B != original {orig_len} B "
              f"- refusing to write a resized library (would corrupt {lib_path})")
        return "n/a"
    tmp = lib_path + ".swtpm-tmp"
    try:
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        shutil.copymode(lib_path, tmp)
        os.replace(tmp, lib_path)
    except OSError as e:
        if os.path.exists(tmp):
            try: os.remove(tmp)
            except OSError: pass
        print(f"    ERROR: atomic write failed for {lib_path}: {e}")
        return "noroot"
    print(f"    patched {total} locations (atomic, {orig_len} B preserved)")
    return "patched"

def quarantine_stray_backups():
    """Move any libtpms backup (*.ORIG / *.bak / *.old / ~ / numbered) OUT of every
    linker dir into BACKUP_DIR, so ldconfig can never resolve the SONAME to a stale
    (e.g. IBM) copy. Symlinks and the canonical versioned object are left alone.
    Returns the number of files quarantined."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    moved = 0
    for d in LINKER_DIRS:
        for pat in (os.path.join(d, "libtpms.so.0*"),
                    os.path.join(d, "libswtpm_libtpms.so.0*")):
            for f in sorted(glob.glob(pat)):
                if os.path.islink(f):
                    continue
                if _VALID_LIBTPMS.search(os.path.realpath(f)):
                    continue
                if not os.path.isfile(f):
                    continue
                dst = os.path.join(BACKUP_DIR, os.path.basename(f))
                i = 0
                while os.path.exists(dst):
                    i += 1
                    dst = os.path.join(BACKUP_DIR, f"{os.path.basename(f)}.{i}")
                try:
                    shutil.move(f, dst)
                    print(f"  quarantined stray libtpms backup: {f} -> {dst}")
                    moved += 1
                except OSError as e:
                    print(f"  WARN: could not quarantine {f}: {e}")
    return moved

def reassert_soname_and_cache():
    """Force /usr/lib*/libtpms.so.0 to point at the real versioned object, then
    rebuild ld.so.cache - defeating any prior ldconfig run that linked the SONAME to
    a backup. Without this, swtpm keeps loading whatever the stale symlink resolved
    to (the root cause of 'patched but still IBM')."""
    for d in ("/usr/lib", "/usr/lib64"):
        objs = [o for o in sorted(glob.glob(os.path.join(d, "libtpms.so.0.*")))
                if not os.path.islink(o) and _VALID_LIBTPMS.search(os.path.realpath(o))]
        if not objs:
            continue
        target = os.path.basename(objs[-1])
        link = os.path.join(d, "libtpms.so.0")
        try:
            if os.path.islink(link) or os.path.exists(link):
                os.remove(link)
            os.symlink(target, link)
            print(f"  SONAME re-asserted: {link} -> {target}")
        except OSError as e:
            print(f"  WARN: could not set {link}: {e}")
    try:
        subprocess.run(["ldconfig"], check=False)
        print("  ldconfig: ld.so.cache rebuilt")
    except OSError as e:
        print(f"  WARN: ldconfig failed: {e}")

def soname_is_target(vendor):
    """True iff /usr/lib*/libtpms.so.0 RESOLVES to an object whose uint32
    manufacturer is the target vendor (and carries no IBM/foreign manufacturer).
    Read-only - lets --verify-only catch an ldconfig-hijacked symlink that points at
    an unpatched backup even when every canonical file is already patched."""
    tgt_le = VENDORS[vendor]["mfr_le"]
    src_les = [IBM_MFR_LE] + [v["mfr_le"] for k, v in VENDORS.items() if k != vendor]
    seen = False
    for d in ("/usr/lib", "/usr/lib64"):
        link = os.path.join(d, "libtpms.so.0")
        if not os.path.exists(link):
            continue
        seen = True
        try:
            data = open(os.path.realpath(link), "rb").read()
        except OSError:
            return False
        swtpm_leak = data.count(SW_VS1_LE) + data.count(SW_VS2_LE)
        if (data.count(tgt_le) < 1 or sum(data.count(s) for s in src_les) > 0
                or swtpm_leak > 0):
            print(f"  SONAME {link} -> {os.path.realpath(link)}: "
                  f"NOT clean {VENDORS[vendor]['name']} "
                  f"(manufacturer/vendor-string still swtpm)")
            return False
    return seen

def swtpm_healthy():
    """Live probe: can swtpm initialize a TPM2? Returns True/False. A truncated or
    corrupt libtpms makes swtpm die with SIGBUS, and libvirt then reports 'TPM
    version 2.0 is not supported' at domain-define time. This is the definitive,
    cheap runtime check (no socket left behind - --help just loads the lib)."""
    swtpm = shutil.which("swtpm")
    if not swtpm:
        return True
    try:
        r = subprocess.run([swtpm, "socket", "--tpm2", "--help"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=20)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False

def rollback(paths):
    """Restore the given libs from their .ORIG backups (self-heal when the post-patch
    swtpm probe fails - never leave the host with a TPM swtpm can't load)."""
    n = 0
    for p in paths:
        b = os.path.join(BACKUP_DIR, os.path.basename(p) + ".ORIG")
        if os.path.isfile(b):
            try:
                shutil.copy2(b, p)
                n += 1
                print(f"     restored {p} <- {b}")
            except OSError as e:
                print(f"     WARN: could not restore {p}: {e}")
    return n

def main():
    parser = argparse.ArgumentParser(description="Patch libtpms manufacturer identity")
    parser.add_argument("--vendor", choices=sorted(VENDORS), default="amd",
                        help="Target TPM manufacturer identity (default: amd)")
    parser.add_argument("--verify-only", action="store_true",
                        help="Exit 0 only if ALL libtpms-family libs are already the target")
    args = parser.parse_args()

    if not args.verify_only and os.geteuid() == 0:
        n = quarantine_stray_backups()
        if n:
            print(f"[*] quarantined {n} stray libtpms backup(s) -> {BACKUP_DIR}")

    libs = find_all_libtpms()
    if not libs:
        print("ERROR: no libtpms found (/usr/lib*/libtpms.so.0* or swtpm bundled)")
        sys.exit(1)

    results, patched_paths = [], []
    for p in libs:
        r = patch_one(p, args.vendor, args.verify_only)
        results.append(r)
        if r == "patched":
            patched_paths.append(p)

    if args.verify_only:
        ok = all(r in ("already", "n/a") for r in results) and soname_is_target(args.vendor)
        sys.exit(0 if ok else 1)
    if "noroot" in results:
        sys.exit(1)
    if os.geteuid() == 0:
        reassert_soname_and_cache()
        if not swtpm_healthy():
            print("  !! swtpm self-test FAILED (libtpms won't load) - self-healing")
            n = rollback(patched_paths)
            reassert_soname_and_cache()
            if swtpm_healthy():
                print(f"  recovered: rolled back {n} patched lib(s); swtpm works now "
                      f"(UNSPOOFED - guest TPM reports IBM until re-patched cleanly).")
                sys.exit(2)
            print("  !! swtpm STILL broken after rollback - libtpms itself is corrupt.")
            print("     FIX: sudo pacman -S --noconfirm libtpms && sudo ldconfig")
            sys.exit(3)
        print("  swtpm self-test OK - TPM2 initializes.")
    print("Done. Fully power-cycle the VM (virsh shutdown + start) so swtpm reloads the lib.")
    sys.exit(0)

if __name__ == "__main__":
    main()
