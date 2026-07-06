#!/usr/bin/env python3
"""
Patch MT6789 preloader to skip GenieZone (GZ) initialization.

Single-byte patch: changes BEQ -> B at 0x023982 in the preloader content,
making `gz_release_all` unconditionally skip the GZ release loop (and its
panic call) before any GZ code is reached.

Stock A75 (MT6789) preloader offsets:
  gz_release_all function:   content offset 0x23970
  BEQ->B patch site:         content offset 0x23982  (byte 0x23983: D0->E0)
  Binary layout:             GFH(240 B) + content + RSA sig(1644 B)

Usage:
    python3 patch_preloader_gz.py <input.bin> [output.bin]
"""

import struct
import sys
import os
import hashlib
from capstone import *

# ── Constants for MT6789 / A75 ────────────────────────────────────────
CONTENT_OFFSET = 240            # GFH header size
PATCH_OFFSET = 0x023982         # content offset of BEQ instruction
SIG_SIZE = 1644                 # trailing RSA signature

JUMP_TARGET = 0x23a12           # what the branch should target


def verify_preloader(data: bytes) -> bool:
    """Check if data looks like a valid MT6789 preloader."""
    if len(data) < CONTENT_OFFSET + 0x30000:
        return False
    # Check for expected instruction at the patch site
    hw = struct.unpack_from('<H', data, CONTENT_OFFSET + PATCH_OFFSET)[0]
    return hw == 0xD046  # BEQ 0x23a12


def patch_preloader(data: bytearray) -> bool:
    """Apply the GZ-skip patch. Returns True if changed."""
    off = CONTENT_OFFSET + PATCH_OFFSET + 1  # high byte of instruction
    if data[off] != 0xD0:
        return False  # already patched or wrong binary
    data[off] = 0xE0  # D0 -> E0: BEQ -> B
    return True


def verify_patch(data: bytes) -> bool:
    """Confirm patch was applied correctly."""
    hw = struct.unpack_from('<H', data, CONTENT_OFFSET + PATCH_OFFSET)[0]
    return hw == 0xE046  # B 0x23a12


def main():
    import argparse
    ap = argparse.ArgumentParser(description='Patch MT6789 preloader to skip GZ init')
    ap.add_argument('so', help='Path to full preloader binary (e.g. preloader_k6789v1_64.bin)')
    ap.add_argument('out', nargs='?', help='Output path (default: <so>.patched)')
    ap.add_argument('--dry-run', '-n', action='store_true', help='Simulate; write nothing')
    args = ap.parse_args()

    in_path = args.so
    out_path = args.out if args.out else in_path + '.patched'

    if not os.path.exists(in_path):
        sys.exit(f"ERROR: input not found: {in_path}")

    with open(in_path, 'rb') as f:
        data = bytearray(f.read())

    size_mb = len(data) / 1024 / 1024
    md5_before = hashlib.md5(data).hexdigest()

    if not verify_preloader(bytes(data)):
        print(f"WARNING: input ({len(data)} B, {size_mb:.1f} MiB, MD5={md5_before})")
        print("  Does not match expected MT6789 preloader layout.")
        print("  Continuing anyway — patch will be validated.")

    if not patch_preloader(data):
        print(f"Patch site at content offset 0x{PATCH_OFFSET:x} is already modified")
        print(f"  or doesn't contain the expected BEQ (0xD046).")
        print(f"  Current value: 0x{struct.unpack_from('<H', bytes(data), CONTENT_OFFSET + PATCH_OFFSET)[0]:04x}")
        sys.exit(1)

    if not verify_patch(bytes(data)):
        sys.exit("ERROR: patch verification failed — output would be corrupt. Aborting.")

    md5_after = hashlib.md5(data).hexdigest()

    if args.dry_run:
        print(f"\n[DRY RUN] Would write patched preloader to {out_path}")
    else:
        with open(out_path, 'wb') as f:
            f.write(data)

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    patch_va = PATCH_OFFSET
    insns = list(md.disasm(bytes(data[CONTENT_OFFSET + PATCH_OFFSET:CONTENT_OFFSET + PATCH_OFFSET + 4]), patch_va))

    print(f"{'[DRY RUN] ' if args.dry_run else ''}Patched {os.path.basename(in_path)} -> {os.path.basename(out_path)}")
    print(f"  Size:   {len(data)} B ({size_mb:.1f} MiB)")
    print(f"  MD5:    {md5_before} -> {md5_after}")
    print(f"  Patch:  content offset 0x{PATCH_OFFSET:x}, byte 0x{PATCH_OFFSET+1:x}: D0 -> E0")
    if insns:
        print(f"  Before: BEQ #0x{JUMP_TARGET:x}")
        print(f"  After:  {insns[0].mnemonic} {insns[0].op_str}")
    print(f"  Effect: gz_release_all unconditionally skips GZ init (no panic)")


if __name__ == '__main__':
    main()
