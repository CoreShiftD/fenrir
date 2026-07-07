#!/usr/bin/env python3
"""
Force USB Download Mode Always-On for A75 (MT6789) preloader.

Patches the key-state conditional branch in usb_dl_init() so that
the preloader always takes the "download key pressed" code path,
making USB DL mode enter regardless of the physical volume key.

Change at content offset 0x3EDE8 (VA 0x00140DE8):
    CBZ   R0, #0x140dfc   (0xB140, 2-byte Thumb)
    -> NOP                 (0xBF00, 2-byte Thumb)

The patched preloader does not wait for a key press; it initialises
the USB download path on every cold boot that reaches this function.
"""

import argparse
import os
import struct
import sys

CONTENT_OFFSET = 0xF0  # GFH header size
PATCH_OFFSET = 0x3EDE8  # content-relative offset of CBZ instruction
OLD_BYTES = b'\x40\xB1'  # CBZ R0, <target>  (little-endian halfword 0xB140)
NEW_BYTES = b'\x00\xBF'  # NOP (Thumb hint)  (little-endian halfword 0xBF00)


def patch_preloader(input_path: str, output_path: str, dry_run: bool = False) -> None:
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())

    file_offset = CONTENT_OFFSET + PATCH_OFFSET
    chunk = bytes(data[file_offset:file_offset + 2])

    if chunk == OLD_BYTES:
        print(f"[OK] Found CBZ at file offset 0x{file_offset:X}")
    elif chunk == NEW_BYTES:
        print("[SKIP] Already patched (NOP already present)")
        if not dry_run:
            with open(output_path, 'wb') as f:
                f.write(data)
        else:
            print("  (dry-run, no bytes written)")
        return
    else:
        print(f"[FAIL] Unexpected bytes at 0x{file_offset:X}: {chunk.hex()} "
              f"(expected {OLD_BYTES.hex()})")
        sys.exit(1)

    data[file_offset:file_offset + 2] = NEW_BYTES

    if dry_run:
        print("[DRY RUN] Patch would be applied (no bytes written)")
    else:
        with open(output_path, 'wb') as f:
            f.write(data)

    print(f"[OK] Patched -> NOP (always-on USB DL mode)")
    print(f"     Input:  {input_path}")
    print(f"     Output: {output_path}")
    print()
    print("NOTE: This invalidates the trailing RSA signature.")
    print("      Only use on unfused devices (SBC/SLA/DAA off).")


def main():
    ap = argparse.ArgumentParser(
        description='Force USB Download Mode always-on in MT6789 preloader')
    ap.add_argument('input', help='Input preloader binary')
    ap.add_argument('output', nargs='?', default=None,
                    help='Output path (default: <input> with _usbdl suffix)')
    ap.add_argument('--dry-run', '-n', action='store_true',
                    help='Simulate; write nothing')
    args = ap.parse_args()

    inpath = args.input
    if args.output:
        outpath = args.output
    else:
        base, ext = os.path.splitext(inpath)
        outpath = base + '_usbdl' + ext

    if not os.path.exists(inpath):
        sys.exit(f"ERROR: input not found: {inpath}")

    patch_preloader(inpath, outpath, dry_run=args.dry_run)


if __name__ == '__main__':
    main()
