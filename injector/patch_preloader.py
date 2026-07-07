#!/usr/bin/env python3
"""
Combined MT6789 preloader patcher -- applies GZ-skip and/or USB-DL-always-on.

Flags (opt-in each):
  --gz         Skip GenieZone initialisation (BEQ -> B in gz_release_all)
  --usb-dl     Force USB Download Mode always-on (CBZ -> NOP in usb_dl_init)

Both patches touch disjoint offsets and can be applied independently.
Order: GZ first, then USB DL (pipeline chaining inside a single pass).
"""

import argparse
import os
import struct
import sys

from patch_preloader_gz import (
    CONTENT_OFFSET as GZ_CONTENT_OFFSET,
    PATCH_OFFSET as GZ_PATCH_OFFSET,
    verify_preloader as gz_verify,
    patch_preloader as gz_patch_data,
    verify_patch as gz_verify_patch,
)
from patch_preloader_usb_dl import (
    CONTENT_OFFSET as USB_CONTENT_OFFSET,
    PATCH_OFFSET as USB_PATCH_OFFSET,
    OLD_BYTES as USB_OLD_BYTES,
    NEW_BYTES as USB_NEW_BYTES,
)


GZ_PATCH_SITE = GZ_CONTENT_OFFSET + GZ_PATCH_OFFSET
USB_PATCH_SITE = USB_CONTENT_OFFSET + USB_PATCH_OFFSET


def apply_usb_dl(data: bytearray, dry_run: bool = False) -> bool:
    chunk = bytes(data[USB_PATCH_SITE:USB_PATCH_SITE + 2])
    if chunk == USB_NEW_BYTES:
        print("  [SKIP] Already patched (NOP already present)")
        return False
    if chunk != USB_OLD_BYTES:
        print(f"  [FAIL] Unexpected bytes at 0x{USB_PATCH_SITE:X}: "
              f"{chunk.hex()} (expected {USB_OLD_BYTES.hex()})")
        sys.exit(1)
    data[USB_PATCH_SITE:USB_PATCH_SITE + 2] = USB_NEW_BYTES
    return True


def main():
    ap = argparse.ArgumentParser(
        description='Apply preloader patches (GZ skip + USB DL always-on)')
    ap.add_argument('input', help='Input preloader binary')
    ap.add_argument('output', nargs='?', default=None,
                    help='Output path (default: <input> with _patched suffix)')
    ap.add_argument('--gz', action='store_true',
                    help='Skip GenieZone initialisation')
    ap.add_argument('--usb-dl', action='store_true',
                    help='Force USB Download Mode always-on')
    ap.add_argument('--dry-run', '-n', action='store_true',
                    help='Simulate; write nothing')
    args = ap.parse_args()

    if not args.gz and not args.usb_dl:
        sys.exit("ERROR: at least one of --gz or --usb-dl is required")

    inpath = args.input
    if args.output:
        outpath = args.output
    else:
        base, ext = os.path.splitext(inpath)
        outpath = base + '_patched' + ext

    if not os.path.exists(inpath):
        sys.exit(f"ERROR: input not found: {inpath}")

    with open(inpath, 'rb') as f:
        data = bytearray(f.read())

    modified = False

    if args.gz:
        print("--- preloader: GZ skip ---")
        if not gz_verify(bytes(data)):
            print("  WARNING: preloader layout unexpected; continuing anyway")
        if not gz_patch_data(data):
            print("  [SKIP] GZ patch site already modified or unexpected bytes")
        else:
            modified = True
            if not gz_verify_patch(bytes(data)):
                sys.exit("  ERROR: GZ patch verification failed")
            print("  [OK] GZ skip applied")

    if args.usb_dl:
        print("--- preloader: USB DL always-on ---")
        if apply_usb_dl(data):
            modified = True
            print("  [OK] USB DL always-on applied")

    if not modified:
        print("No patches were applied (all opted-in patches already present or skipped).")
        if args.dry_run:
            print("(dry-run, no bytes written)")
        else:
            with open(outpath, 'wb') as f:
                f.write(data)
        return

    if args.dry_run:
        print(f"\n[DRY RUN] Would write patched preloader to {outpath}")
    else:
        with open(outpath, 'wb') as f:
            f.write(data)

    applied = [f for f in (args.gz and 'gz', args.usb_dl and 'usb_dl') if f]
    print(f"\nOutput: {outpath}")
    print(f"Patches applied: {', '.join(applied)}")


if __name__ == '__main__':
    main()
