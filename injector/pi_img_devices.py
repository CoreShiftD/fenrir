"""
pi_img_devices.py — KRAKEN pi_img.bin calibration-image patcher (MT6789).

Companion to mcupm_devices.py. Where mcupm.img holds the CPU DVFS OPP-limit
tables, pi_img.bin supplies the per-chip aging/SLT/MC50/LUT calibration envelope
that bl2_ext.bin's KRAKEN loader stages into shared SRAM (0x11340C), which
mcupm's EEMSN module reads to validate voltage/frequency pairs at boot. The
"[CPU][EEMSN]...vboot violate" refusal — the gate that rejects CPU OC past a
threshold — is driven from this data. Full analysis: PI_IMG_KRAKEN_NOTES.md.

════════════════════════════════════════════════════════════════════
 TWO PROTECTION GATES  (both handled by this tool)
════════════════════════════════════════════════════════════════════
  1. Outer MTK GFH / cert2 RSA signature (REAL cryptography). Any payload
     edit invalidates it → the device rejects the image. Bypassed by forging
     a cert2 the verifier accepts, via the local cert_bypass helper (OVERRIDE/WRAP).
     This tool ALWAYS re-signs on --write.
  2. Inner KRAKEN cookie 0x17C3A6B4 at payload[0] and payload[-4] (not crypto).
     Must stay byte-identical AND at the same relative offset. Therefore every
     edit here (a) touches only payload[4:-4], (b) keeps the length constant.

liblk strips/rebuilds the outer GFH wrapper, so `partition.data` is exactly the
12068-byte KRAKEN payload (cookie..cookie). We never do manual GFH offset math.

════════════════════════════════════════════════════════════════════
 PAYLOAD LAYOUT  (partition "pi_img", 12068 bytes, plaintext)
════════════════════════════════════════════════════════════════════
  off 0x000            header cookie  b4 a6 c3 17  (0x17C3A6B4)
  off 0x004..0x300     first STRUCTURED register-shadow table (entropy ~3):
      hdr   [u16 count][..][u32 limit @+6]  (parser fcn.00019be4)
      entry array, stride 0xC (12 bytes), tag-value micro-encoding,
      tag bytes 0x77 'w' / 0x78 'x' / 0xb8 / 0xf0, nested sub-blocks.
      Notable decoded content (payload-relative):
        0x50/0x6c/0x88 : 28B per-domain records, id = 1/3/2
        0x1b8/0x1f4/0x238/0x2ac : reg-shadow  0x11c10580 <- 0x00001000
          (0x11c1_xxxx = MTK EEM/PTP-OD CPU-DVFS/aging controller block)
  off 0x300..0x2f20    per-chip aging/SLT/MC50/LUT envelope plus repeated
      structured islands. A75 has aligned 0x11c10580 shadow writes at
      payload value offsets 0x1bc/0x1f8/0x23c/0x2b0, 0xa4c/0xa88/0xacc/0xb40,
      0x12dc/0x1318/0x135c/0x13d0, 0x1ca4/0x1ce0/0x1d24/0x1d98, and
      0x266c/0x26a8/0x26ec/0x2760. These are hardware-encoded raw values,
      not MHz/mV.
  off 0x2f20 (len-4)   footer cookie  0x17C3A6B4

════════════════════════════════════════════════════════════════════
 WHERE THE OC CAP LIVES  (NOT yet byte-pinned — see PI_IMG_KRAKEN_NOTES §6c)
════════════════════════════════════════════════════════════════════
  The exact value the EEMSN "vboot violate" check compares against is not yet
  proven. Confirming it needs disassembly of mcupm's EEMSN validator (the
  consumer). Until a field is identified WITH CONFIDENCE, this tool enables NO
  cap patch by default — matching mcupm_devices.py's "no-op at stock, opt-in,
  never guess firmware bytes" philosophy. It gives you:
    --dump            decode/inspect the register-shadow table + entropy map
    --set  OFF=HEX    raw byte patch inside the cookie-safe range (opt-in)
    --set-reg A=V     rewrite the value of a register-shadow pair (opt-in)
    --write           re-sign (cert_bypass) and save a flashable image
  so you can run controlled OC experiments and diff working/non-working dumps.

Requires the liblk venv:  /opt/src/fenrir/.venv/bin/python3 pi_img_devices.py ...

Usage:
    .venv/bin/python3 pi_img_devices.py pi_img.bin --dump
    .venv/bin/python3 pi_img_devices.py pi_img.bin out.bin --set 0x1bc=00200000 --write
    .venv/bin/python3 pi_img_devices.py pi_img.bin out.bin --set-reg 0x11c10580=0x2000 --write
    .venv/bin/python3 pi_img_devices.py pi_img.bin out.bin --set 0x1bc=00200000 --write --wrap
"""

import sys
import os
import struct
import argparse
from dataclasses import dataclass, field
from typing import List, Tuple, Optional

# liblk comes from requirements.txt; cert_bypass is local to injector/.
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
try:
    from liblk.image import LkImage
    from cert_bypass import apply_cert_bypass
    _HAVE_LIBLK = True
    _IMPORT_ERR = None
except Exception as e:                       # pragma: no cover - env dependent
    _HAVE_LIBLK = False
    _IMPORT_ERR = e


# ─────────────────────────────────────────────────────────────────────────────
# Constants (firmware identity)
# ─────────────────────────────────────────────────────────────────────────────

PART_NAME  = 'pi_img'
COOKIE     = 0x17C3A6B4                       # header & footer sentinel
COOKIE_LE  = struct.pack('<I', COOKIE)        # b4 a6 c3 17
STRUCT_END = 0x300                            # first low-entropy shadow region
SCAN_START = 4                              # skip header cookie


def scan_end(payload: bytes) -> int:
    return len(payload) - 4                 # skip footer cookie


# ─────────────────────────────────────────────────────────────────────────────
# Patch model (mirrors mcupm_devices.py; same-length, cookie-safe)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BytePatch:
    off:  int                 # payload-relative offset (must be inside [4, len-4))
    data: bytes               # replacement bytes (length preserved)
    name: str = ''
    expect: Optional[bytes] = None   # if set, current bytes must match (safety)

    def apply(self, payload: bytearray) -> str:
        end = self.off + len(self.data)
        if self.off < 4 or end > len(payload) - 4:
            raise ValueError(
                f"[{self.name or hex(self.off)}] edit {hex(self.off)}..{hex(end)} "
                f"is outside the cookie-safe range [4, {len(payload) - 4}) — refused")
        cur = bytes(payload[self.off:end])
        if self.expect is not None and cur != self.expect:
            raise RuntimeError(
                f"[{self.name or hex(self.off)}] expected {self.expect.hex()} at "
                f"{hex(self.off)} but found {cur.hex()} — image differs from expected")
        payload[self.off:end] = self.data
        return f"{hex(self.off)}: {cur.hex()} -> {self.data.hex()}"


# ─────────────────────────────────────────────────────────────────────────────
# Load / identity
# ─────────────────────────────────────────────────────────────────────────────

def _require_liblk():
    if not _HAVE_LIBLK:
        sys.exit(
            "ERROR: liblk/lkpatcher not importable — run under the venv:\n"
            "  /opt/src/fenrir/.venv/bin/python3 pi_img_devices.py ...\n"
            f"(import error: {_IMPORT_ERR})")


def load(path: str):
    """Return (img, partition, payload:bytearray). Validates identity."""
    _require_liblk()
    img = LkImage(path)
    if PART_NAME not in img.partitions:
        sys.exit(f"ERROR: '{PART_NAME}' partition not found in {path} "
                 f"(found: {list(img.partitions)})")
    part = img.partitions[PART_NAME]
    payload = bytearray(part.data)
    if payload[:4] != COOKIE_LE or payload[-4:] != COOKIE_LE:
        sys.exit(f"ERROR: KRAKEN cookie missing/mismatched "
                 f"(head={payload[:4].hex()} tail={payload[-4:].hex()}) — not a pi_img payload")
    return img, part, payload


# ─────────────────────────────────────────────────────────────────────────────
# --dump : decode the structured register-shadow region
# ─────────────────────────────────────────────────────────────────────────────

def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    import math
    from collections import Counter
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in Counter(b).values())


def dump(payload: bytearray):
    n = len(payload)
    print(f"payload            : {n} bytes")
    print(f"header/footer cookie: {payload[:4].hex()} / {payload[-4:].hex()} "
          f"({'OK' if payload[:4] == payload[-4:] == COOKIE_LE else 'BAD'})")

    print("\nentropy map (256B blocks):")
    for off in range(0, n, 0x100):
        e = _entropy(payload[off:off + 0x100])
        tag = 'structured' if e < 4.5 else ('transition' if e < 6.0 else 'aging/calib')
        print(f"  0x{off:04x}  {e:4.2f}  {tag}")

    end = scan_end(payload)
    print(f"\nregister-shadow candidates across cookie-safe aligned payload [0x4, {hex(end)}):")
    print("  (filtered to plausible shadow records: prev=0x00480000 or known header regs)")
    for off in range(SCAN_START, end - 8, 4):
        w = struct.unpack_from('<I', payload, off)[0]
        prv = struct.unpack_from('<I', payload, off - 4)[0]
        if prv != 0x00480000 and w not in (0x11c00000, 0x1b880000):
            continue
        if 0x10000000 <= w <= 0x1fffffff:
            nxt = struct.unpack_from('<I', payload, off + 4)[0]
            print(f"  @0x{off:04x}  reg=0x{w:08x}  value@0x{off + 4:04x}=0x{nxt:08x}")


# ─────────────────────────────────────────────────────────────────────────────
# patch spec parsing
# ─────────────────────────────────────────────────────────────────────────────

def parse_num(s: str) -> int:
    """User-friendly integer: hex (0x..), decimal, '_' separators, and k/M/G
    decimal multipliers (8k = 8000). Unit suffixes (mhz/khz/mv/v) are REFUSED —
    the pi_img shadow values are hardware-encoded EEM aging bytes (they land in
    0x11c1xxxx EEM registers, top byte = aging value; see PI_IMG_KRAKEN_NOTES.md
    §6c), NOT a plain MHz/mV number, so no honest unit conversion exists yet."""
    s0 = s.strip().replace('_', '')
    low = s0.lower()
    for u in ('mhz', 'khz', 'mv', 'ghz', 'v'):
        if low.endswith(u):
            raise ValueError(
                f"unit '{u}' not supported: pi_img fields are hardware-encoded EEM "
                f"aging values, not {u.upper()} — cannot convert '{s}' safely yet. "
                f"Use a raw hex/dec value. (Trace EEMSN first; see notes §6c.)")
    mult = 1
    if not low.startswith('0x') and low[-1:] in ('k', 'm', 'g'):
        mult = {'k': 1000, 'm': 1_000_000, 'g': 1_000_000_000}[low[-1]]
        s0 = s0[:-1]
    return int(s0, 0) * mult


def parse_set(spec: str) -> BytePatch:
    """'OFF=HEX' e.g. 0x1bc=00200000  (HEX byte-length preserved, little as-typed)."""
    if '=' not in spec:
        raise ValueError(f"--set expects OFF=HEX, got {spec!r}")
    off_s, hex_s = spec.split('=', 1)
    off = int(off_s, 0)
    hex_s = hex_s.strip().replace(' ', '')
    if len(hex_s) % 2:
        raise ValueError(f"--set {spec}: hex must be whole bytes")
    return BytePatch(off=off, data=bytes.fromhex(hex_s), name=f'set@{off_s}')


def parse_set_reg(spec: str, payload: bytearray) -> List[BytePatch]:
    """'ADDR=VALUE' — rewrite the value word of every register-shadow pair for
    ADDR in the structured region. Convention (observed): value immediately
    follows the address word. Returns one BytePatch per occurrence (they are
    identical shadow writes, so all are patched together)."""
    if '=' not in spec:
        raise ValueError(f"--set-reg expects ADDR=VALUE, got {spec!r}")
    a_s, v_s = spec.split('=', 1)
    addr = int(a_s, 0) & 0xffffffff
    val  = parse_num(v_s) & 0xffffffff
    end = scan_end(payload)
    hits = [off for off in range(SCAN_START, end - 4, 4)
            if struct.unpack_from('<I', payload, off)[0] == addr]
    if not hits:
        raise RuntimeError(
            f"--set-reg 0x{addr:08x}: not found in the cookie-safe aligned payload "
            f"[0x4, {hex(end)}) — inspect with --dump first")
    newv = struct.pack('<I', val)
    return [BytePatch(off=off + 4, data=newv,
                      name=f'reg@0x{addr:08x}#{i}')
            for i, off in enumerate(hits)]


# ─────────────────────────────────────────────────────────────────────────────
# write (re-sign)
# ─────────────────────────────────────────────────────────────────────────────

def write(img, part, payload: bytearray, out_path: str, wrap: bool = False):
    # cookie & length invariants
    if payload[:4] != COOKIE_LE or payload[-4:] != COOKIE_LE:
        sys.exit("ERROR: refusing to write — KRAKEN cookie was disturbed by an edit")
    if len(payload) != len(part.data):
        sys.exit(f"ERROR: refusing to write — payload length changed "
                 f"({len(part.data)} -> {len(payload)}); KRAKEN footer offset must stay fixed")
    part.data = bytes(payload)
    mode = 'WRAP' if wrap else 'OVERRIDE'
    apply_cert_bypass(img, wrap=wrap)
    img.save(out_path)
    print(f"\nre-signed (cert2 {mode}) and wrote: {out_path}")
    print("NOTE: forged cert2 is UNTESTED on-device — see PI_IMG_KRAKEN_NOTES.md §6d.")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='KRAKEN pi_img.bin calibration patcher (edits payload[4:-4] + re-signs)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split('Usage:')[-1])
    ap.add_argument('input', help='Input pi_img.bin')
    ap.add_argument('output', nargs='?', help='Output image (required with --write)')
    ap.add_argument('--dump', action='store_true', help='Decode/inspect payload, then exit')
    ap.add_argument('--set', action='append', default=[], metavar='OFF=HEX',
                    help='Raw byte patch at payload offset (cookie-safe, length-preserving)')
    ap.add_argument('--set-reg', action='append', default=[], metavar='ADDR=VAL',
                    help='Rewrite the value of every register-shadow pair for ADDR. '
                         'VAL accepts hex/dec, _ separators, k/M/G multipliers (8k=8000). '
                         'Unit suffixes (mhz/mv) are refused until the encoding is decoded.')
    ap.add_argument('--write', action='store_true', help='Re-sign (cert_bypass) and save output')
    ap.add_argument('--wrap', action='store_true', help='Use cert2 WRAP mode (default: OVERRIDE)')
    ap.add_argument('--dry-run', '-n', action='store_true', help='Apply patches, print, do not write')
    args = ap.parse_args()

    img, part, payload = load(args.input)
    print(f"Input : {args.input}")
    print(f"Part  : {PART_NAME}  ({len(payload)} bytes, cookie OK)")

    if args.dump:
        print()
        dump(payload)
        return

    patches: List[BytePatch] = []
    try:
        for s in args.set:
            patches.append(parse_set(s))
        for s in args.set_reg:
            patches.extend(parse_set_reg(s, payload))
    except (ValueError, RuntimeError) as e:
        sys.exit(f"ERROR: {e}")

    if not patches:
        print("\nNo --set / --set-reg patches given. Nothing to change.")
        print("Use --dump to inspect, or see the module docstring for usage.")
        return

    print("\nApplying patches (payload[4:-4] only):")
    for p in patches:
        print(f"  {p.name:18s} {p.apply(payload)}")

    if args.write and not args.dry_run:
        if not args.output:
            sys.exit("ERROR: --write requires an output path")
        write(img, part, payload, args.output, wrap=args.wrap)
    else:
        print("\nDry run — not written. Add --write (and an output path) to re-sign & save.")


if __name__ == '__main__':
    main()
