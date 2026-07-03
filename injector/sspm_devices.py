"""
sspm_devices.py — tinysys-sspm firmware CPU min-freq FLOOR patcher (MT6789).

Companion to mcupm_devices.py. `sspm.img` (partition `tinysys-sspm`) holds the
thermal/power-budget tables that carry the CPU min-freq FLOOR anchors, stored as
u32 kHz inside 40-byte budget records ([floor_khz][0x0013bdb6][max_code]...),
the same record shape found in mcupm's [C] table @0x147f0:

    LITTLE floor = 500000 kHz (500 MHz)  — 8 occurrences
    BIG    floor = 725000 kHz (725 MHz)  — 7 occurrences

════════════════════════════════════════════════════════════════════
 EXPERIMENTAL / UNVERIFIED
════════════════════════════════════════════════════════════════════
Whether rewriting these floors actually moves the kernel `scaling_min_freq` is
NOT confirmed. On MT6789 the min freq is exposed by `mtk-cpufreq-hw` (kernel /
hardware LUT); these values are the DVFS firmware's thermal-budget floor anchors
and are the strongest editable candidate, but the effect must be verified by
flashing and reading `cpuinfo_min_freq` / `scaling_available_frequencies`.
Every knob defaults to stock (no-op). See CPU_OC_CHAIN_NOTES.md.

Two-gate note: sspm is GFH/cert2-signed like mcupm/pi_img. `--sign` re-forges
cert2 via fw_sign (local cert_bypass). On an unlocked device a raw edit
already boots; signing is for consistency / locked units. On-device cert
acceptance is UNTESTED (PI_IMG_KRAKEN_NOTES.md §4c/§6d).

Usage:
    python3 sspm_devices.py sspm.img out.img --minfreq-lit 400 --minfreq-big 600 --sign
    python3 sspm_devices.py sspm.img out.img --minfreq-lit 400 --dry-run
    python3 sspm_devices.py sspm.img --list --minfreq-lit 400 --minfreq-big 600
"""

import os
import sys
import struct
import argparse
from dataclasses import dataclass
from enum import Enum
from typing import List

# allow `import fw_sign` when run standalone or imported by the orchestrator
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ─────────────────────────────────────────────────────────────────────────────
# Core types (mirrors mcupm_devices.py)
# ─────────────────────────────────────────────────────────────────────────────

class MatchMode(Enum):
    ALL   = "all"
    EXACT = "exact"


@dataclass
class PatchStage:
    name:        str
    pattern:     str   # space-separated hex bytes
    replacement: str   # same length as pattern
    match_mode:  MatchMode = MatchMode.ALL
    description: str = ""
    expect:      int = 0   # expected match count (0 = don't check)

    @property
    def is_noop(self) -> bool:
        return self.pattern == self.replacement

    def pattern_bytes(self) -> bytes:
        return bytes(int(x, 16) for x in self.pattern.split())

    def replacement_bytes(self) -> bytes:
        return bytes(int(x, 16) for x in self.replacement.split())


def _hx(b: bytes) -> str:
    return ' '.join(f'{x:02x}' for x in b)

def _u32(v: int) -> str:
    return _hx(struct.pack('<I', v))


SSPM_FWID     = 'tinysys-sspm'
LIT_FLOOR_KHZ = 500000   # LITTLE (A55) min floor, 8x
BIG_FLOOR_KHZ = 725000   # BIG (A76) min floor, 7x


# ─────────────────────────────────────────────────────────────────────────────
# Patch builder
# ─────────────────────────────────────────────────────────────────────────────

def build_patches(minfreq_lit: int = None, minfreq_big: int = None) -> List[PatchStage]:
    """All patches always run; unset → replacement == pattern → no-op."""
    lit_pat = _u32(LIT_FLOOR_KHZ)
    lit_rep = _u32(minfreq_lit * 1000) if minfreq_lit else lit_pat
    lit_desc = (f'LITTLE min floor: 500 → {minfreq_lit} MHz (EXPERIMENTAL, x8)'
                if minfreq_lit else 'LITTLE min floor: 500 MHz (stock)')

    big_pat = _u32(BIG_FLOOR_KHZ)
    big_rep = _u32(minfreq_big * 1000) if minfreq_big else big_pat
    big_desc = (f'BIG min floor: 725 → {minfreq_big} MHz (EXPERIMENTAL, x7)'
                if minfreq_big else 'BIG min floor: 725 MHz (stock)')

    return [
        PatchStage('minfreq_little_floor', lit_pat, lit_rep,
                   match_mode=MatchMode.ALL, description=lit_desc, expect=8),
        PatchStage('minfreq_big_floor', big_pat, big_rep,
                   match_mode=MatchMode.ALL, description=big_desc, expect=7),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Patcher engine
# ─────────────────────────────────────────────────────────────────────────────

def read_fw_id(data: bytes) -> str:
    return data[8:0x30].split(b'\x00')[0].decode('ascii', errors='replace')


def apply_patch(data: bytearray, stage: PatchStage) -> int:
    needle = stage.pattern_bytes()
    repl   = stage.replacement_bytes()
    if len(needle) != len(repl):
        raise ValueError(f"{stage.name}: pattern/replacement length mismatch")
    count = i = 0
    while i <= len(data) - len(needle):
        if data[i:i+len(needle)] == needle:
            data[i:i+len(needle)] = repl
            count += 1
            i += len(needle)
        else:
            i += 1
    return count


def patch_image(input_path: str, output_path: str,
                minfreq_lit: int = None, minfreq_big: int = None,
                sign: bool = False, wrap: bool = False, dry_run: bool = False):
    raw  = open(input_path, 'rb').read()
    data = bytearray(raw)

    fwid = read_fw_id(raw)
    print(f"Input  : {input_path}  ({len(raw)} bytes)")
    print(f"FW ID  : {fwid}")
    if SSPM_FWID not in fwid:
        print(f"WARNING: fwid '{fwid}' is not '{SSPM_FWID}' — wrong image?")
    if minfreq_lit:
        print(f"MINFREQ LIT: 500 → {minfreq_lit} MHz  (EXPERIMENTAL, unverified)")
    if minfreq_big:
        print(f"MINFREQ BIG: 725 → {minfreq_big} MHz  (EXPERIMENTAL, unverified)")
    print()

    errors = []
    for stage in build_patches(minfreq_lit, minfreq_big):
        try:
            n = apply_patch(data, stage)
            if stage.is_noop:
                tag = 'NOOP '
            else:
                tag = f"{'DRY ' if dry_run else ''}OK  ({n} repl)"
                if n == 0:
                    errors.append((stage.name, 'pattern not found'))
                elif stage.expect and n != stage.expect:
                    print(f"  NOTE  {stage.name}: found {n}, expected {stage.expect} "
                          f"(build differs — verify before flashing)")
            print(f"  {tag:16s} {stage.name}: {stage.description}")
        except Exception as e:
            errors.append((stage.name, str(e)))
            print(f"  FAIL             {stage.name}: {e}")

    print()
    if errors:
        print(f"WARNING: {len(errors)} patch(es) failed — output NOT written.")
        for n, e in errors:
            print(f"  {n}: {e}")
        sys.exit(1)

    if dry_run:
        print("Dry run — no file written.")
        return

    open(output_path, 'wb').write(data)
    print(f"Output : {output_path}")

    if sign:
        import fw_sign
        fw_sign.sign_image(output_path, output_path, wrap=wrap)
        print(f"Signed : {output_path}  (cert2 {'WRAP' if wrap else 'OVERRIDE'}) "
              f"— on-device acceptance UNTESTED")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='tinysys-sspm CPU min-freq floor patcher (EXPERIMENTAL)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split('Usage:')[-1])
    ap.add_argument('input',  nargs='?', help='Input sspm.img')
    ap.add_argument('output', nargs='?', help='Output patched image')
    ap.add_argument('--minfreq-lit', type=int, default=None, metavar='MHZ',
                    help='EXPERIMENTAL: LITTLE min floor MHz — rewrites 500000 kHz (x8). Unverified.')
    ap.add_argument('--minfreq-big', type=int, default=None, metavar='MHZ',
                    help='EXPERIMENTAL: BIG min floor MHz — rewrites 725000 kHz (x7). Unverified.')
    ap.add_argument('--sign', action='store_true',
                    help='Re-sign output via cert_bypass (default: raw, no re-sign)')
    ap.add_argument('--wrap', action='store_true', help='cert2 WRAP mode (default: OVERRIDE)')
    ap.add_argument('--dry-run', '-n', action='store_true', help='Simulate, do not write')
    ap.add_argument('--list', '-l', action='store_true', help='Show patch plan, then exit')
    args = ap.parse_args()

    if args.list:
        print(f"Plan  --minfreq-lit={args.minfreq_lit}  --minfreq-big={args.minfreq_big}:")
        for s in build_patches(args.minfreq_lit, args.minfreq_big):
            tag = 'noop ' if s.is_noop else 'PATCH'
            print(f"  [{tag}] {s.name}: {s.description}")
        return

    if not args.input:
        ap.print_help()
        sys.exit(1)

    output = args.output or args.input.replace('.img', '_oc.img')
    patch_image(args.input, output,
                minfreq_lit=args.minfreq_lit, minfreq_big=args.minfreq_big,
                sign=args.sign, wrap=args.wrap, dry_run=args.dry_run)


if __name__ == '__main__':
    main()
