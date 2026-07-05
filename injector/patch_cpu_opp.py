"""
patch_cpu_opp.py — CPU OPP table patcher for tinysys-mcupm firmware (MT6789).

The CPU counterpart of patch_gpufreq.py, framed as an explicit OPP-table tool.

ARCHITECTURAL DIFFERENCE vs the GPU (verified on-device + by RE):
  - The GPU keeps a FULL 45-entry OPP table (freq+volt) baked into
    mtk_gpufreq_mt6789.ko — patch_gpufreq.py rewrites it entry by entry.
  - The CPU has NO full static OPP table. mediatek-cpufreq-hw.ko (a vendor
    module in vendor_boot) GENERATES the 24-step LITTLE / 16-step BIG ladder at
    runtime from the perf-domain SRAM LUT, which mcupm populates from a small set
    of ANCHOR OPPs. Those cluster-max anchors live in mcupm.img and are the only
    editable CPU "OPP table" that exists.

CONFIRMED on-device (INOI A75, mt6789):
    --big    MHZ   BIG   (A76, policy6) cluster max — stock 2200
    --little MHZ   LITTLE (A55, policy0) cluster max — stock 2000

This is a focused, explicit-table front-end over the *verified* mcupm_devices.py
patch stages, so the byte patterns never diverge from the validated patcher. For
the full CPU knob set (--floor throttle OPPs / --volt EEMSN / --thermal trips) use
mcupm_devices.py directly.

Usage:
    python3 patch_cpu_opp.py mcupm.img out.img --big 2600
    python3 patch_cpu_opp.py mcupm.img out.img --big 2600 --little 2200
    python3 patch_cpu_opp.py mcupm.img --list --big 2600 --little 2200
    python3 patch_cpu_opp.py mcupm.img out.img --big 2600 --sign
"""

import os
import sys
import argparse

# import the verified mcupm patcher (same directory)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mcupm_devices as mc

STOCK_BIG    = 2200   # A76 cluster max
STOCK_LITTLE = 2000   # A55 cluster max


# ─────────────────────────────────────────────────────────────────────────────
# Explicit CPU OPP anchor table (the "table" this tool exposes)
#   cluster,        role,       stock MHz, axis,       mcupm stage(s) touched
# ─────────────────────────────────────────────────────────────────────────────
CPU_OPP_TABLE = [
    ('A76 BIG',    'max',      2200, '--big',    'big_max, compact_row_2200, eemsn'),
    ('A76 BIG',    'low-max',  1650, '--big',    'big_low_opp_max'),
    ('A76 BIG',    'throttle', 2000, '--big',    'big_throttle, compact_row_2000'),
    ('A76 BIG',    'low-thr',  1600, '--big',    'big_low_opp_throttle'),
    ('A55 LITTLE', 'max',      2000, '--little', 'dvfs_timer_2000'),
    ('A55 LITTLE', 'low',      1540, '--little', 'dvfs_timer_1540'),
    ('A55 LITTLE', 'thr-max',   750, '--little', 'little_max_opp'),
    ('A55 LITTLE', 'throttle',  650, '--little', 'little_throttle_opp'),
]

# mcupm stages that make up the CPU OPP-table axes (thermal excluded here)
_BIG_STAGES    = {'big_max', 'big_low_opp_max', 'big_throttle', 'big_low_opp_throttle',
                  'compact_row_2000', 'compact_row_2200', 'compact_row_1540', 'eemsn'}
_LITTLE_STAGES = {'dvfs_timer_2000', 'dvfs_timer_1540', 'little_max_opp', 'little_throttle_opp'}
_OPP_STAGES    = _BIG_STAGES | _LITTLE_STAGES


def _opp_stages(big_mhz, little_mhz, volt_mv):
    """Verified OPP-axis stages from mcupm_devices (thermal excluded)."""
    stages = mc.build_patches(big_mhz=big_mhz, volt_mv=volt_mv, little_mhz=little_mhz)
    return [s for s in stages if s.name in _OPP_STAGES]


def print_table(big_mhz, little_mhz):
    print("CPU OPP anchor table (mcupm.img):")
    print(f"  {'cluster':11s} {'role':9s} {'stock':>6s} {'target':>7s}  axis      stage(s)")
    for cluster, role, stock, axis, stages in CPU_OPP_TABLE:
        if axis == '--big':
            tgt = round(stock * big_mhz / STOCK_BIG)
        else:  # --little (A55 max drives from the 2000 anchor)
            tgt = round(stock * little_mhz / STOCK_LITTLE)
        mark = '' if tgt == stock else '  *'
        print(f"  {cluster:11s} {role:9s} {stock:6d} {tgt:7d}  {axis:8s}  {stages}{mark}")


def run(inp, out, big_mhz, little_mhz, volt_mv, sign, wrap, dry_run):
    raw  = open(inp, 'rb').read()
    data = bytearray(raw)
    fw_id = mc.read_fw_id(raw)
    print(f"Input  : {inp}  ({len(raw)} bytes)")
    print(f"FW ID  : {fw_id}")
    if 'mcupm' not in fw_id:
        print(f"WARNING: fwid '{fw_id}' is not a tinysys-mcupm image — wrong file?")
    print(f"BIG    : {big_mhz} MHz (A76){'  (stock)' if big_mhz == STOCK_BIG else ''}")
    print(f"LITTLE : {little_mhz} MHz (A55){'  (stock)' if little_mhz == STOCK_LITTLE else ''}")
    print()

    little_dvfs = None if little_mhz == STOCK_LITTLE else little_mhz
    errors = []
    for stage in _opp_stages(big_mhz, little_dvfs, volt_mv):
        try:
            n = mc.apply_patch(data, stage)
            tag = 'NOOP ' if stage.is_noop else f"{'DRY ' if dry_run else ''}OK  ({n})"
            print(f"  {tag:12s} {stage.name}: {stage.description}")
        except Exception as e:
            errors.append((stage.name, str(e)))
            print(f"  FAIL         {stage.name}: {e}")

    print()
    if errors:
        print(f"WARNING: {len(errors)} patch(es) failed — output NOT written.")
        for name, msg in errors:
            print(f"  {name}: {msg}")
        sys.exit(1)

    if dry_run:
        print("Dry run — no file written.")
        return

    open(out, 'wb').write(data)
    print(f"Output : {out}")
    if sign:
        import fw_sign
        fw_sign.sign_image(out, out, wrap=wrap)
        print(f"Signed : {out}  (cert2 {'WRAP' if wrap else 'OVERRIDE'}) — on-device acceptance UNTESTED")


def _default_output(inp):
    base = os.path.basename(inp)
    stem, _, ext = base.rpartition('.')
    stem = stem or base
    out = f"{stem}_cpuopp.{ext}" if ext else f"{stem}_cpuopp"
    return os.path.join(os.path.dirname(inp) or '.', out)


def main():
    ap = argparse.ArgumentParser(
        description='CPU OPP table patcher for tinysys-mcupm (MT6789) — BIG/LITTLE cluster max',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split('Usage:')[-1])
    ap.add_argument('input',  nargs='?', help='Input mcupm.img')
    ap.add_argument('output', nargs='?', help='Output patched image (default: <input>_cpuopp.img)')
    ap.add_argument('--big',    type=int, default=STOCK_BIG, metavar='MHZ',
                    help=f'BIG (A76) cluster max MHz (default: {STOCK_BIG} = stock)')
    ap.add_argument('--little', type=int, default=STOCK_LITTLE, metavar='MHZ',
                    help=f'LITTLE (A55) cluster max MHz (default: {STOCK_LITTLE} = stock)')
    ap.add_argument('--volt',   type=int, default=None, metavar='MV',
                    help='EEMSN voltage mV override (default: auto-scaled from --big)')
    ap.add_argument('--sign', action='store_true',
                    help='Re-sign output via cert_bypass (default: raw, no re-sign)')
    ap.add_argument('--wrap', action='store_true', help='cert2 WRAP mode (default: OVERRIDE)')
    ap.add_argument('--dry-run', '-n', action='store_true', help='Simulate, do not write')
    ap.add_argument('--list', '-l', action='store_true', help='Show the OPP table + plan, then exit')
    args = ap.parse_args()

    little_dvfs = None if args.little == STOCK_LITTLE else args.little

    if args.list:
        print_table(args.big, args.little)
        print("\nPlan (verified mcupm stages):")
        for s in _opp_stages(args.big, little_dvfs, args.volt):
            tag = 'noop ' if s.is_noop else 'PATCH'
            print(f"  [{tag}] {s.name}: {s.description}")
        return

    if not args.input:
        ap.print_help()
        sys.exit(1)

    out = args.output or _default_output(args.input)
    run(args.input, out, args.big, args.little, args.volt,
        args.sign, args.wrap, args.dry_run)


if __name__ == '__main__':
    main()
