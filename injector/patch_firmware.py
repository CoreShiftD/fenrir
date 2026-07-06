#!/usr/bin/env python3
"""
patch_firmware.py — EXPERIMENTAL multi-partition firmware OC orchestrator.

Reads the per-device `firmware={...}` block from devices.py and drives the
individual partition patchers (each has DIFFERENT flags), re-signing every
modified image. Opt-in from build.sh via `--firmware`.

    build.sh <device> [bootloader] --firmware
        └─> patch_firmware.py <device>
              ├─ mcupm_devices.py  mcupm.img  <dev>-mcupm.img   (--big/--floor/--sign …)
              ├─ pi_img_devices.py pi_img.bin <dev>-pi_img.bin  (--set-reg/--write …)
              └─ patch_gpufreq.py mtk_gpufreq_mt6789.ko <dev>-gpufreq.ko (--bp/--oc …)

Every knob defaults to no-op; a partition with no actionable value or a missing
input image is SKIPPED. Nothing is flashed — this only produces files.

EXPERIMENTAL / UNVERIFIED per silicon (esp. the forged cert2) — flash and verify
on-device. See CPU_OC_CHAIN_NOTES.md.

Run under the liblk venv so re-signing works:
    /opt/src/fenrir/.venv/bin/python3 injector/patch_firmware.py <device>
"""

import os
import sys
import argparse
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from devices import DEVICES  # noqa: E402


def venv_python() -> str:
    """Prefer the liblk venv (needed for cert re-signing)."""
    v = os.path.join(ROOT, '.venv', 'bin', 'python3')
    return v if os.path.exists(v) else sys.executable


# ── per-partition arg builders (each tool has its own flags) ──────────────────

def _mcupm_args(cfg):
    a = []
    if cfg.get('big')     is not None: a += ['--big', str(cfg['big'])]
    if cfg.get('little')  is not None: a += ['--little', str(cfg['little'])]
    if cfg.get('volt')    is not None: a += ['--volt', str(cfg['volt'])]
    if cfg.get('thermal') is not None: a += ['--thermal', str(cfg['thermal'])]
    if cfg.get('sign'): a += ['--sign']
    if cfg.get('wrap'): a += ['--wrap']
    return a

def _mcupm_actionable(cfg):
    return any(cfg.get(k) is not None
               for k in ('big', 'little', 'volt', 'thermal'))


def _pi_img_args(cfg):
    a = []
    for s in cfg.get('set') or []:     a += ['--set', str(s)]
    for s in cfg.get('set_reg') or []: a += ['--set-reg', str(s)]
    a += ['--write']                    # pi_img always re-signs on --write
    if cfg.get('wrap'): a += ['--wrap']
    return a

def _pi_img_actionable(cfg):
    return bool(cfg.get('set') or cfg.get('set_reg'))

def _gpufreq_args(cfg):
    a = []
    if cfg.get('bp') is True: a += ['--bp']
    if cfg.get('oc') is not None: a += ['--oc', str(cfg['oc'])]
    if cfg.get('volt') is not None: a += ['--volt', str(cfg['volt'])]
    if cfg.get('floor_volt') is not None: a += ['--floor-volt', str(cfg['floor_volt'])]
    if cfg.get('offset') is not None: a += ['--offset', str(cfg['offset'])]
    if cfg.get('skip'): a += ['--skip'] + [str(s) for s in cfg['skip']]
    return a


def _gpufreq_actionable(cfg):
    return (cfg.get('bp') is True or cfg.get('oc') is not None or
            cfg.get('volt') is not None or cfg.get('floor_volt') is not None or
            cfg.get('offset') is not None or bool(cfg.get('skip')))


PARTS = {
    'mcupm':  dict(inp='mcupm.img',  out='{dev}-mcupm.img',  tool='mcupm_devices.py',
                   args=_mcupm_args,  actionable=_mcupm_actionable),
    'pi_img': dict(inp='pi_img.bin', out='{dev}-pi_img.bin', tool='pi_img_devices.py',
                   args=_pi_img_args, actionable=_pi_img_actionable),
    'gpufreq': dict(inp='mtk_gpufreq_mt6789.ko', out='{dev}-gpufreq.ko',
                    tool='patch_gpufreq.py', args=_gpufreq_args,
                    actionable=_gpufreq_actionable),
}


def find_device(name):
    for d in DEVICES:
        if d.name.lower() == name.lower() or d.codename.lower() == name.lower():
            return d
    return None


def main():
    ap = argparse.ArgumentParser(
        description='EXPERIMENTAL multi-partition firmware OC orchestrator')
    ap.add_argument('device', help='Device name (as in devices.py)')
    ap.add_argument('--in-dir', default=None,
                    help='Dir with mcupm.img / sspm.img / pi_img.bin '
                         '(default: bin/firmware/<device>/)')
    ap.add_argument('--out-dir', default=None,
                    help='Output directory (default: same as --in-dir)')
    ap.add_argument('--dry-run', '-n', action='store_true', help='Simulate; write nothing')
    args = ap.parse_args()

    dev = find_device(args.device)
    if dev is None:
        sys.exit(f"ERROR: unknown device '{args.device}'. Known: "
                 + ', '.join(d.name for d in DEVICES))

    # default input/output location: bin/firmware/<device>/  (mirrors bin/<device>.bin)
    fw_dir = os.path.join(ROOT, 'bin', 'firmware', dev.name.lower())
    if args.in_dir is None:
        args.in_dir = fw_dir
    if args.out_dir is None:
        args.out_dir = args.in_dir

    fw = dev.device_opts.get('firmware')
    if not fw:
        print(f"No firmware={{...}} config for {dev.name} — nothing to do "
              f"(add one in injector/devices.py).")
        return 0

    print("=" * 68)
    print(f" EXPERIMENTAL firmware OC for {dev.name} ({dev.codename})")
    print(" UNVERIFIED per silicon — flash & verify on-device. Nothing flashed here.")
    print("=" * 68)

    os.makedirs(args.out_dir, exist_ok=True)
    py = venv_python()
    ran, skipped = [], []
    for pname, spec in PARTS.items():
        cfg = fw.get(pname)
        if not cfg or not spec['actionable'](cfg):
            skipped.append((pname, 'no actionable flags'))
            continue
        inp = os.path.join(args.in_dir, spec['inp'])
        if not os.path.exists(inp):
            skipped.append((pname, f"input '{spec['inp']}' not found in {args.in_dir}"))
            continue
        out = os.path.join(args.out_dir, spec['out'].format(dev=dev.name.lower()))
        cmd = [py, os.path.join(HERE, spec['tool']), inp, out] + spec['args'](cfg)
        if args.dry_run:
            cmd += ['--dry-run']
        print(f"\n── {pname} ──")
        print("  $ " + ' '.join(cmd))
        rc = subprocess.call(cmd)
        if rc != 0:
            print(f"\nFAIL: {pname} patcher exited {rc} — aborting.")
            return rc
        ran.append((pname, out))

    # --- GPT partition table images ---
    gpt_cfg = fw.get('gpt')
    if gpt_cfg is not None:
        inp = gpt_cfg.get('scatter') or os.path.join(args.in_dir, 'MT6789_Android_scatter.xml')
        if not os.path.exists(inp):
            skipped.append(('gpt', f"scatter not found at {inp}"))
        else:
            out = args.out_dir
            cmd = [py, os.path.join(HERE, 'mtk_gpt_tool.py'), 'generate',
                   '--device', dev.name.lower(), '--out-dir', out,
                   '--output-suffix', '_gen']
            if gpt_cfg.get('storage'):
                cmd += ['--storage', gpt_cfg['storage']]
            if gpt_cfg.get('disk_size') is not None:
                cmd += ['--disk-size', str(gpt_cfg['disk_size'])]
            if gpt_cfg.get('sector_size'):
                cmd += ['--sector-size', str(gpt_cfg['sector_size'])]
            print(f"\n── gpt ──")
            print("  $ " + ' '.join(cmd))
            if args.dry_run:
                print("  (dry-run, skipped)")
            else:
                rc = subprocess.call(cmd)
                if rc != 0:
                    print(f"\nFAIL: gpt exited {rc} — aborting.")
                    return rc
            ran.append(('gpt', os.path.join(out, 'PGPT_gen.img') + ', SGPT_gen.img'))

    print("\n" + "=" * 68)
    if ran:
        print(" Produced (EXPERIMENTAL, verify before flashing):")
        for p, o in ran:
            print(f"   {p:7s} → {o}")
    for p, why in skipped:
        print(f" skipped {p}: {why}")
    print("=" * 68)
    return 0


if __name__ == '__main__':
    sys.exit(main())
