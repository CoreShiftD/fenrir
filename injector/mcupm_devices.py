"""
mcupm_devices.py — Dynamic CPU freq patcher for tinysys-mcupm firmware (MT6789).

All patches always run (firmware identity validation). Unset flags → stock value
→ replacement == pattern → no-op. Supports overclock AND underclock.

Usage:
    python3 mcupm_devices.py mcupm.img out.img --big 2600
    python3 mcupm_devices.py mcupm.img out.img --big 2600 --little 2200
    python3 mcupm_devices.py mcupm.img out.img --big 2600 --volt 1150
    python3 mcupm_devices.py mcupm.img out.img --big 2600 --dry-run
    python3 mcupm_devices.py mcupm.img out.img --list

Flags (two confirmed cluster-max axes, validated on-device INOI A75):
    --big    MHZ  BIG (A76, policy6) cluster max (default: 2200, stock). All BIG entries scale.
    --little MHZ  LITTLE (A55, policy0) cluster max (default: 2000, stock). Scales the A55
                  DVFS-timer top + LITTLE governor throttle OPPs.
    --volt   MV   EEMSN voltage mV override (default: auto-scaled from --big)
    --thermal C   Thermal trip ceiling °C (default: auto-scaled; stock: 95/85)

════════════════════════════════════════════════════════════════════
 BINARY LAYOUT  (FW: tinysys-mcupm-RV33_A, mcupm.img = 129344 bytes)
════════════════════════════════════════════════════════════════════

 FORMAT: mcupm.img is a GFH-wrapped RISC-V (RV32, "RV33_A") firmware.
   - 0x200-byte MediaTek GFH header prefixes the RISC-V payload.
   - RISC-V code base = 0  →  code_addr = file_offset − 0x200.
   All offsets below are FILE offsets into mcupm.img (what this script patches).

 REVERSE-ENGINEERING SUMMARY (verified with radare2 + capstone):
   Every freq/OPP field in this image is owned by ONE DVFS management
   struct based at file 0x15fe8 (code 0x15de8), driven by a single manager
   function at code 0x92b0. That function:
     - iterates a 3-entry × 228-byte (0xe4) runtime state array @ file 0x16028,
     - reads the source freq tuples from the compact table @ 0x15fec, and
     - WRITES the derived adj/lat OPP limit structs into the governor
       table @ 0x16598 (e.g. `sw a0, 0x778(s9)` → 0x165d0).
   There is NO full per-step (16/24-step) OPP ladder in this firmware — it
   holds only the max / throttle / low ANCHOR OPPs below. The full ladder,
   and the true per-cluster scaling_min_freq, live in the kernel cpufreq
   driver / device tree, NOT here (device mins: LITTLE 500, BIG 725 MHz —
   725000 kHz does not appear anywhere in mcupm.img). See "MIN FREQ" note.

 OPP struct (24 bytes, little-endian):
   [freq_MHz u32][adj i32][lat u32][0x00030d40 u32][flags u32][0x00001666 u32]
   flags: 0x37020402 = BIG (A76)
          0x37020302 = LITTLE (A55)
   Note: structs are NOT 4-byte aligned in this firmware.

 ┌─ [A] Governor OPP-limit table (0x16598) — 10 × 24B, 2 groups ───┐
 │ (the ONLY 24B OPP structs in the image; scan-confirmed complete) │
 │ Offset    Type    Stock MHz   adj        lat    Patched by      │
 │ 0x16598   BIG     2000       -10715     10715   --big (thr)     │
 │ 0x165b0   BIG     1600        -7693      7693   --big (low thr) │
 │ 0x165c8   LITTLE   650       -10000     10000   --little (thr)  │
 │ 0x165e0   LITTLE   650       -10000     10000   --little (thr)  │
 │ 0x165f8   LITTLE   650       -10000     10000   --little (thr)  │
 │ 0x16670   BIG     2200       -15000     15000   --big (max)     │
 │ 0x16688   BIG     1650       -15000     15000   --big (low max) │
 │ 0x166a0   LITTLE   750       -14286     14286   --little (thr)  │
 │ 0x166b8   LITTLE   750       -14286     14286   --little (thr)  │
 │ 0x166d0   LITTLE   750       -14286     14286   --little (thr)  │
 └─────────────────────────────────────────────────────────────────┘

 ┌─ [B] Compact freq-tuple table (0x15fec) — source freq rows ─────┐
 │ Row format: [BIG u16][BIG2 u16][LITTLE u16][pad u16][u32]       │
 │             [lat_byte u8][...3 bytes][u32]  (16 bytes total)    │
 │                                                                  │
 │ Offset    BIG     BIG2    LITTLE  lat   Patched by              │
 │ 0x15fec   2000    1600     650    0x9f  --big (throttle row)    │
 │ 0x16000   2200    1650     725    0x9f  --big (max row)         │
 │ 0x16014   1540    1050     450    0x9f  --big (low row)         │
 │                                                                  │
 │ Exactly 3 rows (whole-image scan confirms no further copies).    │
 └─────────────────────────────────────────────────────────────────┘

 ┌─ [C] CPU power/thermal-limit table (0x147f0) — 4 × 40B ─────────┐
 │ NOT patched. Loop-walked by mcupm (no static xref). Each record: │
 │   +0x00 floor = 500000 (kHz, 500 MHz) — SAME in all 4 records    │
 │   +0x04 1293750  (power/budget coeff, constant)                  │
 │   +0x0e/+0x14 per-domain max code (×5/16 → MHz):                 │
 │        0x147f0→1602  0x14818→1562  0x14840→2202  0x14868→2182    │
 │ This is the aging/thermal power envelope, immediately preceding  │
 │ the thermal trips. The 500000 value is NOT scaling_min_freq      │
 │ (that is kernel/HW-owned, mtk-cpufreq-hw perf-domain SRAM LUT) — │
 │ not a min-freq knob. Left untouched.                             │
 └─────────────────────────────────────────────────────────────────┘

 ┌─ Thermal trips (0x1488c) — read by code @0xe07e ───────────────┐
 │ high trip: 0x1488c  stock 0x5f = 95°C   → --thermal            │
 │ low  trip: 0x14890  stock 0x55 = 85°C   → --thermal            │
 └─────────────────────────────────────────────────────────────────┘

 ┌─ DVFS timer table (0x17b88) — LITTLE (A55) cluster max anchor ──┐
 │ Entry 2000 MHz: 0x17b88  [freq u16][0x186a u16][0x015c u16]... │
 │ Entry 1540 MHz: 0x17d80  same layout                           │
 │ Top entry (2000) = A55 policy0 max — patched by --little.      │
 └─────────────────────────────────────────────────────────────────┘

 ┌─ EEMSN freq+voltage (0x17cb4) ──────────────────────────────────┐
 │ Layout: [freq u16][0x186a u16][voltage_mv u16][0x0000 u16]      │
 │ Stock: freq=2200 MHz, volt=1024 mV (0x0400)                     │
 └─────────────────────────────────────────────────────────────────┘

 ┌─ Separate: EEM/DVFS coefficient curves (0x15d40 … 0x15ef8) ─────┐
 │ Four 14-entry × 8B fixed-point tables. NOT frequencies and NOT  │
 │ part of the OPP struct above — aging/curve data. Do not patch.  │
 └─────────────────────────────────────────────────────────────────┘

 MIN FREQ / HARD OC CEILING (why raising min/max past a point fails):
   - scaling_min_freq (LITTLE 500 / BIG 725 MHz) is set by the kernel
     cpufreq/OPP (device tree), not by any editable clamp in mcupm.img.
     Patching mcupm cannot lower/raise the true min freq.
   - The hard refusal past a threshold is EEMSN validating voltage/freq
     against pi_img.bin aging data ("[CPU][EEMSN]...vboot violate",
     str @ file 0x12ed4; pi_img key-load @ code 0xba10). See
     PI_IMG_KRAKEN_NOTES.md — that path, not these tables, gates the ceiling.

Stock MT6789 (2x Cortex-A76 BIG, 6x Cortex-A55 LITTLE):
    BIG high OPP   max 2200 MHz, throttle 2000 MHz
    BIG low OPP    max 1650 MHz, throttle 1600 MHz
    LITTLE (A55)   max  750 MHz, throttle  650 MHz
"""

import sys
import struct
import argparse
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Core types
# ─────────────────────────────────────────────────────────────────────────────

class MatchMode(Enum):
    FIRST = "first"
    ALL   = "all"
    EXACT = "exact"


@dataclass
class PatchStage:
    name:        str
    pattern:     str   # space-separated hex bytes
    replacement: str   # same length as pattern
    match_mode:  MatchMode = MatchMode.EXACT
    description: str = ""

    @property
    def is_noop(self) -> bool:
        return self.pattern == self.replacement

    def pattern_bytes(self) -> bytes:
        return bytes(int(x, 16) for x in self.pattern.split())

    def replacement_bytes(self) -> bytes:
        return bytes(int(x, 16) for x in self.replacement.split())

    def validate(self):
        p, r = self.pattern_bytes(), self.replacement_bytes()
        if len(p) != len(r):
            raise ValueError(f"{self.name}: pattern/replacement length mismatch")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _hx(b: bytes) -> str:
    return ' '.join(f'{x:02x}' for x in b)

def _u16(v: int) -> str:
    return _hx(struct.pack('<H', v))

def _u32(v: int) -> str:
    return _hx(struct.pack('<I', v))

def _compact_lat_byte(mhz: int) -> str:
    # stock 0x9f at 2200, ref OC 0xbe at 2700 — linear interpolation above 2200
    if mhz <= 2200:
        return '9f'
    val = round(0x9f + (mhz - 2200) / (2700 - 2200) * (0xbe - 0x9f))
    return f'{min(val, 0xff):02x}'

def _opp(freq: int, adj: int, lat: int, flags: int) -> str:
    return _hx(struct.pack('<IiIIII', freq, adj, lat, 0x00030d40, flags, 0x00001666))

BIG_FLAGS    = 0x37020402
LITTLE_FLAGS = 0x37020302

# Stock adj/lat (from firmware scan)
_BIG_MAX_ADJ,    _BIG_MAX_LAT    = -15000, 15000
_BIG_THR_ADJ,    _BIG_THR_LAT    = -10715, 10715
_BIG_LTHR_ADJ,   _BIG_LTHR_LAT   = -7693,  7693
_LIT_MAX_ADJ,    _LIT_MAX_LAT    = -14286, 14286
_LIT_THR_ADJ,    _LIT_THR_LAT    = -10000, 10000


# ─────────────────────────────────────────────────────────────────────────────
# Patch builder
# ─────────────────────────────────────────────────────────────────────────────

def _auto_thermal(big_mhz: int):
    # returns (high_c, low_c) each scaled from their own stock value
    # stock high=95°C, stock low=85°C; ref OC both→100°C at 2600 MHz
    if big_mhz <= 2200:
        return 95, 85
    high = round(95 + (big_mhz - 2200) / (2600 - 2200) * (100 - 95))
    low  = round(85 + (big_mhz - 2200) / (2600 - 2200) * (100 - 85))
    return high, low


def _auto_volt(big_mhz: int) -> int:
    # linear interp: 2200 MHz→1024 mV, 2700 MHz→1100 mV
    if big_mhz <= 2200:
        return 1024
    return round(1024 + (big_mhz - 2200) / (2700 - 2200) * (1100 - 1024))


def build_patches(big_mhz: int = 2200, volt_mv: int = None,
                  little_mhz: int = None) -> List[PatchStage]:
    """
    Two confirmed cluster-max axes (validated on-device, INOI A75):
      big_mhz    — BIG (A76, policy6) cluster max; scales every BIG anchor.
      little_mhz — LITTLE (A55, policy0) cluster max; scales the A55 DVFS-timer
                   top and the LITTLE governor throttle OPPs. None = stock 2000.
    volt_mv=None → EEMSN voltage auto-scaled from big_mhz.
    """
    t_big     = big_mhz
    t_big_thr = round(2000 * t_big / 2200)          # A76 throttle OPP (scales with --big)
    t_volt    = volt_mv if volt_mv is not None else _auto_volt(big_mhz)
    t_a55     = little_mhz if little_mhz else 2000   # A55 (LITTLE) cluster max

    # ── 24-byte OPP structs ──────────────────────────────────────────────────

    # BIG high OPP max (stock 2200) — controlled by --big
    big_max_pat = _opp(2200, _BIG_MAX_ADJ, _BIG_MAX_LAT, BIG_FLAGS)
    big_max_rep = _opp(t_big, _BIG_MAX_ADJ, _BIG_MAX_LAT, BIG_FLAGS)
    big_max_desc = (f'BIG max OPP: 2200 → {t_big} MHz'
                    if t_big != 2200 else 'BIG max OPP: 2200 MHz (stock)')

    # BIG low OPP max (stock 1650) — scales with --big
    _big_lomax = round(1650 * t_big / 2200)
    big_lomax_pat = _opp(1650, _BIG_MAX_ADJ, _BIG_MAX_LAT, BIG_FLAGS)
    big_lomax_rep = _opp(_big_lomax, _BIG_MAX_ADJ, _BIG_MAX_LAT, BIG_FLAGS)
    big_lomax_desc = (f'BIG low OPP max: 1650 → {_big_lomax} MHz'
                      if _big_lomax != 1650 else 'BIG low OPP max: 1650 MHz (stock)')

    # BIG high OPP throttle (stock 2000) — scales with --big
    big_thr_pat = _opp(2000, _BIG_THR_ADJ, _BIG_THR_LAT, BIG_FLAGS)
    big_thr_rep = _opp(t_big_thr, _BIG_THR_ADJ, _BIG_THR_LAT, BIG_FLAGS)
    big_thr_desc = (f'BIG throttle OPP: 2000 → {t_big_thr} MHz'
                    if t_big_thr != 2000 else 'BIG throttle OPP: 2000 MHz (stock)')

    # BIG low OPP throttle (stock 1600) — scales with --big
    _big_lthr = round(1600 * t_big / 2200)
    big_lthr_pat = _opp(1600, _BIG_LTHR_ADJ, _BIG_LTHR_LAT, BIG_FLAGS)
    big_lthr_rep = _opp(_big_lthr, _BIG_LTHR_ADJ, _BIG_LTHR_LAT, BIG_FLAGS)
    big_lthr_desc = (f'BIG low OPP throttle: 1600 → {_big_lthr} MHz'
                     if _big_lthr != 1600 else 'BIG low OPP throttle: 1600 MHz (stock)')

    # ── Compact freq-tuple table (0x15fec) ──────────────────────────────────
    # 16-byte patterns include lat byte at offset +12 so freq+lat change together.
    # Format: [big1 u16][big2 u16][little u16][pad u16][u32][lat_byte ...][u32]

    # compact_row_2000 (stock 2000) — controlled by --little
    # little_a55 col (stock 650) scales proportionally with t_big_thr
    c2000_lit = round(650 * t_big_thr / 2000)
    c2000_pat  = 'd0 07 40 06 8a 02 00 00 00 00 00 00 9f 8f 67 00'
    c2000_rep  = f'{_u16(t_big_thr)} 40 06 {_u16(c2000_lit)} 00 00 00 00 00 00 {_compact_lat_byte(t_big_thr)} 8f 67 00'
    c2000_desc = (f'Compact row 2000: big→{t_big_thr} little→{c2000_lit} MHz'
                  if t_big_thr != 2000 else 'Compact row 2000: 2000/650 MHz (stock)')

    # compact_row_2200 (stock 2200) — controlled by --big
    # little_a55 col (stock 725) scales proportionally with t_big
    c2200_lit = round(725 * t_big / 2200)
    c2200_pat  = '98 08 72 06 d5 02 00 00 00 00 00 00 9f 8b 67 00'
    c2200_rep  = f'{_u16(t_big)} 72 06 {_u16(c2200_lit)} 00 00 00 00 00 00 {_compact_lat_byte(t_big)} 8b 67 00'
    c2200_desc = (f'Compact row 2200: big→{t_big} little→{c2200_lit} MHz'
                  if t_big != 2200 else 'Compact row 2200: 2200/725 MHz (stock)')

    # compact_row_1540 — scales with --big; cols: big1=1540, big2=1050, little=450
    _c1540_big = round(1540 * t_big / 2200)
    _c1540_lit = round(450  * t_big / 2200)
    c1540_pat  = '04 06 1a 04 c2 01 00 00'
    c1540_rep  = f'{_u16(_c1540_big)} 1a 04 {_u16(_c1540_lit)} 00 00'
    c1540_desc = (f'Compact row 1540: big→{_c1540_big} little→{_c1540_lit} MHz'
                  if _c1540_big != 1540 else 'Compact row 1540: 1540/450 MHz (stock)')

    # ── EEMSN freq + voltage (0x17cb4) ──────────────────────────────────────
    # Layout: [freq u16][0x186a u16][voltage_mv u16][0x0000 u16]
    # Both freq and voltage must be updated — freq here caps the BIG cluster.
    eemsn_pat  = '98 08 6a 18 00 04 00 00'
    eemsn_rep  = f'{_u16(t_big)} 6a 18 {_u16(t_volt)} 00 00'
    eemsn_desc = (f'EEMSN: freq 2200→{t_big} MHz, volt 1024→{t_volt} mV'
                  + ('' if volt_mv is not None else ' (auto)')
                  if t_big != 2200 else f'EEMSN: 2200 MHz, {t_volt} mV (stock freq)')

    # ── LITTLE (A55) anchors — scale with --little (A55 cluster max) ─────────
    # DVFS-timer top (0x17b88) is the confirmed A55 max anchor.
    _dvfs1540 = round(1540 * t_a55 / 2000)
    dvfs2000_pat = 'd0 07 6a 18 5c 01 00 00'
    dvfs2000_rep = f'{_u16(t_a55)} 6a 18 5c 01 00 00'
    dvfs2000_desc = (f'LITTLE max (DVFS timer): 2000 → {t_a55} MHz'
                     if t_a55 != 2000 else 'LITTLE max (DVFS timer): 2000 MHz (stock)')
    dvfs1540_pat = '04 06 6a 18 00 00 00 00'
    dvfs1540_rep = f'{_u16(_dvfs1540)} 6a 18 00 00 00 00'
    dvfs1540_desc = (f'LITTLE low (DVFS timer): 1540 → {_dvfs1540} MHz'
                     if _dvfs1540 != 1540 else 'LITTLE low (DVFS timer): 1540 MHz (stock)')

    # LITTLE governor throttle OPPs (750/650, FLAGS_B) — scale with A55 max.
    _lit_max = round(750 * t_a55 / 2000)
    _lit_thr = round(650 * t_a55 / 2000)
    lit_max_pat = _opp(750, _LIT_MAX_ADJ, _LIT_MAX_LAT, LITTLE_FLAGS)
    lit_max_rep = _opp(_lit_max, _LIT_MAX_ADJ, _LIT_MAX_LAT, LITTLE_FLAGS)
    lit_max_desc = (f'LITTLE throttle-max OPP: 750 → {_lit_max} MHz'
                    if _lit_max != 750 else 'LITTLE throttle-max OPP: 750 MHz (stock)')
    lit_thr_pat = _opp(650, _LIT_THR_ADJ, _LIT_THR_LAT, LITTLE_FLAGS)
    lit_thr_rep = _opp(_lit_thr, _LIT_THR_ADJ, _LIT_THR_LAT, LITTLE_FLAGS)
    lit_thr_desc = (f'LITTLE throttle OPP: 650 → {_lit_thr} MHz'
                    if _lit_thr != 650 else 'LITTLE throttle OPP: 650 MHz (stock)')

    return [
        PatchStage('little_max_opp',    lit_max_pat,  lit_max_rep,
                   match_mode=MatchMode.ALL, description=lit_max_desc),
        PatchStage('little_throttle_opp', lit_thr_pat, lit_thr_rep,
                   match_mode=MatchMode.ALL, description=lit_thr_desc),
        PatchStage('big_max',           big_max_pat,  big_max_rep,  description=big_max_desc),
        PatchStage('big_low_opp_max',   big_lomax_pat, big_lomax_rep, description=big_lomax_desc),
        PatchStage('big_throttle',      big_thr_pat,  big_thr_rep,  description=big_thr_desc),
        PatchStage('big_low_opp_throttle', big_lthr_pat, big_lthr_rep, description=big_lthr_desc),
        PatchStage('compact_row_2000',  c2000_pat,    c2000_rep,    description=c2000_desc),
        PatchStage('compact_row_2200',  c2200_pat,    c2200_rep,    description=c2200_desc),
        PatchStage('compact_row_1540',  c1540_pat,    c1540_rep,    description=c1540_desc),
        PatchStage('eemsn',             eemsn_pat,    eemsn_rep,    description=eemsn_desc),
        PatchStage('dvfs_timer_2000',   dvfs2000_pat, dvfs2000_rep, description=dvfs2000_desc),
        PatchStage('dvfs_timer_1540',   dvfs1540_pat, dvfs1540_rep, description=dvfs1540_desc),
    ]


def thermal_patches(thermal_c: int, big_mhz: int = 2200) -> List[PatchStage]:
    if thermal_c is None:
        high_c, low_c = _auto_thermal(big_mhz)
        label = 'auto'
    else:
        high_c = low_c = thermal_c
        label = 'override'
    th = f'{high_c:02x}'
    tl = f'{low_c:02x}'
    return [
        PatchStage(
            name='thermal_trips',
            # stock: 0x5f=95°C (high), 0x55=85°C (low)
            pattern='6a 18 00 00 5f 00 00 00 55 00 00 00 12 00 00 00 05 00 00 00',
            replacement=f'6a 18 00 00 {th} 00 00 00 {tl} 00 00 00 12 00 00 00 05 00 00 00',
            description=f'Thermal trips: 95→{high_c}°C, 85→{low_c}°C ({label})',
        ),
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Patcher engine
# ─────────────────────────────────────────────────────────────────────────────

def read_fw_id(data: bytes) -> str:
    return data[8:0x20].rstrip(b'\x00').decode('ascii', errors='replace')


def apply_patch(data: bytearray, stage: PatchStage) -> int:
    stage.validate()
    needle = stage.pattern_bytes()
    repl   = stage.replacement_bytes()
    count = i = 0
    while i <= len(data) - len(needle):
        if data[i:i+len(needle)] == needle:
            data[i:i+len(needle)] = repl
            count += 1
            if stage.match_mode == MatchMode.FIRST:
                break
        i += 1
    if stage.match_mode == MatchMode.EXACT and count != 1:
        raise RuntimeError(
            f"[{stage.name}] EXACT match required, found {count} occurrence(s). "
            f"Firmware may differ from expected revision."
        )
    return count


def patch_image(input_path: str, output_path: str,
                big_mhz: int = 2200, volt_mv: int = None,
                thermal_c: int = None, little_mhz: int = None,
                no_thermal: bool = False, dry_run: bool = False,
                sign: bool = False, wrap: bool = False,
                skip: Optional[List[str]] = None):
    raw  = open(input_path, 'rb').read()
    data = bytearray(raw)
    skip = skip or []

    fw_id = read_fw_id(raw)
    print(f"Input  : {input_path}  ({len(raw)} bytes)")
    print(f"FW ID  : {fw_id}")
    print(f"BIG    : {big_mhz} MHz (A76){'  (stock)' if big_mhz == 2200 else ''}")
    _lm = little_mhz if little_mhz else 2000
    print(f"LITTLE : {_lm} MHz (A55){'  (stock)' if _lm == 2000 else ''}")
    _v = volt_mv if volt_mv is not None else _auto_volt(big_mhz)
    print(f"VOLT   : {_v} mV{'  (auto)' if volt_mv is None else '  (override)'}")
    if thermal_c is None:
        _th, _tl = _auto_thermal(big_mhz)
        _tlabel = '(auto)'
    else:
        _th = _tl = thermal_c
        _tlabel = '(override)'
    if not no_thermal:
        print(f"THERMAL: high={_th}°C low={_tl}°C  {_tlabel}")
    print()

    stages: List[PatchStage] = []
    if not no_thermal:
        stages += thermal_patches(thermal_c, big_mhz)
    stages += build_patches(big_mhz, volt_mv, little_mhz)

    errors = []
    for stage in stages:
        if stage.name in skip:
            print(f"  SKIP  {stage.name}")
            continue
        try:
            n = apply_patch(data, stage)
            if stage.is_noop:
                tag = 'NOOP '
            else:
                tag = f"{'DRY ' if dry_run else ''}OK  ({n} repl)"
            print(f"  {tag:22s} {stage.name}: {stage.description}")
        except Exception as e:
            errors.append((stage.name, str(e)))
            print(f"  FAIL                   {stage.name}: {e}")

    print()
    if errors:
        print(f"WARNING: {len(errors)} patch(es) failed — output NOT written.")
        for n, e in errors:
            print(f"  {n}: {e}")
        sys.exit(1)

    if not dry_run:
        open(output_path, 'wb').write(data)
        print(f"Output: {output_path}")
        if sign:
            import fw_sign
            fw_sign.sign_image(output_path, output_path, wrap=wrap)
            print(f"Signed : {output_path}  (cert2 {'WRAP' if wrap else 'OVERRIDE'}, EXPERIMENTAL/untested)")
    else:
        print("Dry run — no file written.")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description='MCUPM firmware CPU overclock patcher',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s mcupm.img out.img --big 2600
  %(prog)s mcupm.img out.img --big 2600 --little 2400
  %(prog)s mcupm.img out.img --big 2600 --dry-run
  %(prog)s --list --big 2600
        """,
    )
    ap.add_argument('input',  nargs='?', help='Input mcupm.img')
    ap.add_argument('output', nargs='?', help='Output patched image')
    ap.add_argument('--big',        type=int, default=2200, metavar='MHZ',
                    help='Target BIG MHz; all entries scale from this (default: 2200 = stock)')
    ap.add_argument('--volt',       type=int, default=None, metavar='MV',
                    help='EEMSN voltage mV (default: auto-scaled from --big; stock: 1024)')
    ap.add_argument('--little',     type=int, default=None, metavar='MHZ',
                    help='LITTLE (A55) cluster max MHz; scales the A55 DVFS-timer top and the '
                         'LITTLE governor throttle OPPs (default: 2000 = stock)')
    ap.add_argument('--thermal',    type=int, default=None, metavar='C',
                    help='Thermal trip ceiling °C (default: auto-scaled from --big; stock: 95/85)')
    ap.add_argument('--sign', action='store_true',
                    help='Re-sign output via cert_bypass (EXPERIMENTAL/untested on-device)')
    ap.add_argument('--wrap', action='store_true', help='cert2 WRAP mode (default: OVERRIDE)')
    ap.add_argument('--no-thermal', action='store_true',
                    help='Skip thermal trip threshold patch')
    ap.add_argument('--dry-run', '-n', action='store_true',
                    help='Simulate, do not write output')
    ap.add_argument('--skip', '-s', nargs='+', metavar='PATCH',
                    help='Skip patches by name')
    ap.add_argument('--list', '-l', action='store_true',
                    help='Show patch plan without applying')
    args = ap.parse_args()

    if args.list:
        stages = ([] if args.no_thermal else thermal_patches(args.thermal)) + build_patches(args.big, args.volt, args.little)
        print(f"Plan  --big={args.big}  --little={args.little if args.little is not None else 2000}  --volt={args.volt}  --thermal={args.thermal}:")
        for s in stages:
            tag = 'noop ' if s.is_noop else 'PATCH'
            print(f"  [{tag}] {s.name}: {s.description}")
        return

    if not args.input:
        ap.print_help()
        sys.exit(1)

    output = args.output or args.input.replace('.img', '_oc.img')
    patch_image(
        args.input, output,
        big_mhz=args.big,
        volt_mv=args.volt,
        thermal_c=args.thermal,
        little_mhz=args.little,
        no_thermal=args.no_thermal,
        dry_run=args.dry_run,
        sign=args.sign,
        wrap=args.wrap,
        skip=args.skip,
    )


if __name__ == '__main__':
    main()
