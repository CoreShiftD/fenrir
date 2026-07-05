"""
patch_gpufreq.py — GPU OPP table patcher for mtk_gpufreq_mt6789.ko (MT6789)

 All patches always run (firmware identity validation). Stock value → replacement == pattern → NOOP.
 Supports overclock AND underclock.
 
 Usage:
     python3 patch_gpufreq.py                          # bypass patches only → stock_OC.ko
     python3 patch_gpufreq.py stock.ko out.ko          # explicit output name
     python3 patch_gpufreq.py --bp --oc 1200           # bypass + OPP to 1200 MHz (full OC)
     python3 patch_gpufreq.py --bp --oc 1300 --volt 850
     python3 patch_gpufreq.py --bp                     # bypass only (explicit, same as default)
     python3 patch_gpufreq.py --oc 1200                # OPP only, no code patches (advanced)
     python3 patch_gpufreq.py --dry-run
     python3 patch_gpufreq.py --list
 
 Flags:
     --bp       Apply bypass code/data patches (avs_freq_check, apply_adjust×2, segment_adj).
                Default ON when --oc absent. Pass with --oc for full OC (code + OPP).
                NOTE: segment_cap_bypass intentionally excluded — causes bootloop.
     --oc  MHZ  GPU ceiling MHz. Scales OPP entries + auto-scales voltage from OC curve.
     --volt MV  Ceiling voltage mV override (default: auto from OC curve when --oc given)
 
 ════════════════════════════════════════════════════════════════════
  BINARY LAYOUT  (mtk_gpufreq_mt6789.ko, stock 196672 bytes)
 ════════════════════════════════════════════════════════════════════
 
  OPP struct (24 bytes, little-endian):
    [freq_khz u32][volt u32][vsram u32][u3 u32][u4 u32][u5 u32]
    volt/vsram: 10uV units  (80000 = 800.00 mV)
    u3:  1 when freq >= 948 MHz, else 2
    u4:  1875 when freq >= 835 MHz | 1250 when >= 596 MHz | 625 below
    vsram: max(volt, 75000)  (750 mV floor)
 
  ┌─ OPP table (45 entries × 24 bytes) ────────────────────────────┐
  │ Stock range: 1100–390 MHz  (pattern source)                     │
  │ OC range:    1200–390 MHz  (default replacement)                │
  │ Voltage:     OC curve uniformly shifted by (ceil_volt - 800 mV) │
  └────────────────────────────────────────────────────────────────┘
 
    Code patches (4 total, all confirmed unique patterns):
   ┌─────────────────────────────────────────────────────────────────┐
   │ 1. avs_freq_check_bypass                                        │
   │    __gpufreq_avs_adjustment fn+0xcc                            │
   │    NOP b.ne  (skip efuse freq≠OPP abort on patched table)      │
   │                                                                 │
   │ 2. apply_adjust_probe_bypass                                    │
   │    __gpufreq_pdrv_probe fn+0x8b0                               │
   │    NOP bl  (__gpufreq_apply_adjust overwrites OPP table with   │
   │             efuse calibration data — removed in OC binary)     │
   │                                                                 │
   │ 3. apply_adjust_avs_bypass                                      │
   │    __gpufreq_avs_adjustment fn+0x2c8                           │
   │    NOP bl  (same function called again from AVS path)          │
   │                                                                 │
    │ 4. segment_adj_data                                             │
   │    .data g_segment_adj = 25 → 0                                │
   │    gpuppm_init uses this to set a runtime GPU ceiling via       │
   │    gpuppm. OC binary compiles this as 0 (uncapped).            │
   │                                                                 │
   │ NOT applied: segment_cap_bypass (b.hs→b.al in init_opp_idx)   │
   │    Forcing OPP idx=0 at boot → GPU jumps to table max freq     │
  │    before regulators stable → bootloop. g_segment_adj=0        │
  │    is sufficient; governor scales up after boot safely.        │
  └────────────────────────────────────────────────────────────────┘
 
  ⚠ RELOCATION ISSUE (fixed):
    The apply_adjust* patches NOP-out `bl __gpufreq_apply_adjust` calls,
    but kernel .ko files are relocatable ELF objects. The .rela.text.*
    sections still contain relocation entries targeting those call sites.
    When the kernel module loader processes relocations, it:
      a) Reads the instruction at r_offset — finds our NOP (0xd503201f)
      b) On AArch64, validates bits[31:26] == 100101 (BL opcode) → NOP
         fails the check → module load fails with -ENOEXEC → boot hang
    The fix: after patching .text, nullify the corresponding .rela entries
    by setting r_type = R_AARCH64_NONE (0). See nullify_bl_relocations().
 
 Stock OPP table (extracted from mtk_gpufreq_mt6789.ko @ 0x00bd10):
   Entry 0:  1100 MHz  900.00 mV
   Entry 44:  390 MHz  675.00 mV
 """

import sys
import struct
import argparse
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Core types  (same model as mcupm_devices.py)
# ─────────────────────────────────────────────────────────────────────────────

class MatchMode(Enum):
    FIRST = "first"
    ALL   = "all"
    EXACT = "exact"


@dataclass
class PatchStage:
    name:        str
    pattern:     str   # space-separated hex bytes
    replacement: str
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
# Stock table — source of truth for pattern bytes
# (freq_khz, volt, vsram, u3, u4, u5)  volt/vsram in 10uV units
# ─────────────────────────────────────────────────────────────────────────────

STOCK_TABLE = [
    (1100000, 90000, 90000, 1, 1875, 0),
    (1086000, 89375, 89375, 1, 1875, 0),
    (1072000, 88750, 88750, 1, 1875, 0),
    (1058000, 88125, 88125, 1, 1875, 0),
    (1045000, 87500, 87500, 1, 1875, 0),
    (1031000, 86875, 86875, 1, 1875, 0),
    (1017000, 86250, 86250, 1, 1875, 0),
    (1003000, 85625, 85625, 1, 1875, 0),
    ( 990000, 85000, 85000, 1, 1875, 0),
    ( 976000, 84375, 84375, 1, 1875, 0),
    ( 962000, 83125, 83125, 1, 1875, 0),
    ( 948000, 82500, 82500, 2, 1875, 0),
    ( 935000, 81875, 81875, 2, 1875, 0),
    ( 921000, 81250, 81250, 2, 1875, 0),
    ( 907000, 80625, 80625, 2, 1875, 0),
    ( 893000, 80000, 80000, 2, 1875, 0),
    ( 880000, 79375, 79375, 2, 1875, 0),
    ( 868000, 78750, 78750, 2, 1875, 0),
    ( 857000, 78125, 78125, 2, 1875, 0),
    ( 846000, 77500, 77500, 2, 1875, 0),
    ( 835000, 76875, 76875, 2, 1250, 0),
    ( 823000, 76250, 76250, 2, 1250, 0),
    ( 812000, 75625, 75625, 2, 1250, 0),
    ( 801000, 75625, 75625, 2, 1250, 0),
    ( 790000, 75000, 75000, 2, 1250, 0),
    ( 778000, 74375, 75000, 2, 1250, 0),
    ( 767000, 73750, 75000, 2, 1250, 0),
    ( 756000, 73125, 75000, 2, 1250, 0),
    ( 745000, 72500, 75000, 2, 1250, 0),
    ( 733000, 71875, 75000, 2, 1250, 0),
    ( 722000, 71250, 75000, 2, 1250, 0),
    ( 711000, 70625, 75000, 2, 1250, 0),
    ( 700000, 70000, 75000, 2, 1250, 0),
    ( 674000, 70000, 75000, 2, 1250, 0),
    ( 648000, 70000, 75000, 2, 1250, 0),
    ( 622000, 69375, 75000, 2, 1250, 0),
    ( 596000, 69375, 75000, 2,  625, 0),
    ( 570000, 69375, 75000, 2,  625, 0),
    ( 545000, 68750, 75000, 2,  625, 0),
    ( 519000, 68750, 75000, 2,  625, 0),
    ( 493000, 68750, 75000, 2,  625, 0),
    ( 467000, 68125, 75000, 2,  625, 0),
    ( 441000, 68125, 75000, 2,  625, 0),
    ( 415000, 68125, 75000, 2,  625, 0),
    ( 390000, 67500, 75000, 2,  625, 0),
]

# OC reference curve credited to @raffprjkt; used for default ceil/volt and voltage shape
OC_TABLE = [
    (1200000, 80000, 80000, 1, 1875, 0),
    (1186000, 79375, 79375, 1, 1875, 0),
    (1172000, 78750, 78750, 1, 1875, 0),
    (1158000, 78125, 78125, 1, 1875, 0),
    (1144000, 77500, 77500, 1, 1875, 0),
    (1130000, 76875, 76875, 1, 1875, 0),
    (1116000, 76250, 76250, 1, 1875, 0),
    (1086000, 76250, 76250, 1, 1875, 0),
    (1072000, 75625, 75625, 1, 1875, 0),
    (1058000, 75000, 75000, 1, 1875, 0),
    (1045000, 75000, 75000, 1, 1875, 0),
    (1031000, 74375, 75000, 1, 1875, 0),
    (1017000, 73750, 75000, 1, 1875, 0),
    (1003000, 73750, 75000, 1, 1875, 0),
    ( 990000, 73125, 75000, 1, 1875, 0),
    ( 976000, 72500, 75000, 1, 1875, 0),
    ( 962000, 72500, 75000, 1, 1875, 0),
    ( 948000, 71875, 75000, 2, 1875, 0),
    ( 935000, 71250, 75000, 2, 1875, 0),
    ( 921000, 71250, 75000, 2, 1875, 0),
    ( 907000, 70625, 75000, 2, 1875, 0),
    ( 893000, 70000, 75000, 2, 1875, 0),
    ( 880000, 70000, 75000, 2, 1875, 0),
    ( 868000, 69375, 75000, 2, 1875, 0),
    ( 857000, 68750, 75000, 2, 1875, 0),
    ( 846000, 68750, 75000, 2, 1875, 0),
    ( 835000, 68125, 75000, 2, 1875, 0),
    ( 823000, 68125, 75000, 2, 1250, 0),
    ( 812000, 67500, 75000, 2, 1250, 0),
    ( 801000, 67500, 75000, 2, 1250, 0),
    ( 790000, 66875, 75000, 2, 1250, 0),
    ( 778000, 66250, 75000, 2, 1250, 0),
    ( 767000, 66250, 75000, 2, 1250, 0),
    ( 756000, 65625, 75000, 2, 1250, 0),
    ( 745000, 65625, 75000, 2, 1250, 0),
    ( 733000, 65000, 75000, 2, 1250, 0),
    ( 722000, 65000, 75000, 2, 1250, 0),
    ( 711000, 64375, 75000, 2, 1250, 0),
    ( 700000, 63750, 75000, 2, 1250, 0),
    ( 674000, 63125, 75000, 2, 1250, 0),
    ( 648000, 62500, 75000, 2, 1250, 0),
    ( 622000, 61875, 75000, 2, 1250, 0),
    ( 596000, 60625, 75000, 2, 1250, 0),
    ( 570000, 60000, 75000, 2,  625, 0),
    ( 545000, 59375, 75000, 2,  625, 0),
]

N           = len(STOCK_TABLE)   # 45
STRIDE      = 24
VSRAM_FLOOR = 75000              # 750 mV in 10uV units
PMIC_STEP   = 625                # 6.25 mV in 10uV units

# Known OPP table offsets for mtk_gpufreq_mt6789.ko.
# Probed in order; first one whose first entry looks like a GPU freq wins.
# 0xbd10 = stock firmware, 0xbc10 = OC firmware (confirmed from local .ko).
DEFAULT_OPP_OFFSETS = [0xbd10, 0xbc10]
FLOOR_KHZ   = STOCK_TABLE[-1][0] # 390000 — hardcoded, matches stock bottom

OC_CEIL_KHZ  = OC_TABLE[0][0]   # 1200000
OC_CEIL_VOLT = OC_TABLE[0][1]   # 80000
OC_FLOOR_VOLT = OC_TABLE[-1][1] # 59375 — default floor volt (593.75 mV) at 390 MHz

# Voltage slope from OC curve (10uV per KHz) — for auto ceil-volt extrapolation
_OC_VOLT_SLOPE = (OC_TABLE[0][1] - OC_TABLE[-1][1]) / (OC_TABLE[0][0] - OC_TABLE[-1][0])


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _hx(b: bytes) -> str:
    return ' '.join(f'{x:02x}' for x in b)

def _pack(entry) -> str:
    return _hx(struct.pack('<6I', *entry))

def round_volt(v: float) -> int:
    return round(v / PMIC_STEP) * PMIC_STEP

def u3_for(khz: int) -> int:
    return 1 if khz >= 948000 else 2

def u4_for(khz: int) -> int:
    if khz >= 835000: return 1875
    if khz >= 596000: return 1250
    return 625

def auto_volt(khz: int) -> int:
    v = OC_CEIL_VOLT + (khz - OC_CEIL_KHZ) * _OC_VOLT_SLOPE
    return round_volt(max(50000, min(v, 100000)))

def probe_opp_offset(data: bytearray, candidates=DEFAULT_OPP_OFFSETS) -> Optional[int]:
    """Return first candidate whose first entry has a plausible GPU freq_khz."""
    for off in candidates:
        if off < 0 or off + STRIDE > len(data):
            continue
        freq = struct.unpack_from('<I', data, off)[0]
        if 200_000 <= freq <= 2_000_000 and freq % 1000 == 0:
            return off
    return None


def nullify_bl_relocations(data: bytearray, dry_run: bool = False) -> int:
    """Nullify .rela entries targeting patched `bl` instructions.

    After patching `bl __gpufreq_apply_adjust` → NOP in .text, scan
    every .rela section for entries whose r_offset falls within one
    of the NOP'd call sites and zero out r_info (→ R_AARCH64_NONE).
    Returns count of nullified entries.
    """
    # ── Locate .text base in file ──────────────────────────────────────
    if data[:4] != b'\x7fELF' or data[4] != 2:  # ELF64
        print("  WARN  Not an ELF64 file — skipping rela nullification")
        return 0

    # ELF64 header offsets
    e_shoff   = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsz = struct.unpack_from('<H', data, 0x3a)[0]
    e_shnum   = struct.unpack_from('<H', data, 0x3c)[0]
    e_shstrndx = struct.unpack_from('<H', data, 0x3e)[0]

    # Read .shstrtab to resolve section names
    shstr_ent_off = e_shoff + e_shstrndx * e_shentsz
    shstr_off = struct.unpack_from('<Q', data, shstr_ent_off + 0x18)[0]
    shstr_sz  = struct.unpack_from('<Q', data, shstr_ent_off + 0x20)[0]
    shstrtab  = data[shstr_off:shstr_off + shstr_sz]

    def _sec_name(idx: int) -> str:
        name_off = struct.unpack_from('<I', data, e_shoff + idx * e_shentsz)[0]
        return shstrtab[name_off:shstrtab.index(b'\x00', name_off)].decode('ascii', errors='replace')

    # Find .text section index and its file offset
    text_idx = None
    text_foff = 0
    for i in range(e_shnum):
        if _sec_name(i) == '.text':
            text_idx = i
            text_foff = struct.unpack_from('<Q', data, e_shoff + i * e_shentsz + 0x18)[0]
            break
    if text_idx is None:
        print("  WARN  .text section not found — skipping rela nullification")
        return 0

    # Build list of patched-bl .text-relative offsets by scanning for
    # NOP bytes (1f 20 03 d5) that used to be `bl` (00 00 00 94).
    # We look for the 12-byte apply_adjust patterns with NOP in the last 4.
    nop_bl_ranges = []   # list of (r_offset_start, r_offset_end_exclusive)
    bl_patterns = [
        bytes.fromhex('e0 03 14 aa e1 03 13 2a 1f 20 03 d5'),
        bytes.fromhex('61 00 80 52 e0 03 13 aa 1f 20 03 d5'),
    ]
    for pat in bl_patterns:
        pos = 0
        while True:
            pos = data.find(pat, pos)
            if pos < 0:
                break
            # Convert file offset → .text-relative offset
            bl_text_off = pos - text_foff
            # The NOP occupies the last 4 bytes of the 12-byte pattern
            nop_start = bl_text_off + 8   # bytes 8-11 have the NOP
            nop_bl_ranges.append((nop_start, nop_start + 4))
            pos += 1

    # ── Known-patched non-BL ranges ─────────────────────────────────────

    if not nop_bl_ranges:
        return 0   # nothing to nullify

    # ── Iterate .rela sections, nullify matching entries ───────────────
    nullified = 0
    for i in range(e_shnum):
        name = _sec_name(i)
        if not name.startswith('.rela'):
            continue
        ent_off = e_shoff + i * e_shentsz
        sh_type   = struct.unpack_from('<I', data, ent_off + 4)[0]
        if sh_type != 4:     # SHT_RELA
            continue
        sh_offset = struct.unpack_from('<Q', data, ent_off + 0x18)[0]
        sh_size   = struct.unpack_from('<Q', data, ent_off + 0x20)[0]
        sh_info   = struct.unpack_from('<I', data, ent_off + 0x2c)[0]

        # Does this .rela section target .text?
        if sh_info != text_idx:
            continue

        for j in range(0, sh_size, 24):
            r_off  = struct.unpack_from('<Q', data, sh_offset + j)[0]
            for nop_start, nop_end in nop_bl_ranges:
                if nop_start <= r_off < nop_end:
                    # Nullify r_info → R_AARCH64_NONE
                    tag = 'DRY ' if dry_run else 'OK  '
                    if not dry_run:
                        data[sh_offset + j + 8 : sh_offset + j + 16] = b'\x00' * 8
                    print(f"  {tag:12s} rela[{j//24}] @ {name}: r_offset=.text+0x{r_off:x} → R_AARCH64_NONE")
                    nullified += 1
                    break

    return nullified


# ─────────────────────────────────────────────────────────────────────────────
# Patch builder
# ─────────────────────────────────────────────────────────────────────────────

def build_patches(ceil_khz: Optional[int], ceil_volt: Optional[int],
                  floor_volt: Optional[int] = None) -> List[PatchStage]:
    """
    Build all PatchStages.

    Code patches:
      avs_freq_check_bypass, segment_adj_data  (always when apply_bp is set).
      apply_adjust_probe_bypass, apply_adjust_avs_bypass  (only when ceil_khz is set,
        because they prevent efuse voltage calibration — without OC the uncalibrated
        voltages can cause GPU hangs).

    OPP table (45 stages, only when ceil_khz is not None):
      Pattern = stock bytes (identity check).
      Voltage mode:
        floor_volt given → linear interp between ceil_volt@OPP[0] and floor_volt@OPP[44].
        floor_volt None  → OC curve at scaled freq, shifted so OPP[0] == ceil_volt.
      When ceil_khz is None: pattern == replacement → NOOP on all OPP entries.

    All stages always run; stock value → replacement == pattern → NOOP.
    """
    if ceil_khz is not None:
        _fv          = floor_volt if floor_volt is not None else OC_FLOOR_VOLT
        _stock_range = STOCK_TABLE[0][0] - FLOOR_KHZ  # 710000
        _new_range   = ceil_khz          - FLOOR_KHZ
    else:
        _fv = _stock_range = _new_range = 0

    stages = []

    # NOTE: segment_cap_bypass (b.hs→b.al in __gpufreq_init_opp_idx) is intentionally
    # NOT applied. That patch forces OPP idx=0 during driver init, causing the GPU to
    # immediately attempt the table max frequency (1100+ MHz) before regulators/clocks
    # are stable → bootloop. The OC .ko never needs this because its device efuse
    # naturally returns a freq ≥ table max. For our device, the efuse-limited idx (~7)
    # is the safe starting point. g_segment_adj=0 (patch below) handles the runtime cap.

    # ── AVS freq validation bypass ───────────────────────────────────────────
    # __gpufreq_avs_adjustment fn+0xcc:
    #   cmp w4,w5      <- avs_efuse_freq vs opp_table_freq
    #   b.ne abort     <- abort if mismatch — fires because our patched
    #                     OPP freqs differ from what the device efuse expects
    #   NOP            <- patch: skip abort, let AVS continue with volt adjust
    stages.append(PatchStage(
        name='avs_freq_check_bypass',
        pattern    ='9f 00 05 6b 21 22 00 54',
        replacement='9f 00 05 6b 1f 20 03 d5',
        match_mode=MatchMode.EXACT,
        description='__gpufreq_avs_adjustment: NOP b.ne, bypass efuse freq≠OPP abort',
    ))

    # ── apply_adjust bypass (probe) ──────────────────────────────────────────
    # __gpufreq_pdrv_probe fn+0x8b0:
    #   mov x0, x20  ; mov w1, w19 ; bl __gpufreq_apply_adjust
    #   This overwrites OPP table entries with efuse calibration data,
    #   undoing our frequency/voltage patches. OC binary removes this call.
    stages.append(PatchStage(
        name='apply_adjust_probe_bypass',
        pattern    ='e0 03 14 aa e1 03 13 2a 00 00 00 94',
        replacement='e0 03 14 aa e1 03 13 2a 1f 20 03 d5',
        match_mode=MatchMode.EXACT,
        description='__gpufreq_pdrv_probe: NOP bl __gpufreq_apply_adjust (efuse overwrite)',
    ))

    # ── apply_adjust bypass (AVS path) ───────────────────────────────────────
    # __gpufreq_avs_adjustment fn+0x2c8:
    #   mov w1, #3 ; mov x0, x19 ; bl __gpufreq_apply_adjust
    #   Same function called again from the AVS path. Same fix.
    stages.append(PatchStage(
        name='apply_adjust_avs_bypass',
        pattern    ='61 00 80 52 e0 03 13 aa 00 00 00 94',
        replacement='61 00 80 52 e0 03 13 aa 1f 20 03 d5',
        match_mode=MatchMode.EXACT,
        description='__gpufreq_avs_adjustment: NOP bl __gpufreq_apply_adjust (efuse overwrite)',
    ))

    # ── g_segment_adj data patch ─────────────────────────────────────────────
    # .data g_segment_adj = 25 in stock, 0 in OC.
    # gpuppm_init reads this compiled-in value and passes it to gpuppm_set_limit
    # as a GPU ceiling OPP index — caps the device even after segment bypass.
    # OC ships with 0 (fully uncapped). Unique 12-byte forward pattern required.
    stages.append(PatchStage(
        name='segment_adj_data',
        pattern    ='19 00 00 00 00 00 00 00 e8 fd 00 00',
        replacement='00 00 00 00 00 00 00 00 e8 fd 00 00',
        match_mode=MatchMode.EXACT,
        description='g_segment_adj: 25→0, remove gpuppm GPU ceiling (matches OC compiled value)',
    ))

    # ── OPP table entries ────────────────────────────────────────────────────
    for i, (s_f, s_v, s_vs, s_u3, s_u4, s_u5) in enumerate(STOCK_TABLE):
        pat = _pack((s_f, s_v, s_vs, s_u3, s_u4, s_u5))

        if ceil_khz is None:
            # No --oc: leave OPP table at stock values (NOOP)
            rep  = pat
            desc = f'OPP[{i:02d}] {s_f//1000} MHz  {s_v/100:.2f} mV  (stock, no --oc)'
        else:
            # Scale freq from stock ladder position — preserves uniform stock steps, no OC gap artifacts
            ratio = (s_f - FLOOR_KHZ) / _stock_range
            new_f = round((FLOOR_KHZ + ratio * _new_range) / 1000) * 1000
            # Voltage: linear interp — OPP[0]=ceil_volt, OPP[44]=_fv (floor_volt or OC_FLOOR_VOLT)
            ratio_v = (new_f - FLOOR_KHZ) / (ceil_khz - FLOOR_KHZ)
            new_v   = round_volt(_fv + ratio_v * (ceil_volt - _fv))
            new_v  = max(50000, new_v)
            new_vs = max(new_v, VSRAM_FLOOR)
            rep    = _pack((new_f, new_v, new_vs, u3_for(new_f), u4_for(new_f), 0))
            s_mhz, new_mhz = s_f // 1000, new_f // 1000
            if pat == rep:
                desc = f'OPP[{i:02d}] {s_mhz} MHz  {s_v/100:.2f} mV  (stock)'
            else:
                desc = f'OPP[{i:02d}] {s_mhz} → {new_mhz} MHz  {s_v/100:.2f} → {new_v/100:.2f} mV'

        stages.append(PatchStage(
            name=f'opp_{i:02d}',
            pattern=pat,
            replacement=rep,
            match_mode=MatchMode.EXACT,
            description=desc,
        ))

    return stages


# ─────────────────────────────────────────────────────────────────────────────
# Patcher engine  (same as mcupm_devices.py)
# ─────────────────────────────────────────────────────────────────────────────

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
            f'[{stage.name}] EXACT match required, found {count} occurrence(s). '
            f'Firmware may differ from expected revision.'
        )
    return count


def write_opp_table_at(data: bytearray, base: int,
                       ceil_khz: int, ceil_volt: int,
                       floor_volt: Optional[int] = None,
                       dry_run: bool = False) -> None:
    """Write OPP entries directly at base offset — no pattern matching needed.
    Used when --offset is given so re-patching already-patched files works."""
    _fv          = floor_volt if floor_volt is not None else OC_FLOOR_VOLT
    _stock_range = STOCK_TABLE[0][0] - FLOOR_KHZ
    _new_range   = ceil_khz          - FLOOR_KHZ
    for i, (s_f, *_) in enumerate(STOCK_TABLE):
        ratio = (s_f - FLOOR_KHZ) / _stock_range
        new_f = round((FLOOR_KHZ + ratio * _new_range) / 1000) * 1000
        ratio_v = (new_f - FLOOR_KHZ) / (ceil_khz - FLOOR_KHZ)
        new_v   = round_volt(_fv + ratio_v * (ceil_volt - _fv))
        new_v  = max(50000, new_v)
        new_vs = max(new_v, VSRAM_FLOOR)
        entry  = struct.pack('<6I', new_f, new_v, new_vs, u3_for(new_f), u4_for(new_f), 0)
        off = base + i * STRIDE
        tag = 'DRY ' if dry_run else 'OK  '
        print(f"  {tag} opp_{i:02d}: {new_f//1000} MHz  {new_v/100:.2f} mV")
        if not dry_run:
            data[off:off+STRIDE] = entry


def patch_ko(input_path: str, output_path: str,
             ceil_khz: Optional[int], ceil_volt: Optional[int],
             floor_volt: Optional[int] = None,
             apply_bp: bool = True,
             opp_offset: Optional[int] = None,
             dry_run: bool = False,
             skip: Optional[List[str]] = None) -> None:
    raw  = open(input_path, 'rb').read()
    data = bytearray(raw)
    skip = skip or []

    print(f"Input : {input_path}  ({len(raw)} bytes)")
    print(f"Bypass: {'yes' if apply_bp else 'no (--oc only)'}")
    if ceil_khz is not None:
        _fv_show = floor_volt if floor_volt is not None else OC_FLOOR_VOLT
        print(f"OC    : {ceil_khz//1000} MHz  {ceil_volt/100:.2f} mV  →  {FLOOR_KHZ//1000} MHz  {_fv_show/100:.2f} mV{' (default)' if floor_volt is None else ''}")
        if opp_offset is not None:
            print(f"Offset: 0x{opp_offset:x}  (manual — skipping OPP pattern match)")
        else:
            auto = probe_opp_offset(data)
            if auto is not None:
                opp_offset = auto
                print(f"Offset: 0x{opp_offset:x}  (auto-detected from defaults {[hex(x) for x in DEFAULT_OPP_OFFSETS]})")
            else:
                print(f"Offset: (none — using pattern match)")
    else:
        print(f"OC    : (none — stock OPP table)")
    print()

    stages = build_patches(None, None)  # code patches only — no OPP stages
    errors = []

    for stage in stages:
        if stage.name in skip or stage.name.startswith('opp_'):
            continue
        if not apply_bp:
            continue
        # apply_adjust* NOPs prevent efuse voltage calibration — only safe
        # when --oc modifies the OPP table. Without OC, they cause boot failure.
        if stage.name.startswith('apply_adjust') and ceil_khz is None:
            continue
        try:
            n = apply_patch(data, stage)
            tag = 'NOOP ' if stage.is_noop else f"{'DRY ' if dry_run else ''}OK  ({n})"
            print(f"  {tag:12s} {stage.description}")
        except Exception as e:
            errors.append((stage.name, str(e)))
            print(f"  FAIL         {stage.name}: {e}")

    # OPP table
    if ceil_khz is not None:
        if opp_offset is not None:
            # Direct write — works on already-patched files too
            write_opp_table_at(data, opp_offset, ceil_khz, ceil_volt, floor_volt, dry_run)
        else:
            # Pattern-matched write — requires stock bytes (first-time patch)
            opp_stages = build_patches(ceil_khz, ceil_volt, floor_volt)
            opp_stages = [s for s in opp_stages if s.name.startswith('opp_')]
            for stage in opp_stages:
                if stage.name in (skip or []):
                    continue
                try:
                    n = apply_patch(data, stage)
                    tag = 'NOOP ' if stage.is_noop else f"{'DRY ' if dry_run else ''}OK  ({n})"
                    print(f"  {tag:12s} {stage.description}")
                except Exception as e:
                    errors.append((stage.name, str(e)))
                    print(f"  FAIL         {stage.name}: {e}")

    # ── Nullify .rela entries for patched `bl` instructions ──────────
    # Without this, the kernel module loader's relocation pass overwrites
    # our NOPs with the resolved function addresses (the .rela section
    # still contains entries targeting those offsets).
    n_rela = nullify_bl_relocations(data, dry_run)
    if n_rela:
        print(f"  Rela        {n_rela} relocation(s) nullified (R_AARCH64_NONE)")

    print()
    if errors:
        print(f"WARNING: {len(errors)} patch(es) failed — output NOT written.")
        for name, msg in errors:
            print(f"  {name}: {msg}")
        sys.exit(1)

    if not dry_run:
        open(output_path, 'wb').write(data)
        print(f"Output: {output_path}")
    else:
        print("Dry run — no file written.")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def _default_output(input_path: str) -> str:
    import os
    base = os.path.basename(input_path)
    stem, ext = (base.rsplit('.', 1) + [''])[:2]
    out = f"{stem}_OC.{ext}" if ext else f"{stem}_OC"
    return os.path.join(os.path.dirname(input_path) or '.', out)


def main() -> None:
    ap = argparse.ArgumentParser(
        description='GPU OPP table patcher for mtk_gpufreq_mt6789.ko',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s stock.ko                         # bypass patches only (default) → stock_OC.ko
  %(prog)s stock.ko out.ko                  # explicit output name
  %(prog)s stock.ko --oc 1200               # OPP table only, no bypass patches
  %(prog)s stock.ko --bp --oc 1200          # bypass + OPP to 1200 MHz
  %(prog)s stock.ko --bp                    # bypass only (explicit, same as default)
  %(prog)s stock.ko --oc 1300 --volt 850    # OPP only, 1300 MHz / 850 mV ceiling
  %(prog)s stock.ko --dry-run
  %(prog)s stock.ko --list
        """)
    ap.add_argument('input', nargs='?', default='mtk_gpufreq_mt6789.ko',
                    help='Stock .ko input path (default: mtk_gpufreq_mt6789.ko)')
    ap.add_argument('output', nargs='?',
                    help='Output path (default: <input>_OC.ko)')
    ap.add_argument('--bp', action='store_true',
                    help='Apply bypass code/data patches (avs_freq_check, apply_adjust x2, '
                         'segment_adj_data). Default ON when --oc is absent. '
                         'Pass --bp with --oc to apply both.')
    ap.add_argument('--oc',   type=int,   metavar='MHZ',
                    help='GPU ceiling MHz. Scales all OPP entries + auto-scales voltage '
                         'from OC reference curve. Use --bp --oc N to apply both together.')
    ap.add_argument('--volt', type=float, metavar='MV',
                    help='OPP[0] ceiling voltage mV (default: auto from OC curve)')
    ap.add_argument('--floor-volt', type=float, metavar='MV',
                    help=f'OPP[44] floor voltage mV (default: {OC_FLOOR_VOLT/100:.2f} mV — OC table bottom)')
    ap.add_argument('--offset', type=lambda x: int(x, 0), metavar='HEX',
                    help='OPP table file offset (e.g. 0xbd10). Bypasses pattern matching — '
                         'use to re-patch an already-patched file or for non-stock firmware.')
    ap.add_argument('--dry-run', '-n', action='store_true',
                    help='Simulate — show patch plan without writing output')
    ap.add_argument('--skip',    '-s', nargs='+', metavar='PATCH',
                    help='Skip patches by name (e.g. opp_00)')
    ap.add_argument('--list',    '-l', action='store_true',
                    help='Show patch plan without applying')
    args = ap.parse_args()

    ceil_khz  = args.oc * 1000 if args.oc else None
    ceil_volt = None
    floor_volt = None

    if ceil_khz is not None:
        if ceil_khz <= FLOOR_KHZ:
            ap.error(f'--oc ({args.oc}) must be > {FLOOR_KHZ//1000} (hardcoded floor)')
        ceil_volt  = round_volt(args.volt * 100) if args.volt else auto_volt(ceil_khz)
        floor_volt = round_volt(getattr(args, 'floor_volt') * 100) if getattr(args, 'floor_volt', None) else None
    elif args.volt or getattr(args, 'floor_volt', None):
        ap.error('--volt / --floor-volt require --oc')

    # bypasses ON by default (no args); explicit --bp overrides; --oc alone skips bypasses
    apply_bp = args.bp or (ceil_khz is None)

    output = args.output or (None if args.dry_run else _default_output(args.input))

    if args.list:
        _fv = floor_volt if floor_volt is not None else OC_FLOOR_VOLT
        stages = build_patches(ceil_khz, ceil_volt, floor_volt)
        bp_str = 'bypass+OPP' if (apply_bp and ceil_khz) else ('bypass only' if apply_bp else 'OPP only')
        oc_str = (f"--oc={ceil_khz//1000}  --volt={ceil_volt/100:.2f}mV"
                  f"  --floor-volt={_fv/100:.2f}mV{'(default)' if floor_volt is None else ''}") if ceil_khz else "(no OPP)"
        print(f"Plan  [{bp_str}]  {oc_str}:")
        for s in stages:
            if s.name.startswith('opp_') and not ceil_khz:
                continue
            if not s.name.startswith('opp_') and not apply_bp:
                continue
            if s.name.startswith('apply_adjust') and ceil_khz is None:
                continue
            tag = 'noop ' if s.is_noop else 'PATCH'
            print(f"  [{tag}] {s.description}")
        return

    patch_ko(args.input, output or '/dev/null',
             ceil_khz, ceil_volt,
             floor_volt=floor_volt,
             apply_bp=apply_bp,
             opp_offset=args.offset,
             dry_run=args.dry_run,
             skip=args.skip)


if __name__ == '__main__':
    main()
