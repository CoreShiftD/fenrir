# MT6789 (fenrir) GPU overclock — mtk_gpufreq_mt6789.ko full map

SoC: MediaTek MT6789 (Helio G99) — Mali-G57 MC2 GPU.
Device slot: `_a`.

---

## 0. TL;DR — the OC chain

GPU DVFS on this device is governed entirely by `mtk_gpufreq_mt6789.ko` (a vendor
kernel module loaded from vendor_dlkm). Unlike CPU DVFS (§CPU_OC_CHAIN_NOTES.md),
which reads OPP anchors from MCUPM SRAM, the GPU driver carries its own **static
OPP table** compiled into `.data` plus code-level efuse checks and calibration
calls.

```
 mtk_gpufreq_mt6789.ko
   ├── .data  OPP table  (45 entries × 24 B = 1080 B)
   │     freq_khz, volt_10uv, vsram_10uv, u3, u4, u5
   │     Stock: 1100–390 MHz, 900.00–675.00 mV
   │     OC:    up to 1200+ MHz, voltage from OC reference curve
   │
   ├── __gpufreq_pdrv_probe
   │     calls __gpufreq_apply_adjust  (efuse calibration → overwrites OPP)
   │     ╰── patch: NOP the bl → preserve OPP table
   │
   ├── __gpufreq_avs_adjustment
   │     ├── cmp avs_efuse_freq vs opp_table_freq
   │     │   ╰── patch: NOP b.ne → skip abort on freq mismatch
   │     └── calls __gpufreq_apply_adjust (again)
   │         ╰── patch: NOP the bl → preserve OPP table
   │
   ├── gpuppm_init
   │     reads g_segment_adj from .data → gpuppm_set_limit(OPP_idx)
   │     stock: 25 → caps at idx 25 (~778 MHz)
   │     ╰── patch: g_segment_adj = 0 → uncapped
   │
   └── __gpufreq_init_opp_idx
         b.hs → cap OPP idx to efuse segment limit at boot
         ╰── NOT patched: forcing idx=0 before regulators stable → bootloop
```

**Only one file needs editing:** `mtk_gpufreq_mt6789.ko` from the device's
`vendor_dlkm` partition inside `super` (`/vendor_dlkm/lib/modules/`).
No firmware partitions (MCUPM, SSPM, PI_IMG) are involved in GPU DVFS.

---

## 1. Binary layout

File: `mtk_gpufreq_mt6789.ko`
Format: ELF64 relocatable, AArch64, not stripped
Stock size: 196 672 bytes
Stock BuildID: `7c14c222025c4ffdecf69f3d624dd8fac76a590d`

### Section map

| section | offset | size | content |
|---------|--------|------|---------|
| `.text` | 0x1000 | 36888 | AArch64 code |
| `.data` | 0xb778 | 5432 | OPP table + g_segment_adj + misc |
| `.rodata` | 0xccb0 | 7140 | read-only data |
| `.rela.text.*` | 0xfe88 | 54096 | **relocations for .text (2254 entries)** |
| `__versions` | 0xeac0 | 3904 | CRC checksums for imported kernel symbols |
| `.symtab` | 0x242e0 | 32160 | symbol table |
| `.strtab` | 0x2c211 | 13737 | symbol names |

### OPP struct (24 bytes, little-endian)

```
offset  field     type   description
------  -----     ----   -----------
+0      freq_khz  u32    frequency in kHz  (e.g. 1100000 = 1100 MHz)
+4      volt      u32    voltage in 10 µV units  (90000 = 900.00 mV)
+8      vsram     u32    SRAM voltage, same unit  (max(volt, 75000))
+12     u3        u32    1 when freq >= 948 MHz, else 2
+16     u4        u32    1875 when >= 835 MHz | 1250 when >= 596 MHz | 625 below
+20     u5        u32    always 0
```

### Stock OPP table @ 0xbd10  (.data + 0x598)

45 entries, linearly stepped from 1100 MHz down to 390 MHz:

```
[00] 1100 MHz  900.00 mV  [01] 1086 MHz  893.75 mV  [02] 1072 MHz  887.50 mV
[03] 1058 MHz  881.25 mV  [04] 1045 MHz  875.00 mV  [05] 1031 MHz  868.75 mV
[06] 1017 MHz  862.50 mV  [07] 1003 MHz  856.25 mV  [08]  990 MHz  850.00 mV
[09]  976 MHz  843.75 mV  [10]  962 MHz  831.25 mV  [11]  948 MHz  825.00 mV
... (all 45 entries in patch_gpufreq.py STOCK_TABLE)
[44]  390 MHz  675.00 mV
```

OPP base offset within `.data` is preserved across builds: **always `.data + 0x598`**.
Different firmware revisions shift the file offset because `.text` size changes.

---

## 2. Code bypass patches

### 2a. `avs_freq_check_bypass` — NOP the efuse-frequency mismatch abort

**File offset:** 0x96f8 (.text + 0x86f8)

```
Stock:  9f 00 05 6b          cmp  w4, w5
        21 22 00 54          b.ne  abort         # efuse freq ≠ OPP freq → skip entry
Patch:  9f 00 05 6b          cmp  w4, w5
        1f 20 03 d5          nop                  # always continue
```

At `__gpufreq_avs_adjustment + 0xcc`, the driver compares the hardware efuse
GPU ceiling frequency against each OPP entry and aborts entries that exceed it.
After we raise the OPP table frequencies, every entry above the efuse cap would
be skipped — making the OC table half-empty. NOP-ing the `b.ne` forces all
entries through, leaving only the voltage to be calibrated by the AVS path.

This is a **within-function conditional branch** — no ELF relocation needed.

### 2b. `apply_adjust_probe_bypass` — NOP the probe-time efuse calibration call

**File offset:** 0x8d9c (.text + 0x7d9c)

```
Stock:  e0 03 14 aa          mov  x0, x20
        e1 03 13 2a          mov  w1, w19
        00 00 00 94          bl   __gpufreq_apply_adjust   # ← placeholder
Patch:  e0 03 14 aa          mov  x0, x20
        e1 03 13 2a          mov  w1, w19
        1f 20 03 d5          nop
```

At `__gpufreq_pdrv_probe + 0x8b0`, the driver calls `__gpufreq_apply_adjust`,
which overwrites OPP table entries with efuse calibration data. This undoes
our frequency and voltage changes. The OC firmware build removes this call
entirely.

**This is a `bl` with a relocation entry.** See §3.

### 2c. `apply_adjust_avs_bypass` — same call again from the AVS adjustment path

**File offset:** 0x98f0 (.text + 0x88f0)

```
Stock:  61 00 80 52          mov  w1, #3
        e0 03 13 aa          mov  x0, x19
        00 00 00 94          bl   __gpufreq_apply_adjust   # ← placeholder
Patch:  61 00 80 52          mov  w1, #3
        e0 03 13 aa          mov  x0, x19
        1f 20 03 d5          nop
```

Same function, called again from the AVS path during runtime voltage tuning.
Same fix.

### 2d. `segment_adj_data` — zero the gpuppm OPP ceiling

**File offset:** 0xbf70 (.data segment)

```
Stock:  19 00 00 00  →  g_segment_adj = 25
Patch:  00 00 00 00  →  g_segment_adj = 0
```

`gpuppm_init` reads `g_segment_adj` from `.data` and passes it to
`gpuppm_set_limit` as a GPU ceiling OPP index. Stock value 25 caps the
device at roughly OPP[25] = ~778 MHz even if higher entries exist. The OC
firmware compiles with 0 (uncapped).

The next 8 bytes (`00 00 00 00 e8 fd 00 00`) are also captured in the
pattern as a forward-uniqueness guard.

### 2e. NOT applied: `segment_cap_bypass` — would cause bootloop

At `__gpufreq_init_opp_idx`: the driver picks the boot-time OPP index from
efuse segment data and enforces a hardware min via `b.hs`. Patching this
to `b.al` (always-taken) forces OPP index 0 = table max at boot, before
regulators/clocks are stable → GPU powers up at 1100+ MHz cold → bootloop.

`g_segment_adj = 0` (§2d) is sufficient: the governor freely scales up
after boot without the init-time jump.

---

## 3. Critical: ELF relocation overwrites NOP patches

### The problem

This is the bug that made the patched `.ko` fail to boot. Kernel `.ko` files
are relocatable ELF objects — the `bl` instruction at each call site is a
placeholder (`00 00 00 94` = `bl #0`), and the real target address is written
by the kernel module loader **after** loading the file into memory.

The relocation entries are stored in `.rela.text.gpufreq_set_history_state`
(2254 entries × 24 B = 54 096 B). Two entries target our patch sites:

```
rela[1891]  r_offset=.text+0x7da4  r_type=R_AARCH64_CALL26  → __gpufreq_apply_adjust
rela[2116]  r_offset=.text+0x88f8  r_type=R_AARCH64_CALL26  → __gpufreq_apply_adjust
```

When the kernel's `apply_relocate_add()` runs (kernel/5.10-android12,
`arch/arm64/kernel/insn.c`):

1. Reads 4 bytes at `r_offset` — finds our NOP (`0xd503201f`)
2. Checks `(*insn & 0x7c000000) != 0x14000000` — NOP has bits[31:26] = 110101
   (HINT), but BL requires 100101
3. Returns `-EINVAL` → `apply_relocate_add` returns `-ENOEXEC`
4. **Module load fails entirely** → GPU driver never loads

The NOP itself would also have been overwritten even if the check passed,
because the relocation writes the resolved `bl` target into those bytes.

### The fix

`nullify_bl_relocations()` in `patch_gpufreq.py` scans every `.rela.*` section
in the ELF after patching `.text`, and zeroes `r_info` for entries whose
`r_offset` falls within a NOP'd `bl` site. Setting `r_type = 0 =
R_AARCH64_NONE` causes the loader to skip the entry.

ELF64 RELA entry before nullification:
```
r_info  = 0x000000570401001b    # r_type=0x11b (283, CALL26), r_sym=1111
r_addend = 0x00000000000084dc
```

After nullification:
```
r_info  = 0x0000000000000000    # r_type=0 (R_AARCH64_NONE)
r_addend = 0x00000000000084dc   # left as-is (not read when type=NONE)
```

**Patches not affected:** `avs_freq_check` is a within-function conditional
branch (no relocation), and `segment_adj_data` modifies `.data` directly
(the `.rela` sections cover only `.text`).

---

## 4. OPP voltage model

All voltages in 10 µV units (90000 = 900.00 mV). PMIC step = 625 (6.25 mV).

### OC reference curve

Credited to @raffprjkt. Each frequency maps to a proven voltage:

```
1200 MHz  800.00 mV    1186 MHz  793.75 mV    1172 MHz  787.50 mV
1158 MHz  781.25 mV    1144 MHz  775.00 mV    1130 MHz  768.75 mV
1116 MHz  762.50 mV    1086 MHz  762.50 mV    1072 MHz  756.25 mV
1058 MHz  750.00 mV    1045 MHz  750.00 mV    1031 MHz  743.75 mV
...down to 390 MHz → 593.75 mV (OC floor)
```

The voltage slope `ΔV / Δf` across the OC curve is:

```
(80000 - 59375) / (1200000 - 390000) = 20625 / 810000 ≈ 0.02546  (10µV/kHz)
```

### Voltage scaling logic

When `--oc <MHz>` is given without `--volt`:

```
ceil_volt = auto_volt(ceil_khz)  ≈ 80000 at 1200 MHz (from OC curve)
floor_volt = OC_FLOOR_VOLT = 59375  (593.75 mV at 390 MHz)

For each OPP entry at frequency f:
  ratio = (f - 390000) / (ceil_khz - 390000)
  volt = round_to_pmic(floor_volt + ratio × (ceil_volt - floor_volt))
  vsram = max(volt, 75000)
```

The `--volt` flag overrides `ceil_volt`; `--floor-volt` overrides the floor.
This lets you set, e.g., 1200 MHz at 850 mV for stability margin.

### Field derivation rules

| field | rule |
|-------|------|
| `u3` | `1` when freq >= 948 MHz, else `2` |
| `u4` | `1875` when >= 835 MHz, `1250` when >= 596 MHz, else `625` |
| `vsram` | `max(volt, 75000)` — 750 mV floor |
| `u5` | always `0` |

---

## 5. Using the patcher

```bash
cd injector/

# Bypass patches only (avs_freq_check + segment_adj_data, stock OPP)
python3 patch_gpufreq.py stock.ko

# Full OC: bypass + 1200 MHz OPP table
python3 patch_gpufreq.py stock.ko --bp --oc 1200

# Full OC with custom voltage
python3 patch_gpufreq.py stock.ko --bp --oc 1200 --volt 850

# Full OC + custom floor voltage (higher bottom = less voltage swing)
python3 patch_gpufreq.py stock.ko --bp --oc 1200 --floor-volt 650

# OPP only, no code patches (for advanced users)
python3 patch_gpufreq.py stock.ko --oc 1200

# Dry run: show what would be patched
python3 patch_gpufreq.py stock.ko --bp --oc 1200 --dry-run

# Re-patch an already-patched file at known offset
python3 patch_gpufreq.py stock.ko --bp --oc 1200 --offset 0xbd10
```

Output: `<input>_OC.ko` (e.g., `mtk_gpufreq_mt6789_OC.ko`)

`--bp` is **ON by default when `--oc` is absent**; you must pass `--bp`
explicitly with `--oc` to get both code bypasses and OPP changes.

---

## 6. Integration with build system

In `injector/devices.py`, the `gpufreq` firmware block controls GPU OC:

```python
'gpufreq': {
    'bp': True,        # apply code bypass patches
    'oc': 1200,        # OPP ceiling MHz (or None for stock)
    'volt': 800,       # mV @ ceiling (or None for auto)
    'floor_volt': None # mV @ floor (or None for OC curve default)
}
```

When `build.sh --firmware` is called, `patch_firmware.py` reads this block
and runs `patch_gpufreq.py` with the corresponding flags.

---

## 7. Reference: /opt/tmp/mtk_gpufreq_mt6789.ko (other firmware build)

This file (195 192 B, BuildID `a2f52073`) is a **different firmware revision**
sharing the same module name but compiled from different source. Key differences:

| property | stock (bin/firmware/a75) | /opt/tmp reference |
|----------|--------------------------|-------------------|
| File size | 196 672 B | 195 192 B |
| BuildID | `7c14c222` | `a2f52073` |
| `.text` size | 36888 | 36632 |
| `.data` base | 0xb778 | 0xb678 |
| OPP file offset | 0xbd10 (.data+0x598) | 0xbc10 (.data+0x598) |
| OPP[0] | 1100 MHz / 900.00 mV | 1200 MHz / 800.00 mV |
| OPP[44] | 390 MHz / 675.00 mV | 441 MHz / 556.25 mV |
| Code bypasses applied? | No | No |

Both use `.data + 0x598` for the OPP table base — the relationship is preserved
across builds.

---

## 8. Verification checklist

After patching, confirm on the output `.ko`:

```
1. Stock patterns removed:
   avs_freq_check     9f 00 05 6b 21 22 00 54       → 0 occurrences
   apply_adjust_probe e0 03 14 aa e1 03 13 2a 00 00 00 94 → 0
   apply_adjust_avs   61 00 80 52 e0 03 13 aa 00 00 00 94 → 0
   segment_adj        19 00 00 00 00 00 00 00 e8 fd 00 00 → 0

2. Replacement patterns present:
   avs_freq_check     9f 00 05 6b 1f 20 03 d5       → 1
   apply_adjust_probe e0 03 14 aa e1 03 13 2a 1f 20 03 d5 → 1
   apply_adjust_avs   61 00 80 52 e0 03 13 aa 1f 20 03 d5 → 1
   segment_adj        00 00 00 00 00 00 00 00 e8 fd 00 00 → 1

3. Relocations nullified:
   .rela entry @ r_offset=.text+0x7da4: r_info = 0x0000000000000000
   .rela entry @ r_offset=.text+0x88f8: r_info = 0x0000000000000000

4. OPP[0] = desired ceiling (e.g., 1200000 for 1200 MHz)
   struct.unpack_from('<I', data, 0xbd10)[0] == 1200000
```

On-device after loading: `cat /proc/gpufreq/gpufreq_opp_dump` should show the
new OPP table.
