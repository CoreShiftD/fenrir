# Camera RAW / DNG Capture — Patch Chain

## Overview

The INOI A75 (MT6789) ships with stock firmware that **hides** RAW and
DNG capture from camera apps despite the hardware being fully capable.
Enabling it requires **two independent binary patches** on two shared
libraries in the vendor firmware partition:

| Patch | Target | What it does |
|-------|--------|-------------|
| Metastore (`patch_raw_capability.py`) | `libmtkcam_metastore.so` | Adds `RAW(3)` + `BURST_CAPTURE(6)` to every sensor's `ANDROID_REQUEST_AVAILABLE_CAPABILITIES` list |
| 3rdparty (`patch_raw_3rdparty.py`) | `libmtkcam_3rdparty.customer.so` | Sets ScenarioFeatures bits 35 + 36 in `customer_update_capture_feature_combination` when raw metadata tag 0x80150005 is present |

Both run automatically via `build.sh <device> --firmware`.

---

## Patch 1: Metastore Capability Tier (`patch_raw_capability.py`)

### What stock does

Each camera sensor has a dedicated constructor function named:
```
constructCustStaticMetadata_PLATFORM_PROJECT_SENSOR_DRVNAME_<sensor_name>
```

Inside each function, a `0xc000c` tag block enumerates the sensor's
`ANDROID_REQUEST_AVAILABLE_CAPABILITIES` via repeated `push_back` calls.
Stock only lists `BACKWARD_COMPATIBLE(0)` and sometimes `BURST_CAPTURE(6)` —
RAW is never included, so Camera2 hides RAW capture from apps.

### Trampoline approach (tier mode)

When `BIND_NOW` is set (PLT[0] is dead), the patcher reuses the gap
between `.text` end and `.plt` start plus the 32-byte dead PLT[0] region as a
code cave. For each sensor:

1. Finds the `0xc000c` capability block in its constructor function.
2. Identifies which tier caps (e.g. `RAW=3, BURST_CAPTURE=6`) are missing.
3. Picks a slot: prefers `BURST_CAPTURE(6)`, then the last non-tier cap.
4. Repurposes the slot's value to the first missing cap (RAW first).
5. Repoints the slot's `BL push_back` to a trampoline in the PLT[0] cave.
6. The trampoline calls `push_back` for each remaining missing cap.

Trampoline layout (16 + 20*K bytes for K extra values):
```
stp x29, x30, [sp, #-16]!
bl  push_back                     ; push slot value (already replaced)
movz w8, #val_k                   ; for each extra cap:
strb w8, [sp, #32+16*k]
sub x0, x29, #0x50
add x1, sp, #0x20+16*k
bl  push_back
ldp x29, x30, [sp], #16
ret
```

### Fallback replace mode

When `BIND_NOW` is absent (no PLT[0] cave), pass `--allow-replace` to
fall back to single-slot replacement (first missing cap only, others lost).
The tier-mode orchestrator in `devices.py` sets `allow_replace: True`.

### Usage

```bash
# Tier mode (recommended)
python3 patch_raw_capability.py libmtkcam_metastore.so --tier=RAW,BURST_CAPTURE

# With replace fallback
python3 patch_raw_capability.py libmtkcam_metastore.so --tier=RAW,BURST_CAPTURE --allow-replace

# Dry run to preview
python3 patch_raw_capability.py libmtkcam_metastore.so --tier=3,6 --dry-run
```

---

## Patch 2: 3rdparty Scenario Features (`patch_raw_3rdparty.py`)

### What stock does

`customer_update_capture_feature_combination` (at VA 0xde8c in the stock
binary) populates `ScenarioFeatures` (a bitmap at `[x27, 0x38]`) for each
capture scenario. Stock only handles the NR (noise-reduction) feature bit
(bit 4). The **raw-specific bits 35 and 36 are never set** because the
metadata-tag check for `0x80150005` is entirely absent.

### Target binary reference

The Advan stock firmware (which has working RAW/DNG on the same chipset)
has the **same function at the same VA**, but 3x larger — the target
appends code that:

1. Iterates metadata tag range `0x80150005–0x8015000E` via the same
   `entryFor`/`count`/`itemAt`/`~IEntry` PLT helpers used elsewhere.
2. When tag `0x80150005` is found with a non-zero value,
   **bit 35** (`0x800000000`) is OR'd into `ScenarioFeatures`.
3. When tag `0x8015000E` is present, **bit 36** (`0x1000000000`).
4. An inner loop checks sub-tags for finer-grained feature bits.

### Our patch

Instead of porting the entire 6 KB of extra target code, we inject a
**164-byte trampoline** into the LOAD-2 segment cave (the gap between
`.plt` end at 0x2c690 and `.data.rel.ro` start at 0x2d000, mapped
executable by extending LOAD-2's `FileSiz`).

The trampoline:
1. Saves registers (x0-x3, x8-x10, x28, x30) and simulates the replaced
   ORR/STR instruction (the original NR bit-4 enable at 0xe1b4).
2. Calls `entryFor(x23=IMetadata*, tag=0x80150005)` → IEntry on stack.
3. Checks `count` > 0.
4. Calls `itemAt` to get the first entry's tag value.
5. Destroys the IEntry via `~IEntry`.
6. If the tag value is non-zero, sets bits 35 + 36 in `[x27, 0x38]`.
7. Restores all registers and branches back to 0xe1bc.

### ELF modifications

| Change | Detail |
|--------|--------|
| LOAD‑2 `FileSiz` | 0x1f690 → 0x20000 (maps bytes 0x2c690..0x2d000 as executable) |
| Insn at 0xe1b4 | `orr x7, x28, #0x10` → `b 0x2c690` (branch to trampoline) |
| Cave at 0x2c690 | 164-byte trampoline + remaining 2252 bytes zero-filled |

### PLT helpers used

| PLT stub | VA in stock | Purpose |
|----------|-------------|---------|
| `entryFor` | 0x2bed0 | Begin iteration over metadata entries for a tag |
| `count`    | 0x2bee0 | Return count of entries found |
| `itemAt`   | 0x2bef0 | Return the first entry's value |
| `~IEntry`  | 0x2bf00 | Destroy the IEntry iterator |

### Usage

```bash
python3 patch_raw_3rdparty.py libmtkcam_3rdparty.customer.so [output.so]
```

---

## Device Configuration (`devices.py`)

Both patches are configured via the `firmware={}` dict per device.

### A75 (existing, complete)

```python
Device('A75', 'INOI A75', { /* bootloader stages */ },
    base=...,
    firmware={
        # Camera patches
        'metastore': {
            'tier': 'RAW,BURST_CAPTURE',
            'allow_replace': True,
        },
        '3rdparty': True,

        # OC patches (unchanged)
        'mcupm':  { 'big': 2700, 'little': 2500, ... },
        'pi_img': { 'set_reg': [...] },
        'gpufreq': { 'bp': True, 'oc': 1900, ... },
        'gpt': { ... },
    },
)
```

### Adding to another device

For a new device, add the `metastore` and/or `3rdparty` keys to the
`firmware` dict. The metastore patcher expects the stock binary to have
`constructCustStaticMetadata_PLATFORM_PROJECT_SENSOR_DRVNAME_*` symbols
present. The 3rdparty patcher expects the same function at the same VAs
(VA 0xe1b4, PLT at 0x2bed0-0x2bf00). If VAs differ, the trampoline
offsets in `patch_raw_3rdparty.py` must be adjusted.

---

## Build Wiring

Both patches activate through the existing `--firmware` flag:

```bash
./build.sh A75 bootloader.img --firmware
```

The build pipeline:
```
build.sh --firmware
  └─> patch_firmware.py A75
        ├─ metastore  → patch_raw_capability.py libmtkcam_metastore.so ...
        └─ 3rdparty   → patch_raw_3rdparty.py libmtkcam_3rdparty.customer.so ...
```

Input files live in `bin/firmware/a75/` alongside the OC images. Patched
outputs get written to the same directory with device-prefixed names.

---

## RE Summary

### Key discovery (July 2026)

Both stock and target `libmtkcam_3rdparty.customer.so` share the same
function at the same virtual address (`customer_get_capture_scenario_int`
at 0xd014) but with drastically different code sizes:

| Function | Stock size | Target size | Δ |
|----------|-----------|-------------|---|
| `customer_get_capture_scenario_int` | 3544 B | 9816 B | +6272 B |
| `customer_get_streaming_scenario_int` | 1424 B | 4484 B | +3060 B |

The extra code in the target handles raw/reprocessing scenarios that stock
lacks. The functions are at the **same base address** because `.text`
section layout is identical up to the point where the stock version ends.

### ScenarioFeatures bit assignments

| Bit | Value | Meaning |
|-----|-------|---------|
| 4   | `0x10` | NR (noise reduction) enabled |
| 35  | `0x800000000` | Any raw tag (0x80150005) non-zero |
| 36  | `0x1000000000` | Tag 0x8015000E present (DNG/opaque raw) |

### What's identical between stock and target

- `customer_get_isp_hidl_capture_scenario` — same jump table
- `customer_get_isp_hidl_features_table_by_scenario` — same hash-map lookup
- All exported globals (`gCustomerScenarioFeaturesMaps`, etc.)
- `camerahalserver` binary

### What differs

- `.data.rel.ro`: 335/445 8-byte words differ (pointer relocations + feature data)
- Init code in `customer_get_capture_scenario_int` populates raw-related
  hash‑map entries via `__emplace_unique_key_args` that stock lacks

### Metastore

The target firmware has no metastore patch — it already includes RAW in
every sensor's capability list. Only stock firmware needs this patch.

---

## Verification Checklist

Post-patch, confirm on-device:

- [ ] `dumpsys media.camera` lists each sensor with `android.request.availableCapabilities` containing `3` (RAW) and `6` (BURST_CAPTURE)
- [ ] Third-party camera apps (OpenCamera, HedgeCam2) show a RAW capture option
- [ ] DNG files are produced and loadable (check with `exiftool` or `identify -verbose`)
- [ ] No camera HAL crashes or `libmtkcam_3rdparty.customer.so` segfaults
- [ ] Video recording still works (BURST_CAPTURE is a superset, not a replacement)

If RAW doesn't appear: re-verify the `--firmware` output files exist in
`bin/firmware/a75/` and the device is booting the patched system.
