# INOI A750 — Camera RAW Patch

## Overview

**Device**: INOI A750 (MT6789, Helio G99), Android 14  
**Target**: `/vendor/lib64/mt6789/libmtkcam_metastore.so` (712440 bytes)  

Factory stock has no RAW support on any camera except Camera 3 (the last one, native in metastore). Cameras 0, 1, and 2 lack `RAW` in `availableCapabilities` and RAW16 entries in `availableStreamConfigurations`.

Two independent patches fix this:

1. **Capability trampoline** — injects `RAW(3)` + `BURST_CAPTURE(6)` into `ANDROID_REQUEST_AVAILABLE_CAPABILITIES` (tag `0xc000c`)
2. **Stream config format swap** — replaces YUV420 (33) and YV12 (35) with RAW16 (32) in sensor constructors

---

## Patch 1 — Capability trampoline

**Script**: `injector/patch_raw_capability.py`  

### The 0xc000c tag block

Each sensor constructor (`constructCustStaticMetadata_PLATFORM_PROJECT_SENSOR_DRVNAME_*`) builds a metadata entry for `ANDROID_REQUEST_AVAILABLE_CAPABILITIES` (tag `0xc000c`). The block layout in AArch64:

```
mov  w1, #0xc000c           ; tag
movz w8, #N                 ; capability value
strb w8, [sp, #16]          ; store to slot
sub  x0, x29, #0x50         ; IMetadata* (base)
add  x1, sp, #0x10          ; IEntry* (slot ptr)
bl  push_back               ; append to block
```

Factory stock has `MOVZ w8, #0` `MOVZ w8, #1` `MOVZ w8, #2` (BACKWARD_COMPATIBLE, MANUAL_SENSOR, MANUAL_POST_PROCESSING). RAW(3) and BURST_CAPTURE(6) are absent.

### Trampoline mechanism

The patcher picks the last non‑tier slot (typically BURST_CAPTURE at value `#6` or MANUAL_POST_PROCESSING at `#2`), overwrites its `MOVZ` with `#3` (RAW), then redirects its `BL push_back` to a **trampoline** in the PLT[0] dead zone.

PLT[0] is 32 bytes of resolver stub in the gap between `.text` and `.plt`. With BIND_NOW, lazy binding is disabled and PLT[0] is never called — safe to overwrite.

Trampoline code (36 bytes for RAW + BURST_CAPTURE):

| Offset | Bytes (LE) | Insn |
|--------|-----------|------|
| +0x00 | `fd 7b bf a9` | `stp x29, x30, [sp, #-16]!` |
| +0x04 | `12 00 00 94` | `bl push_back` (relative) |
| +0x08 | `c8 00 80 52` | `movz w8, #6` (BURST_CAPTURE) |
| +0x0c | `e8 83 00 39` | `strb w8, [sp, #32]` |
| +0x10 | `a0 43 01 d1` | `sub x0, x29, #0x50` |
| +0x14 | `e1 83 00 91` | `add x1, sp, #0x20` |
| +0x18 | `0d 00 00 94` | `bl push_back` |
| +0x1c | `fd 7b c1 a8` | `ldp x29, x30, [sp], #16` |
| +0x20 | `c0 03 5f d6` | `ret` |

The slot's original `BL push_back` (at slot_offset + 16) is rewritten to `BL cave_va`. Execution flow:

```
constructor:
  ...
  movz w8, #3          ← RAW (was #2 or #6)
  strb w8, [sp, #16]
  sub x0, x29, #0x50
  add x1, sp, #0x10
  bl trampoline_cave   ← redirected here
  ...

trampoline_cave:
  stp x29, x30, [sp, #-16]!
  bl push_back         ← pushes RAW(3)
  movz w8, #6
  strb w8, [sp, #32]
  sub x0, x29, #0x50
  add x1, sp, #0x20
  bl push_back         ← pushes BURST_CAPTURE(6)
  ldp x29, x30, [sp], #16
  ret                  ← back to constructor
```

### Sensors patched

All present in this library: S5KJN1, S5K3L6, BF2257, BF20A1, and every other MTK sensor template (~40 sensors).

### Usage

```bash
python3 injector/patch_raw_capability.py libmtkcam_metastore.so --tier=RAW,BURST_CAPTURE
```

---

## Patch 2 — Stream config format swap

**Script**: `injector/patch_inoi_raw.py`  

### The stream config entry builder

Each sensor constructor also builds entries for `ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS` (tag `0xd000a`). The entry structure is `[format, width, height, direction]` — four `int32`s pushed via MTK metadata helpers (`entryFor`, `push`, `push_long`). Format is set with a `MOVK` immediate before pushing.

### S5KJN1 (Camera 0, BACK)

Constructor VA: `0x3f594`. Two `MOVK` immediates changed:

**Change 1** — `0x3f9fc`:
```
Stock:   38 04 80 52    → MOVK w24, #0x21 (format 33 = YUV420)
Patched: 18 04 80 52    → MOVK w24, #0x20 (format 32 = RAW16)
                            ↑ byte 0x38 → 0x18
```

**Change 2** — `0x3fae0`:
```
Stock:   7a 04 80 52    → MOVK w26, #0x23 (format 35 = YV12)
Patched: 1a 04 80 52    → MOVK w26, #0x20 (format 32 = RAW16)
                            ↑ byte 0x7a → 0x1a
```

`MOVK` encoding: `0x52800000 | (rd) | (imm16 << 5)`. The byte at offset +0 differs by `(new_imm16 - old_imm16) << 5` in the low byte.

Result — two RAW16 entries added:

| Format | Width | Height | Direction |
|--------|-------|--------|-----------|
| 32     | 4080  | 3072   | OUTPUT    |
| 32     | 3264  | 2448   | OUTPUT    |

### S5K3L6 (Camera 1, FRONT)

Constructor VA: `0x5c1a0`. Six sites need modification because Camera 1's builder interleaves duration and height fields with format fields.

**Site 1** — `0x5c33c` (same pattern as Camera 0):
```
Stock:   38 04 80 52    → MOVK w24, #0x21 (33)
Patched: 18 04 80 52    → MOVK w24, #0x20 (32)
```

**Site 2** — `0x5c468` (2 bytes, duration→format):
```
Stock:   10 9e          → MOVK w23, #0x9e10 (duration value)
Patched: 04 80          → MOVK w23, #0x20   (format 32)
                           ↑↑ byte pair changed
```
Full insn: `0x528004??` → the low 2 bytes change the `imm16` field.

**Site 3** — `0x5c46c` (4 bytes, kill duration hi word):
```
Stock:   57 5f a0 72    → MOVK w23, #0x2fa5, lsl #16
Patched: 1f 20 03 d5    → NOP (0xd503201f)
```
`MOVK` with shift `lsl #16` was setting the upper half of a 32-bit duration. Replaced with `NOP` — the duration is no longer needed because the entry is now format 32 instead of a frame duration entry.

**Site 4** — `0x5c690` (same as Camera 0's second change):
```
Stock:   78 04 80 52    → MOVK w24, #0x23 (35)
Patched: 18 04 80 52    → MOVK w24, #0x20 (32)
```

**Site 5** — `0x5c96c` (5 bytes, kill height + register swap):
```
Stock:   17 87 80 52    → MOVZ w23, #0x438 (1080 = height)
         f7             → STR x23, [sp, #?] (store height)
Patched: 1f 20 03 d5    → NOP
         f4             → STR x20, [sp, #?] (store different reg)
```
The `MOVZ` setting height (1080 pixels) is NOPped out. The following `STR` register is changed from x23→x20 so the entry's height field picks up whatever x20 holds (presumably the RAW-native height from earlier in the function).

**Site 6** — `0x5cc58` (1 byte, reverse register swap):
```
Stock:   f4             → STR x20, [sp, #?]
Patched: f7             → STR x23, [sp, #?]
```
Undoes the register swap at Site 5 for a different code path, keeping the old height logic intact where needed.

### Combined result for Camera 1

RAW16 entries replace the format-33/35 entries at alternative resolutions. Exact entry list depends on the original builder but includes at minimum the 3264×2448 and lower resolutions.

### Usage

```bash
python3 injector/patch_inoi_raw.py libmtkcam_metastore.so -o patched.so
```

---

## Patch order

1. Run `patch_raw_capability.py --tier=RAW,BURST_CAPTURE` first
2. Run `patch_inoi_raw.py` second

---

## Files

| File | Hash | Stage |
|------|------|-------|
| `working.so` | `923f4e83` | After both patches (712440 bytes) |

## Deploy

```bash
adb push working.so /data/local/tmp/
adb shell "umount -l /vendor/lib64/mt6789/libmtkcam_metastore.so 2>/dev/null"
adb shell "mount -o bind /data/local/tmp/working.so /vendor/lib64/mt6789/libmtkcam_metastore.so"
adb shell "killall camerahalserver"
sleep 3
```

## Verify

```bash
adb shell dumpsys media.camera
```

**Camera 0** (BACK, S5KJN1):
```
availableCapabilities: BACKWARD_COMPATIBLE MANUAL_SENSOR MANUAL_POST_PROCESSING RAW CONSTRAINED_HIGH_SPEED_VIDEO BURST_CAPTURE
availableStreamConfigurations: contains [32 4080 3072 OUTPUT] [32 3264 2448 OUTPUT]
```

**Camera 1** (FRONT, S5K3L6):
```
availableCapabilities: BACKWARD_COMPATIBLE MANUAL_SENSOR MANUAL_POST_PROCESSING RAW PRIVATE_REPROCESSING CONSTRAINED_HIGH_SPEED_VIDEO BURST_CAPTURE
availableStreamConfigurations: contains multiple [32 w h OUTPUT] entries
```

**Camera 3** (last):
```
availableCapabilities: RAW present (native)
availableStreamConfigurations: RAW16 entries present (native in metastore)
```
