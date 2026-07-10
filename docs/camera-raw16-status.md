# Camera RAW16 Stream Config — Status

## Device
- INOI A75 (mt6789, Android 14, kernel 5.10)
- Sensors: S5KJN1 (Back, Camera 0), S5K3L6 (Front, Camera 1)
- Target: Enable RAW16 (format 32) stream configs for GCam

## Approach Evolution

### Phase 1: MOVK replace (patch_inoi_raw.py) — DEPRECATED
- Changes format immediates in `movz` instructions in-place (33→32, 35→32)
- Only works for Camera 0 (S5KJN1) — correct instruction offsets
- **Corrupts Camera 1** (S5K3L6) — wrong offsets produce `33333333` height
- Also corrupts metadata: SENSOR_INFO_ACTIVE_ARRAY_SIZE, PIXEL_ARRAY_SIZE

### Phase 2: Trampoline at UPDATE (patch_inoi_raw_v2.py) — BROKEN
- Hook point: `bl UPDATE` (0x3fbb8) — the metadata commit call
- Trampoline calls UPDATE, then adds RAW16 entries, then calls UPDATE again
- **Bug**: after commit, `cbz w0, loop_head` re-enters the tag builder, discarding our entries

### Phase 3: Trampoline at entryFor (current) — WORKING
- Hook point: `bl entryFor` (0x3f9f8) — intercepts **after** entryFor creates/populates the IEntry for tag 0xd0012
- Trampoline calls entryFor, pushes RAW16 entries to the **same** IEntry, returns to original code
- Original code continues with its own push sequence — both coexist
- **No corruption**: entries are appended, not patched in place

## Critical Fix: Hook Point Selection

```
Old (broken):   0x3fbb8  bl UPDATE    → bl trampoline
                                         └─ calls UPDATE → adds entries → UPDATE again
                                         └─ cbz w0, loop → entries discarded

New (working):  0x3f9f8  bl entryFor  → bl trampoline
                                         └─ calls entryFor → pushes RAW16 entries
                                         └─ returns to 0x3f9fc (normal push_back)
                                         └─ original entries + RAW16 coexist
```

The entryFor hook is clean because:
1. No need to handle UPDATE return values or loop semantics
2. The IEntry is already populated by entryFor — we just add to it
3. The original push_back sequence continues normally after we return
4. Both original and appended entries get committed together by the subsequent UPDATE call

## Constructor Loop Structure

```
Camera 0 range (0x3f900-0x3fc00):

0x3f99c: sub x0, x29, #0x50               ; IEntry buffer
0x3f9a0: bl entryFor                       ; entryFor for tag X
         ... push_back sequence for tag X ...
0x3f9f0: movz w1, #0x12                   ; tag 0xd0012 low
0x3f9f4: movk w1, #0xd, lsl #16           ; tag 0xd0012 high
0x3f9f8: bl entryFor                       ; ← OUR HOOK: entryFor for tag 0xd0012
0x3f9fc: movz w24, #0x21 / movz w8, #0x33 ; push format entries for 0xd0012
         ... push_back sequence for 0xd0012 (4 entries) ...
0x3fbb8: bl UPDATE                         ; commit metadata
0x3fbbc: cbz w0, 0x3f99c                  ; if success, loop to next tag
```

Camera 1 has the same pattern at different addresses:
- entryFor for tag 0xd0012 at **0x5d204** (hook point)
- Return address at **0x5d208**

## Trampoline Code

```
At cave VA 0x263cc (LOAD1-LOAD2 gap):
  stp x29, x30, [sp, #-16]!    ; save regs (x30 = return address)
  bl entryFor                   ; call REAL entryFor (preserving x0/x1/x2 from caller)
  movz w8, #0x20                ; push RAW16 fields:
  str x8, [sp, #0x10]           ;   format=32
  sub x0, x29, #0x50            ;   IEntry*
  add x1, sp, #0x10             ;   &value
  bl push_long                  ;   push field
  movz w8, #0xFF0               ;   width=4080
  ...                            ;   (repeat for all 6 fields × 2 entries)
  ldp x29, x30, [sp], #16       ; restore regs
  ret                            ; return to 0x3f9fc (normal code)
```

## RAW16 Entries Added

| Camera | Sensor | Resolutions |
|--------|--------|-------------|
| Camera 0 | S5KJN1 | 4080×3072, 3264×2448 |
| Camera 1 | S5K3L6 | 4160×3120, 3328×2448 |

Each entry: `[format=32, width, height, direction=0, internal1=0x3f940aa, internal2=0x1fca055]`

## Test Results (Jul 10 2026 — entryFor hook)

- **GCam**: No crash, ALL_TEST_PASSED for both cameras
- **Camera 0**: RAW16 configs appear correctly
- **Camera 1**: RAW16 configs appear correctly
- **No corruption**: No `33333333` artifacts (MOVK patches removed)
- **All 4 cameras**: `RAW` in availableCapabilities

## Files

| File | Purpose |
|------|---------|
| `injector/patch_inoi_raw.py` | MOVK replace (DEPRECATED, Camera 0 only) |
| `injector/patch_inoi_raw_v2.py` | Trampoline append at entryFor (MAIN) |
| `stock_libmtkcam_metastore.so` | Original unpatched library |
| `device_libmtkcam_metastore.so.patched` | Currently deployed patched library |

## Deploy

```bash
# On host: patch
python3 injector/patch_inoi_raw_v2.py stock_libmtkcam_metastore.so -o patched.so

# Push to device
adb push patched.so /data/local/tmp/libmtkcam_metastore.so
adb shell cp /data/local/tmp/libmtkcam_metastore.so /data/local/tmp/overlay_upper/

# Mount overlay
adb shell su -c 'mount -t overlay overlay \
  -o lowerdir=/vendor/lib64,upperdir=/data/local/tmp/overlay_upper,workdir=/data/local/tmp/overlay_work \
  /vendor/lib64'

# Restart HAL
adb shell su -c 'killall -9 camerahalserver'
```
