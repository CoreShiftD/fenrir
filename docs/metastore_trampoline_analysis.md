# Metastore trampoline analysis — dead code discovery

## Summary

The function patched by `patch_raw_3rdparty.py --mode metastore-raw16` in
`libmtkcam_metastore.so` (the BL at VA `0x76174`, originally calling
`updateAfRegions` at `0x761d4`) is **never reached** during camera
initialization on the V7 firmware.  Crash-test instrumentation
(`str wzr, [xzr]` — a guaranteed SIGSEGV) confirmed that the trampoline
does **not** execute; camerahalserver starts without fault.

This means the patch worked as intended (ELF load segment extended,
trampoline written, BL redirected, `updateAfRegions` NOP'd), but the
enclosing code path is **dead** in this firmware build.

## Evidence

1. **No crash**: replacing the trampoline with `str wzr, [xzr]` (`0xB9001FFF`)
   should crash camerahalserver immediately if reached.  It didn't —
   camerahalserver started normally and dumpsys returned 3 devices.

2. **Stock RAW16 entries persist unchanged**: Device 2 has `[32 1600 1200 OUTPUT]`
   with and without the patch.  This entry comes from the **HAL
   initialization code**, not from the patched function.

3. **Device 0 never gets RAW16**: even with the patch, Device 0 has zero
   RAW16 entries (508 stream config entries, all format 33/35/34/private).
   The hidden code path at `0x76068–0x760ec` (which checks global feature
   flags before building vendor-specific RAW entries) is gated by
   conditions that are not met on this device/firmware.

4. **Single caller**: only one BL in the entire binary targets
   `0x761d4` (at `0x76174`).  No other code path reaches the patched
   function.

## Root cause

The function at `0x76174` is inside a larger stream-config-builder that
contains a feature-flag gate (`0x76068–0x760ec`).  When the global flags
are not set, the code jumps **to** `0x76160` (which calls `tag()` then our
trampoline) — but the `0x76160` code itself may only be reachable from a
**different** entry point that is also never called.  In other words, the
entire builder function appears to be legacy/unused in this firmware
version.

## Implication for future work

- The `metastore-raw16` mode in `patch_raw_3rdparty.py` does **nothing**
  useful against the V7 firmware.  It is safe (no crashes) but produces no
  visible metadata changes.
- RAW16 support must be enabled through a different mechanism:
  - Finding and patching the **actual** HAL code that builds
    `android.scaler.availableStreamConfigurations` (likely in
    `libmtkcam_device3_hal.so` or `libmtkcam_pipelinepolicy*.so`)
  - Or setting the global feature flags that gate the vendor RAW path
    in the existing builder (the GOT entries at `0xac000+0xac8`,
    `0xac000+0xad0`, `0xac000+0xab8`)
  - Or using the `3rdparty` library patch (which works at a different
    layer — `libmtkcam_3rdparty.customer.so`).
