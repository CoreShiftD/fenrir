# Preloader GZ patch — binary patching approach

**Goal:** disable GenieZone (TEE) without touching GPT.

## Problem

GPT modification (pointing `gz_a`/`gz_b` LBAs beyond capacity) triggers the
preloader's GZ init FSM, which eventually calls `panic()` and hangs the device
when the loaded GZ image can't be released/validated. See the panic at
`libmtkcam_3rdparty.customer.so` analysis — same pattern: preloader code at
`0x023a02` calls `bl 0x2f0c4` which enters an infinite WFE/WFI loop.

## Solution

One-byte patch to the preloader binary that makes the GZ release function
unconditionally skip before it reaches the panic path.

### How it works

The GZ init FSM in the preloader has this structure:

```
bl check_gz_status (0x329b0)    → r0 = 0 if GZ not active, ≠0 if active
mov.w fp, #0                    → fp = 0 (return value flag)
cmp r0, #0                      → check GZ status
beq 0x23a12                     → skip if GZ not active (ORIGINAL)
↓ (r0 ≠ 0, GZ is active)
GZ release loop (9 entries)     → for each GZ memory region:
  → if release fails: panic("GZ fatal error") → HANG
→ fall through to skip target
0x23a12: mov r0, fp             → r0 = fp = 0 (success)
```

The patch changes `BEQ 0x23a12` (conditional, only taken when `r0==0`) to
`B 0x23a12` (unconditional, always taken). The GZ release loop (including
the panic call) is never reached.

### Patch detail

| Location | Original | Patched | Effect |
|----------|----------|---------|--------|
| Content offset `0x23982` | `BEQ 0x23a12` (`D0 46`) | `B 0x23a12` (`E0 46`) | Always skip GZ |

Single byte change: content byte `0x23983` from `0xD0` to `0xE0`.

### Return-value trace

Only one direct caller: `bl 0x23970` at offset `0x2712a` in the GZ init FSM.

```
0x2712a: bl 0x23970          → r0 = 0 (fp was set to 0)
0x2712e: cbz r0, 0x27150     → r0==0 → branch to partition-load path
```

| r0 | Path | Result |
|----|------|--------|
| **0** (patched) | Try `bldr_load_gz_part(0x23ab4)` → fails (no valid partition) → r6=err → loop top → bail out | **GZ skipped, boot continues** |
| ≠0 | Set r6=0 → continue FSM → `bl 0x23a44` → panics at `0x23a6a` because GZ not actually loaded | HANG |

Returning `0` from the patched function is correct. The post-return path
(`0x23a44`) that has its own panic call is exactly what gets shielded by the
`r6≠0` bailout.

### Chain of functions

```
0x2709c: init FSM entry
  → bl 0x329b0          check_gz_status (first call)
  → bl 0x269e4          init GZ infrastructure
0x2710e: main loop body
  → dprintf             "GZINIT gz_release_all"
  → bl 0x23970          gz_release_all  ← PATCHED
  → cbz r0, 0x27150     r0==0 → partition loader
0x27150: partition loader
  → bl 0x2e05c          mt_set_part_info
  → bl 0x23ab4          bldr_load_gz_part
  → cmp r0, #0          check result
  → beq 0x27130         success → continue
  → mov r6, r0          error → save in r6
  → b 0x2703c           loop top
0x2703c: loop top
  → cbz r6, 0x27048     r6==0 → continue init
  → dprintf error       r6≠0 → print error
  → b 0x27090           bail out (skip 0x23a44!)
0x27048: continue init
  → bl 0x3015c          timer
  → bl 0x23a44          GZ launch (HAS ITS OWN PANIC)
  → bl 0x30238          finalize
  → return
```

## Files

| File | Purpose |
|------|---------|
| `bin/firmware/a75/preloader_k6789v1_64.bin` | Full preloader with GFH header + RSA sig |
| `bin/firmware/a75/preloader_content.bin` | Raw code/data (GFH stripped) |
| `bin/firmware/a75/preloader_k6789v1_64_patched.bin` | Patched full preloader |
| `injector/patch_preloader_gz.py` | Standalone patching script |

## Verification

```bash
# Check the patch was applied
python3 -c "
import struct
with open('preloader_k6789v1_64_patched.bin', 'rb') as f:
    f.seek(0xF0 + 0x23982)  # GFH(240) + content offset
    hw = struct.unpack('<H', f.read(2))[0]
    assert hw == 0xE046, f'Bad patch: 0x{hw:04x}'
    print('Patch OK: B 0x23a12')
"
```

## Flash note

The patched preloader's RSA signature (last 1644 bytes) is now invalid.
This matters for cold boot (BootROM verifies it) but is typically ignored
in download/DA mode. If the device enforces signature verification on cold
boot, an unlocked bootloader or a signed replacement is needed.

## Comparison: GPT vs preloader approach

| Aspect | GPT disable | Preloader patch |
|--------|-------------|-----------------|
| What it touches | Partition table (PGPT/SGPT) | Preloader binary |
| Risk | BootROM panic if preloader can't parse modified GPT | Invalid RSA sig on cold boot |
| Reversibility | Reflash stock GPT | Reflash stock preloader |
| Complexity | Full GPT rebuild (scatter, LBA math) | One-byte change |
| Side effects | None visible | GZ/TEE unavailable |
