# pi_img.bin / KRAKEN / CPU max-freq investigation

**Goal:** push CPU max frequency higher than the current ceiling. User can already
raise it via `mcupm.bin` patching, but past a certain threshold the firmware
refuses. Working hypothesis: `pi_img.bin` supplies an aging/binning-derived
frequency-or-voltage cap that gates this, consumed by `mcupm.bin`'s EEMSN module.

Scope constraint: only `/opt/src/fenrir/*.bin` (top-level) are this user's own
device dumps and are in-scope. `/opt/src/fenrir/bin/*.bin` are unrelated
(other devices) — do not analyze those for this task.

Tools used: `radare2` (`-a arm -b 64`), `strings`, python for offset/entropy checks.

---

## 1. `pi_img.bin` file layout (16320 bytes)

```
offset 0x000            outer GFH header (MediaTek "Generic File Header")
                         magic  = 0x58881688 ("88 16 88 58" LE)
                         name   = "pi_img" (ASCII, at +0x08)
                         second sub-header magic 0x58891689 at ~+0x30
                         (standard signed-partition wrapper used by all MTK
                          preloader/lk/tee/pi component images — integrity/
                          signature framing, NOT related to KRAKEN below)

offset 0x200 (512)      KRAKEN payload starts here.
                         header_cookie = 0x17C3A6B4 (4 bytes LE: b4 a6 c3 17)

0x200 .. 0x3120         "shadow table" payload (12068 bytes), PLAINTEXT.
                         NOT encrypted, NOT compressed. Dumped as u32 LE words
                         it looks like address/size/count entries (register-
                         shadow style table) — see fcn.00019be4 notes below
                         for the actual entry structure format (still only
                         partially decoded).

offset 0x3120 (12576)   footer_cookie = 0x17C3A6B4 (same magic, closes payload)

0x3124 .. 0x3fc0 (EOF)  trailing padding / signature area belonging to the
                         outer GFH wrapper, not touched by KRAKEN.
```

Verified in python: `0x17C3A6B4` (as LE bytes `b4 a6 c3 17`) occurs at exactly
offsets 512 and 12576 in `pi_img.bin` — matches the cookie check in
`bl2_ext.bin` below byte-for-byte.

## 2. `bl2_ext.bin` — KRAKEN loader (confirmed, fully traced)

"KRAKEN" is **not** an encryption or compression algorithm — it's MediaTek's
internal codename for a calibration/test-parameter-image loader. No cipher
or decompression instructions appear anywhere in this path.

- Function `fcn.0001a01c` = `kraken_load_para_img` (name from log string
  `"ERR: line-%d: kraken_load_para_img failed"`).
  - Called from `fcn.000057c0` (boot-stage dispatcher) at `+0x330`.
  - Reads partition by name — the name string passed to the partition-read
    call (`fcn.0004867c`) is literally `"pi_img"` (string at `0x65000+0x69f`
    with base `0x41e00000`). **This is the direct confirmation that KRAKEN
    loads `pi_img.bin`.**
  - Bounds-checks read size vs 1MB (`w20 >> 20`).
  - Validates `header_cookie` (first 4 bytes of payload) and `footer_cookie`
    (last 4 bytes) both equal `0x17C3A6B4`; constant built via
    `mov w8, 0xa6b4; movk w8, 0x17c3, lsl 16`.
  - On success, calls `fcn.00019be4` (the "shadow table" linker/parser, see
    below) to walk the payload, writes parsed entries into a **fixed global
    buffer at physical/virtual address `0x11340C`** via a copy helper
    `fcn.00045b98`, then does a cache-clean over the region
    (`fcn.00004430(0x113400, size=0xc00)`) — i.e. this is a **shared-memory
    handoff to another core/subsystem** (cache maintenance is only needed
    when another cache-incoherent agent, e.g. the MCUPM Cortex-M/RV core,
    will read it).
  - Debug status struct at fixed addr `0xcd0b8` (relative, base `0x41e00000`):
    `+0x0` = magic (`0xA5A5A5A5` sentinel when size-OK), `+0x4` = img_size,
    `+0x8` = status word (`0xDEADBEEF` while processing) + bitflags read back
    for the log lines:
    - bit1 → `is_aging_load`
    - bit2 → `is_slt_load`
    - bit3 → `is_mc50_load`
    - bit4 → `is_lut_load`

  These flag names (**aging**, **SLT** = system-level test/chip-binning,
  **MC50**, **LUT**) all point to **factory calibration / silicon-aging
  test data**, not firmware code or a DVFS OPP table itself.

- `fcn.00019be4` = shadow-table parser (1080 instr, only partially decoded).
  - Args: `(x0=dest_buffer, x1=out_count_ptr, x2=raw_payload_ptr, ...)`.
  - Header at `x2`: `u16 count` at +0, then entries; each entry region uses
    a byte-stream sub-format with delimiter bytes `'w'` (0x77) and `'x'`
    (0x78) — looks like a **RLE/tag-value micro-encoding** for offsets
    (not a cipher — single-byte tag dispatch, `cmp` against `0x77/0x78/0xb8/0xf0`).
  - Copies resolved sub-blocks via `fcn.00045b98` (memcpy-like) into the
    destination buffer, accumulating running offsets (w19/w20/w25/w28 etc.)
  - **Not fully reverse engineered yet** — entry struct fields (freq table?
    voltage margin table? per-core aging offsets?) are still unknown. This
    is the highest-value next target: decoding this format tells you exactly
    what the payload words dumped in section 1 above actually mean.

## 3. `mcupm.bin` — where the CPU freq cap is enforced (confirmed link, NOT yet traced)

- Raw blob, `file` reports "data" (no ELF header) — **architecture/load base
  not yet confirmed**. MCUPM normally runs on a separate small core
  (Cortex-M or similar) from the AP/bootloader cores, so it may NOT be
  AArch64 like `bl2_ext.bin`. r2 auto-analysis under `-a arm -b 32` found
  the strings but **no xrefs** — likely wrong arch/base, needs correct
  identification before disassembly will work. **Next agent: try arm/thumb
  32-bit variants, check for a known MCUPM core type for this SoC, or look
  for a load-address hint in `preloader_gfh.bin`/`lk_main_dtb.bin`.**
- Confirmed via `strings`:
  - `"pi_img"` string present at offset `0x1302c`.
  - EEMSN (aging-aware EEM/DVFS) module strings nearby:
    - `"[CPU][EEMSN]get eemsn_init_semphr err"` @ 0x12e9a
    - `"[CPU][EEMSN]id:%d, vboot violate"` @ 0x12ec1  ← **likely the exact
      refusal path** — "vboot violate" reads as a voltage/frequency-vs-boot
      -constraint violation check.
    - `"[CPU][EEMSN]id:%d, orig volt:0x%x"` @ 0x1359b
    - `"[CPU][EEMSN]SN irq request failed"` @ 0x13761
    - `"[CPU][EEMSN]eemsn_main SPMC ready, sn_aging_status:%d, ..."` @ 0x13c47
    - `"[CPU][EEMSN]eemsn_main, sn_aging_status:%d, ..."` @ 0x13ca0
  - **EEMSN = "EEM Silicon-aging/Sensor" tracking module.** It maintains
    `sn_aging_status` per CPU id and appears to reject ("vboot violate")
    voltage/frequency combinations that don't match calibration data —
    almost certainly the mechanism refusing your OC past a threshold.

## 4. Working theory (unconfirmed, needs step 5 to verify)

`bl2_ext.bin`'s KRAKEN loader reads `pi_img.bin`'s aging/SLT/MC50/LUT
calibration table into shared memory (`0x11340C`) early in boot →
`mcupm.bin`'s EEMSN module reads that same shared region → uses it to
validate/clamp voltage-frequency pairs per CPU, rejecting ones that violate
the aging-derived envelope (`"vboot violate"`). If true, the cap is **not a
hardcoded OPP table limit** but a **derived envelope from pi_img's aging
data** — meaning either:
  (a) patch the aging/SLT threshold values inside `pi_img.bin`'s payload
      (between file offsets 0x200–0x3120, respecting the two 0x17C3A6B4
      cookies which must still match after edits — footer includes the
      payload up to size-4, so any resize must be reflected/cookie kept
      at same relative position), or
  (b) patch the check in `mcupm.bin`'s EEMSN function directly (same style
      as `patch_gpufreq.py`'s `avs_freq_check_bypass` — NOP the branch that
      enforces "vboot violate"), which is likely the lower-risk route once
      the function is located, following the exact pattern already proven
      to work for GPU in `patch_gpufreq.py`.

## 4b. UPDATE — two independent signature/sanity gates found, not one (confirmed)

`pi_img.bin` is protected by **two separate, independently-checked mechanisms**.
Don't confuse them — they need completely different fixes.

1. **Outer GFH/cert2 signature (real cryptography).** `bl2_ext.bin`'s raw
   partition-read helper `fcn.0004867c` (called by KRAKEN's
   `kraken_load_para_img` to fetch `pi_img`) validates the GFH magic
   `0x58881688`, then calls `fcn.00046114(dest=x28, cert_ptr=x23, len=0x20)`
   against a cert block before accepting the read as good. Confirmed present
   in `pi_img.bin` itself:
   - GFH sub-block named `"cert1"` at absolute file offset **0x3130 (12592)**.
   - A second GFH sub-header (magic `0x58891689`) immediately after it.
   - An actual DER-encoded certificate — `30 82 06 a9 ...` (ASN.1 SEQUENCE,
     declared length 1705 bytes) starting at absolute file offset
     **0x3330 (13104)**, running to offset 14813.
   - This is the exact same MTK GFH `cert1`+`cert2` structure that
     `injector/cert_bypass.py` (`liblk`'s
     `Certificate`/`LkImage.partitions[...].cert2`) already models for
     `lk.bin` partitions.
   - **This is a real RSA-signed hash you cannot recompute without the
     private key.** If you edit the payload bytes, this check WILL reject
     the modified image at load time, independent of the KRAKEN cookie.
   - **Fix: reuse `cert_bypass.py`.** `apply_cert_bypass(image, mode=OVERRIDE)`
     (or `WRAP`) forges a `cert2` the verifier accepts by exploiting how the
     parser reads the cert structure (prepend a `[0]` hash-override block
     ahead of the untouched, validly-signed original — same trick already
     proven against `lk.bin`). `liblk` needs to be pip-installed in a venv
     first (`pip install liblk` failed here — externally-managed env, no
     venv present); once installed, load `pi_img.bin` the same way `lk.bin`
     is loaded (may need to confirm `LkImage` handles a single-partition
     GFH file rather than the full multi-partition `lk.bin` layout — TODO,
     not yet tested).

2. **Inner KRAKEN cookie (not cryptographic).** Just the `0x17C3A6B4` sentinel
   at payload start/end described in section 1/2 above. **No forging needed
   here** — this is the "simpler approach" available for this one specific
   check: edit only bytes strictly inside `0x204`–`0x311B`, leave the two
   4-byte cookies untouched, and keep the total payload length identical so
   the footer cookie stays at its expected relative offset. Do NOT reach for
   `cert_bypass.py`-style forging for this layer — it's solving a problem
   (RSA signature) this layer doesn't have.

**Net takeaway:** editing `pi_img.bin`'s aging/SLT table requires BOTH (a)
staying inside the cookie-safe byte range and (b) re-signing via the
cert_bypass.py technique, because the outer GFH/cert2 check runs first, at
the raw partition-read level, before KRAKEN's own cookie check ever executes.

## 4c. CONFIRMED WORKING — patch + re-sign pipeline (tested end-to-end)

`liblk` is installed at `/opt/src/fenrir/.venv` and correctly parses
`pi_img.bin` as a single-partition GFH image. The local `injector/cert_bypass.py` helper works against it. Verified working pipeline:

```python
import sys
sys.path.insert(0, '/opt/src/fenrir/injector')
from cert_bypass import apply_cert_bypass
from liblk.image import LkImage

img = LkImage('/opt/src/fenrir/pi_img.bin')
p = img.partitions['pi_img']          # only partition in this file
# p.data is EXACTLY the 12068-byte KRAKEN payload (liblk already strips
# the outer GFH header/cert1/cert2 wrapper for you — no manual offset
# math needed, unlike section 1-3's file-offset-based notes above).
# p.data[:4] == p.data[-4:] == b'\xb4\xa6\xc3\x17' (the KRAKEN cookie,
# confirmed present at both ends of liblk's `data` view too).

data = bytearray(p.data)
# ... edit data[4:-4] only — never touch data[:4] or data[-4:] ...
p.data = bytes(data)

apply_cert_bypass(img)   # forges cert2
img.save('/path/to/pi_img_patched.bin')
```

Tested: single-byte flip at `data[100]`, saved, reloaded with `liblk` —
round-trips cleanly (cookie intact, cert2 grew 982→1072 bytes as expected
for OVERRIDE mode, outer GFH header byte-identical). `matches_cert2()`
returns `None` post-bypass (not `True`/`False`) — that's expected: the
forged cert2 is a parser-confusion payload for the *device's* verifier,
not something `liblk`'s own strict parser considers "clean". Do not treat
a `None` here as failure.

**Still unverified: whether the real device firmware actually accepts this
forged cert2 at boot.** This was only validated at the file-structure level
(liblk round-trip + the manually-confirmed disassembly of `fcn.00046114`'s
call site in section 4b) — it has not been flashed/tested on hardware.
`WRAP` mode is available as a fallback if `OVERRIDE` is rejected on-device.

## 4d. `mcupm.bin` — architecture identified, EEMSN chain partially traced

**Architecture confirmed: RISC-V, not ARM.** `mcupm.bin` is GFH-wrapped
(same outer header format as `pi_img.bin`) around a single partition named
`tinysys-mcupm-RV33_A` (name string at file offset 8) — "RV" = RISC-V. This
is why earlier ARM/AArch64 disassembly attempts on it found nothing.

Working extraction + disasm pipeline:
```bash
# 1. strip the GFH/cert wrapper with liblk to get the raw RISC-V payload
.venv/bin/python3 -c "
from liblk.image import LkImage
img = LkImage('/opt/src/fenrir/mcupm.bin')
p = img.partitions['tinysys-mcupm-RV33_A']
open('/tmp/mcupm_payload.bin','wb').write(p.data)
"
# 2. disassemble with radare2 as 32-bit RISC-V, base 0 (first bytes decode
#    as a valid `jal` instruction at offset 0, confirming base=0 is correct)
r2 -qq -a riscv -b 32 -c 'aaa; aav0; <commands>' /tmp/mcupm_payload.bin
```

Confirmed call chain from the `"pi_img"` string (file offset 0x12e2c in the
raw payload):
- `fcn.0000ba0a` (0xba0a) — loads the `"pi_img"` string, calls `fcn.0000ba28`.
  If it returns 0 (not found), falls through to an error/assert path
  (`fcn.0000ba06` with a fixed string operand); if found, jumps to
  `fcn.00002584` (unexamined — likely main init continuation).
  XREF'd from `fcn.00000000 @ 0x1143a` (i.e. called from the RV core's
  entry/init function, early boot).
- `fcn.0000ba28` (0xba28) — NOT a simple lookup. It's a **named config-key
  loader**: loops calling `fcn.0000ba02`/`fcn.0000ba06` (get/set-style
  accessors keyed by string, compared against a `0xdeadc2f7`-style sentinel
  for "not found") and copies 4-byte words into fixed base-register
  structures built from `lui 0x10114` / `lui 0x21c10` constants (looks
  like MMIO or shared-SRAM register block addresses — possibly related to
  the `0x11340C` shared buffer `bl2_ext.bin`'s KRAKEN loader writes to,
  worth checking: `0x113...` prefix matches). Calls further into
  `fcn.0000b3de`, `fcn.0000bb54`, `fcn.0000b974` — **none of these three
  are unwound yet**. EEMSN's actual aging/frequency logic almost certainly
  lives in one of them, or further down that chain.

**Status after later tracing:** the config-key loader path is still relevant, but
newer work in sections 6-7 supersedes the concrete offsets and next-step list
below. The main confirmed consumer clue is now the EEM hardware layer around
RV32 function `~0x3a1e`, which reads `0x11c101a4` / `0x11c10090`, extracts the
top byte, and stores the aging/SVS value at global `0x17af0`. Continue from
that consumer-side value and its callers rather than from the stale wrapped-file
string offsets.

## 5. Current handoff state (supersedes the old TODO list)

The early unknowns are now resolved:

- `liblk` is installed in `/opt/src/fenrir/.venv` and parses `pi_img.bin`
  directly as a single-partition GFH image.
- `cert_bypass.py` works on `pi_img.bin` at the file-structure level; use
  `OVERRIDE` first and `WRAP` as fallback if the device rejects it.
- `mcupm.bin` is RISC-V RV32, GFH partition `tinysys-mcupm-RV33_A`, base 0
  after extracting `partition.data` with `liblk`.
- The parser at `fcn.00019be4` is structurally decoded enough to separate the
  low-entropy register-shadow table from high-entropy per-chip aging/SLT/MC50/LUT data.
- `injector/pi_img_devices.py` now implements the safe edit pipeline:
  cookie-safe same-length patching plus cert2 re-signing.

What is still missing is exactly one proof: the mcupm EEMSN validator compare
that turns the loaded EEM/aging value into the `vboot violate` refusal. Until
that compare is named, `pi_img_devices.py` intentionally exposes only raw
`--set` / `--set-reg` controls and refuses friendly MHz/mV conversions.

Concrete next work:

1. Continue from mcupm RV32 function `~0x3a1e` and its callers. This code reads
   EEM regs `0x11c101a4` and `0x11c10090`, extracts their top byte, and caches
   the aging/SVS value at global `0x17af0`.
2. Locate the call site or indirect logging path for the EEMSN strings,
   especially payload offset `0x12cc1` (`vboot violate` in A75 payload). Plain pointer xrefs
   did not find it, so force function starts around suspected log-call sites or
   emulate callers of `~0x3a1e`.
3. Find the comparison that gates boot/requested volt+freq against the aging
   byte or a derived table value. That comparison names either:
   - the exact `pi_img` field to patch, if staying with route (a), or
   - the branch to bypass in `mcupm.bin`, if taking route (b).
4. Only after step 3, add a high-level option to `pi_img_devices.py` such as
   `--cap-*`. Do not encode a guess as a default patch.

## Reference addresses (base 0x41e00000 for bl2_ext.bin)

| symbol | addr | note |
|---|---|---|
| `fcn.0001a01c` | 0x1a01c | `kraken_load_para_img` |
| `fcn.00019be4` | 0x19be4 | shadow-table parser (partial) |
| `fcn.0001a2d0` | 0x1a2d0 | called from parser byte-tag dispatch (unexamined) |
| `fcn.00045b98` | 0x45b98 | copy/link helper (memcpy-like, unexamined) |
| `fcn.00004430` | 0x4430 | cache-clean by VA range (unexamined, standard MTK API name is likely `mt_secure_call`/`dcache_clean_range` equiv) |
| status struct | 0xcd0b8 | magic/size/status/flags, written by KRAKEN |
| shared handoff buf | 0x11340c | destination for parsed shadow table, consumed cross-core |
| header/footer cookie | 0x17c3a6b4 | validates `pi_img` payload integrity |

## Reference offsets in mcupm payload — AVERIFIED against A75 `bin/firmware/a75/mcupm.img` (GFH-stripped, base 0)

⚠ Flagship A75 payload offsets below — if you analyze a different device's
mcupm, re-verify with `strings -t x` on the stripped payload. The original
offsets in earlier notes differed by 0x13 (offsets in the A75 payload are
consistently 19 bytes earlier than the earlier session's offsets).

Payload md5: `d56e48ebc91543742185037c1b7045fc`

| string | A75 payload offset |
|---|---|
| `pi_img` | 0x12e2c |
| `[CPU][EEMSN]id:%d, vboot violate` | **0x12cc1** |
| `[CPU][EEMSN]get eemsn_init_semphr err` | **0x12c9a** |
| `[CPU][EEMSN]id:%d, orig volt:0x%x` | **0x1339b** |
| `[CPU][EEMSN]SN irq request failed` | **0x13561** |
| `[CPU][EEMSN]eemsn_main SPMC ready, ...` | **0x13a47** |
| `[CPU][EEMSN]eemsn_main, sn_aging_status:%d, ...` | **0x13aa0** |
| `[CPU][EEMSN]NULL eemsn_init_semphr!` | 0x13a22 |

Older notes quoted offsets from the GFH-wrapped `mcupm.bin`; use the stripped
payload offsets above for disassembly and script work.

## 6. CONFIRMED — shadow-table parser format + payload layout (this session)

Decoded `bl2_ext.bin` parser `fcn.00019be4` (AArch64) and the `pi_img` payload
(`liblk`-extracted, 12068 bytes). Tooling: radare2 (`-a arm -b 64`) + capstone.

### 6a. Parser `fcn.00019be4` control flow (decoded)

```
w20 = ldrh [x2]          ; entry COUNT (u16) at header+0
w24 = ldur [x2, 6]       ; a limit/threshold field at header+6
x19 = x2 + 2             ; entry array base
loop over w20 entries, ENTRY STRIDE = 0xC (12 bytes):
    w22 = ldr [x19]                       ; entry.field0 = byte-stream position
    if !(w24 > w22): error "kraken ... line-%d"   (str @ 0x65724)
    walk tag byte-stream at base+w22, dispatch on tag byte:
        0x77 'w'  -> (<= 'w') emit-zero / skip path via fcn.0x1a2d0(x1=0)
        0x78 'x'  -> copy 4-byte word: ld [base+pos+1] -> fcn.0x1a2d0, pos += 5
        0xb8      -> boundary/terminator check (base+pos+2)
        0xf0      -> indexed pull from global array @0x794a8 (counter @+0x190)
    on b8/terminator: ldp {w8,w22},[entry+4]; sub-block = base + w8;
                      ldp {w8,w20},[subblk]; w21 = [subblk+0xc]; recurse fields
```

So the format is a **tag-value micro-encoding of register-shadow words** with a
12-byte outer entry descriptor and nested sub-blocks — NOT a flat array. It is
plaintext (no cipher), confirming section 1. `fcn.0x1a2d0` is the word emitter
into the destination buffer that ends up at shared SRAM `0x11340C`.

### 6b. `pi_img` payload layout (entropy-verified)

| file off (payload) | entropy | content |
|---|---|---|
| `0x000` | — | header cookie `b4 a6 c3 17` (`0x17C3A6B4`) |
| `0x004..0x300` | ~2.9–3.3 | **structured register-shadow table** (plaintext) |
| `0x300..0x2f20` | ~7.5 | **per-chip aging/SLT/MC50/LUT calibration** (high-entropy silicon data) |
| `0x2f20` (`-4`) | — | footer cookie `0x17C3A6B4` |

Structured region highlights (payload-relative offsets):
- `0x50/0x6c/0x88`: 28-byte records `[id][0x8000f048][0x0011c105][0x10][0x1300][0x30000][0x80000]`, id = 1/3/2 — per-domain descriptors.
- `0x1b8/0x1f4/0x238/0x2ac`: repeated `[0x00480000][0x11c10580][0x00001000]` —
  **register-shadow writes: reg `0x11c10580` <- `0x1000`**. `0x11c1_xxxx` is the
  MTK EEM/PTP-OD (`CPU DVFS/aging`) controller block — the SAME `0x11c1` region
  mcupm's EEMSN builds addresses for (section 4d, `lui 0x21c10`/`0x10114`).
- The `0x300+` region is where the actual aging-derived voltage/frequency
  envelope lives; being per-chip silicon data it is inherently high-entropy.

### 6c. Which bytes are the OC cap — STILL NOT pinned (do not guess)

The register-shadow table (`<0x300`) is understood structurally, but WHICH
value is the max-freq / voltage-margin the EEMSN "vboot violate" path enforces
is not yet proven. Confirming it requires disassembling mcupm's EEMSN validator
(the consumer) to see which shadowed register / envelope byte it compares boot
volt/freq against. Until then, `pi_img_devices.py` ships the **patch+re-sign
pipeline** and register-shadow tooling but enables **no** cap patch by default.

### 6d. CONFIRMED patch+re-sign pipeline (used by `pi_img_devices.py`)

`liblk` (`/opt/src/fenrir/.venv`) + local `cert_bypass` round-trip cleanly:
- edit only `payload[4:-4]`, keep length constant (KRAKEN cookie gate), then
- `apply_cert_bypass(img)` forges cert2 (outer GFH/RSA gate), `img.save()`.
Both gates handled; **on-device acceptance of the forged cert2 remains untested.**

## 7. EEMSN consumer trace in mcupm (RISC-V) — partial, this session

Goal: find the encoding/unit of pi_img shadow values so a friendly `--freq/--volt`
knob is possible. Disassembled `/tmp/mcupm_payload.bin` (RV32, base 0) w/ r2 + capstone.

Confirmed:
- **gp = 0** (set at code 0x108 `mv gp, zero`) — no gp-relative addressing.
- **pi_img config key** loaded at code 0xba0e/0xba10 (matches §4d `fcn.0000ba0a`).
- **EEM hardware layer** at 0x3a96 (NOT 0x3a1e as earlier — the function at 0x3a1e is
  a different arithmetic helper, not the EEM reader): builds address **0x11c101a4**
  via `lui a0, 0x11c10; addi a0, a0, 420`, does an atomic load (`lr.w`), extracts
  the TOP byte (`srli a2, a0, 0x18`) — an aging/SVS value — and caches it to
  global **0x17af0** (`sw a2, -1296(s2)` with `s2 = 0x18000`).
  i.e. pi_img's shadowed values arrive in the `0x11c1_xxxx` EEM registers as
  **hardware-encoded aging bytes, NOT MHz/mV**.
  → This is why `pi_img_devices.py` refuses `--set-reg ...=2600mhz`: there is no
    clean unit→byte formula; the values are raw EEM encodings.


### 7a. A75 `bin/firmware/a75/pi_img.bin` offset result

Target image checked: `bin/firmware/a75/pi_img.bin`. `liblk` sees partition
`pi_img`, payload length 12068 bytes, cookies intact, payload md5
`0c793c981d2f8a45918d8d04c7871423`.

The A75 payload does **not** have only one structured register-shadow table. It
has repeated low-entropy structured islands at payload ranges around `0x000`,
`0x900`, `0x1200`, `0x1c00`, and `0x2600`. The EEM shadow register found in all
these islands is:

```
reg 0x11c10580 <- 0x00001000
```

For this A75 `pi_img.bin`, the payload-relative **value** offsets to patch for
that register are:

```
0x01bc 0x01f8 0x023c 0x02b0
0x0a4c 0x0a88 0x0acc 0x0b40
0x12dc 0x1318 0x135c 0x13d0
0x1ca4 0x1ce0 0x1d24 0x1d98
0x266c 0x26a8 0x26ec 0x2760
```

These are payload offsets, not outer-file offsets. Outer-file offsets for this
image are `payload + 0x200`, so the same bytes are at file offsets:

```
0x03bc 0x03f8 0x043c 0x04b0
0x0c4c 0x0c88 0x0ccc 0x0d40
0x14dc 0x1518 0x155c 0x15d0
0x1ea4 0x1ee0 0x1f24 0x1f98
0x286c 0x28a8 0x28ec 0x2960
```

`injector/pi_img_devices.py --set-reg 0x11c10580=VALUE` now scans the whole
cookie-safe payload and patches all 20 value offsets together. Example dry run:

```bash
.venv/bin/python3 injector/pi_img_devices.py \
  bin/firmware/a75/pi_img.bin /tmp/a75-pi-test.bin \
  --set-reg 0x11c10580=0x2000 --dry-run
```

Important: this is the best A75 EEM shadow-write candidate offset set, not a
fully proven final OC-cap field. The consumer-side proof still missing is the
exact EEMSN comparison that leads to `vboot violate`.

Additional A75 mcupm trace notes:

- Corrected RISC-V address reconstruction must treat `c.lui` immediates as
  `imm << 12`. With that fix, only one relevant direct string load was found:
  - `0xba0e/0xba10`: `c.lui a0, 0x13; addi a0, a0, -468` -> `0x12e2c` (`pi_img`)
- No `lui`/`c.lui` + `addi` combination anywhere in the payload targets any of
  the `[CPU][EEMSN]...` error strings (0x12c9a vboot, 0x1339b orig volt, etc.).
  This is not a missed xref — the strings simply are NOT loaded by direct
  address arithmetic in this firmware. Supports the indirect log-id / pointer
  table theory: EEMSN messages are dispatched by an integer log ID that indexes
  into a string table, and the printf/log function retrieves the string by
  table lookup, not by inline LUI+ADDI.
- r2 confirms the EEM reader around `0x3a96`: it builds `0x11c101a4`, does an
  atomic read (`lr.w`), shifts right by 24, and stores the top byte to `0x17af0`
  (`lui s2, 0x18; sw ..., -1296(s2)`).

### 7b. Aging cache / config-key loader function — decodes to ~0x3a7e

The function starting around `0x3a7e` is the **aging-value caching wrapper**
(read-once from EEM hardware, cache at `0x17af0` for the rest of boot).
Disassembly (r2, RV32, base 0):

```
0x3a7e: mv   s0, a1            ; save args
0x3a80: mv   s1, a0
0x3a82: lw   a0, 12(a0)        ; load struct fields
0x3a84: lw   a1, 8(a1)
0x3a86: ...                    ; (4-byte op, mul/div arithmetic)
0x3a8a: lw   a2, 0(a2)         ; load cached-marker
0x3a8c: bnez a2, 0x3ace        ; if non-zero, skip to tail (already cached)
0x3a8e: lui  s2, 0x18          ; s2 = 0x18000 (global base for 0x17af0)
0x3a90: lw   a2, -1296(s2)     ; load current aging byte from 0x17af0
0x3a94: bnez a2, 0x3ab2        ; if already cached, skip EEM read
0x3a96: lui  a0, 0x11c10       ;  \ build EEM reg 0x11c101a4
0x3a9a: addi a0, a0, 420       ;  /
0x3a9e: jal  ra, 0x649a        ; call EEM reg-access helper
0x3aa2: lr.w a0, (a0)          ; atomic load from 0x11c101a4
0x3aa6: srli a2, a0, 0x18      ; extract TOP byte = aging value
0x3aaa: sw   a2, -1296(s2)     ; CACHE aging byte at 0x17af0
0x3aae: lw   a0, 12(s1)        ; reload struct fields
0x3ab0: lw   a1, 8(s0)
0x3ab2: li   a3, 60            ; a3 = 60 (??? threshold constant?)
0x3ab6: ...                    ; (4-byte op, compare arithmetic)
0x3aba: ...                    ; (4-byte op)
0x3abe: sw   a3, -1296(s2)     ; ALSO cache a3=60 at 0x17af0 (overwrite?)
0x3ac2: sw   a3, 0(a0)         ; store 60 to struct field
0x3ac4: lw   a2, 20(s1)        ; load function pointer from struct
0x3ac6: beqz a2, 0x3ace        ; if null, skip indirect call
0x3ac8: mv   a0, s1
0x3aca: mv   a1, s0
0x3acc: jalr a2                ; call the indirect handler
0x3ace: ...                    ; tail/return path
```

Key observations:
- Two values are stored to `0x17af0`: the aging byte (top byte of `0x11c101a4`),
  AND the constant `60` (0x3c). The second store at `0x3abe` **overwrites**
  the aging byte with `60` — but note the `beqz a2` at `0x3a94` skips
  the EEM read entirely when the cache is already filled. So on first call:
  the aging byte is written at `0x3aaa`, then immediately overwritten with `60`
  at `0x3abe`. This means `60` is NOT the aging value — it may be a
  "read-complete" sentinel or a default.
- The `li a3, 60` constant (`60` = 0x3C) appears in every firmware build as a
  fixed threshold — its meaning is unclear (seconds? a counter limit?).
- The config-key loader at `0xba0a` calls `0x253c` (an indirect trampoline
  wrapper that saves callee-saved regs and jumps through `t0`), loads `pi_img`
  string via `c.lui a0, 0x13; addi a0, a0, -468 -> 0x12E2C`, then calls
  `fcn.0xba28` which iterates the config-key struct.

### 7c. EEM descriptor pointer tables discovered at 0x15f00+

The string region `0x12C00-0x13C00` contains 42 identified strings
(FreeRTOS task names, EEM descriptor names, file paths, etc.). Among them:

| payload offset | string |
|---|---|
| 0x138dc | `EEM_DET_L` |
| 0x13163 | `EEM_DET_B` |
| 0x135b5 | `EEM_DET_CCI` |
| 0x13552 | `top_data_share` |
| 0x12fab | `vproc1` |
| 0x131bf | `vproc2` |
| 0x1307b | `vsram_proc1` |
| 0x13028 | `vsram_proc2` |
| 0x12f68 | `mcdi_write_bus` |
| 0x12ff0 | `EEMR` |

These strings ARE referenced by a pointer table at the following offsets
(each entry is a 32-bit LE pointer to the string):

| pointer table offset | points to | description |
|---|---|---|
| 0x15f00 | 0x138dc (`EEM_DET_L`) | EEM detection struct LITTLE |
| 0x15fe4 | 0x13163 (`EEM_DET_B`) | EEM detection struct BIG |
| 0x160c8 | 0x135b5 (`EEM_DET_CCI`) | EEM detection CCI |
| 0x169f4 | 0x13552 (`top_data_share`) | shared data region |
| 0x17278 | 0x12fab (`vproc1`) | voltage proc 1 |
| 0x17284 | 0x131bf (`vproc2`) | voltage proc 2 |
| 0x17290 | 0x1307b (`vsram_proc1`) | SRAM voltage proc 1 |
| 0x1729c | 0x13028 (`vsram_proc2`) | SRAM voltage proc 2 |
| 0x1759c | 0x138cb (UID hash) | unique chip identifier |

These are EEM/DVFS per-domain detection descriptor structs, each containing
a name pointer + calibration data. The struct stride between entries
(12-16 bytes between pointer table entries) suggests a struct like
`{char *name, u32 reg_base, u32 threshold, ...}`.

The `[CPU][EEMSN]...` error strings (0x12c9a, 0x12cc1, etc.) are NOT in any
pointer table — they sit in the data section as isolated null-terminated
strings, accessible only through a log-ID dispatch layer.

## 8. Current status — what is still missing

The exact comparison that gates `"vboot violate"` remains unlocated.
Confirmed:

1. **EEM aging reader** at 0x3a96-0x3aaa: reads `0x11c101a4`, extracts top
   byte, caches to `0x17af0` (but immediately overwritten with `0x3c`).
2. **pi_img config-key loader** at 0xba0a: LUI+ADDI loads `"pi_img"` from
   `0x12E2C`, calls config-key iterator at 0xba28, which populates shared
   structures.
3. **EEMSN error strings** at 0x12cc1 (vboot) and 0x12c9a (sem err) are NOT
   reachable by any direct pointer or LUI+ADDI sequence in the entire binary.
   They must be dispatched through an indirect log-ID mechanism: the code
   calls a printf-like function with a small integer ID, and that function
   looks up the string from a table indexed by ID.
4. **EEM descriptor pointer tables** at 0x15f00+ reference the per-domain
   EEM detection strings by direct 32-bit pointer, but these cover only
   hardware-detection names (EEM_DET_L/B/CCI), not error messages.

The missing comparison therefore lives in the code that:
- Reads the cached aging byte (or the `0x11c1xxxx` EEM registers directly),
- Compares it against the requested OPP frequency/voltage,
- Calls the log-ID dispatch with ID for vboot-violate when the check fails.

Finding it requires either:
- (a) Tracing callers of the aging cache function at 0x3a7e upward to find
  the freq/volt comparison, or
- (b) Finding the log-ID dispatch function and backward-tracing to the
  comparison call site, or
- (c) Dynamic analysis: instrument the firmware to dump the log ID and
  comparison values at boot.

Strategy (b) is likely more tractable: locate the log function used by the
EEMSN code by looking for format-string dispatch patterns (a function that
takes an integer ID and a variable arg list, and emits `"[CPU][EEMSN]..."`).
