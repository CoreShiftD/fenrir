#!/usr/bin/env python3
"""
patch_raw_capability.py — Capability-tier enforcer for MediaTek camera sensors

Usage:
    # Default replace mode: find BURST_CAPTURE(6) slot, replace with RAW(3)
    python3 patch_raw_capability.py libmtkcam_metastore.so

    # Tier mode (recommended): ensure RAW + BURST_CAPTURE via trampoline
    python3 patch_raw_capability.py libmtkcam_metastore.so --tier=RAW,BURST_CAPTURE

    # Tier mode with replace fallback (no BIND_NOW binary)
    python3 patch_raw_capability.py libmtkcam_metastore.so --tier=RAW --allow-replace

    # Append mode (legacy alias for --tier=RAW,BURST_CAPTURE)
    python3 patch_raw_capability.py libmtkcam_metastore.so --append

    # Manual VA mode
    python3 patch_raw_capability.py libmtkcam_metastore.so --va 0x3f628

    # Dry run
    python3 patch_raw_capability.py libmtkcam_metastore.so --tier=3,6 --dry-run

    # List only
    python3 patch_raw_capability.py libmtkcam_metastore.so --list

Tier mode (recommended):
    --tier defines a minimum set of capabilities a sensor must expose.  For each
    sensor the script checks what's already present; if all tier caps are present
    the sensor is skipped.  Missing caps are appended via a dynamic trampoline in
    the .text→.plt gap + dead PLT[0] region.

    Capabilities are ordered with RAW(3) first, then the rest.  Example tiers:
      --tier=3               ensure RAW only
      --tier=RAW,BURST_CAPTURE  ensure RAW + BURST_CAPTURE (same as --append)
      --tier=1,2,3           ensure MANUAL_SENSOR + MANUAL_POST_PROC + RAW

    The trampoline approach requires BIND_NOW and enough cave space.  Pass
    --allow-replace to fall back to single-slot replacement when the trampoline
    cannot be used (only the first missing cap gets added in that case).

Replace mode (default, no --tier):
    Patches BURST_CAPTURE(6) slot → RAW(3), replacing the value in place.
    Use --replace=N to target a different slot, --allow-fallback to replace
    the last cap if the target slot is not found.

AArch64 encoding:
    movz w8, #N  →  bytes: (0x52800008 | (N << 5)) little-endian
    movz w8, #3  →  52 80 00 68  (file bytes: 68 00 80 52)
    movz w8, #6  →  52 80 00 c8  (file bytes: c8 00 80 52)
    movz w8, #N  →  file bytes: (8 | (N<<5)&0xff), 0x00, 0x80, 0x52
    B  <target>  →  0x14000000 | (offset_in_insns & 0x3FFFFFF)
    BL <target>  →  0x94000000 | (offset_in_insns & 0x3FFFFFF)
"""

import sys
import struct
import hashlib
import argparse
import subprocess
from pathlib import Path

# Capability values
CAP_BACKWARD_COMPATIBLE   = 0
CAP_MANUAL_SENSOR         = 1
CAP_MANUAL_POST_PROCESSING = 2
CAP_RAW                   = 3
CAP_PRIVATE_REPROCESSING  = 4
CAP_READ_SENSOR_SETTINGS  = 5
CAP_BURST_CAPTURE         = 6
CAP_READ_SENSOR_SETTINGS2 = 7
CAP_DEPTH_OUTPUT          = 8
CAP_HIGH_SPEED_VIDEO      = 9

CAP_NAMES = {
    0: 'BACKWARD_COMPATIBLE',
    1: 'MANUAL_SENSOR',
    2: 'MANUAL_POST_PROCESSING',
    3: 'RAW',
    4: 'PRIVATE_REPROCESSING',
    5: 'READ_SENSOR_SETTINGS',
    6: 'BURST_CAPTURE',
    7: 'READ_SENSOR_SETTINGS_2',
    8: 'DEPTH_OUTPUT',
    9: 'HIGH_SPEED_VIDEO',
    10: 'CONSTRAINED_HIGH_SPEED_VIDEO',
    11: 'MOTION_TRACKING',
    12: 'LOGICAL_MULTI_CAMERA',
    13: 'MONOCHROME',
    14: 'SECURE_IMAGE_DATA',
    15: 'SYSTEM_CAMERA',
    16: 'OFFLINE_PROCESSING',
    17: 'ULTRA_HIGH_RESOLUTION_SENSOR',
    18: 'REMOSAIC_REPROCESSING',
    19: 'DYNAMIC_RANGE_TEN_BIT',
    20: 'STREAM_USE_CASE',
    21: 'COLOR_SPACE_PROFILES',
}

# Sensor name suffixes that should NOT be patched — sub-modes, not physical sensors
SKIP_SUFFIXES = (
    '_securecamera',
    '_bayermono',
    '_bayerbayer',
    '_bayerwide',
    '_dummy',
    '_satcam',
    '_vsdof',
    '_lvsdof',
    '_fvsdof',
    '_dualzoom',
    '_tricam',
    '_trivsdof',
    '_trizvsdof',
    '_staggerTriZoom',
    '_staggerZoom',
    '_securecamera',
)

TAG_CAPABILITIES = 0xc000c  # ANDROID_REQUEST_AVAILABLE_CAPABILITIES

# AArch64 instruction words (little-endian 32-bit)
MOVZ_W8_BASE     = 0x52800008   # movz w8, #0 — base; value bits at [20:5]
STRB_W8_SP16     = 0x390043e8   # strb w8, [sp, #16]
STRB_W8_SP32     = 0x390083e8   # strb w8, [sp, #32]
STRBWZR_SP16     = 0x390043ff   # strb wzr, [sp, #16] (push value 0)
SUB_X0_X29_0x50  = 0xd10143a0   # sub x0, x29, #0x50
ADD_X1_SP_0x10   = 0x910043e1   # add x1, sp, #0x10
ADD_X1_SP_0x20   = 0x910083e1   # add x1, sp, #0x20
STP_X29_X30_PRE16 = 0xa9bf7bfd  # stp x29, x30, [sp, #-16]!
LDP_X29_X30_POST16 = 0xa8c17bfd # ldp x29, x30, [sp], #16
RET              = 0xd65f03c0   # ret

MOV_W1_C000C_LO  = 0x320e87e1   # mov w1, #0xc000c (lower half of pair)

# PLT[0] is 32 bytes (two 16-byte slots) in AArch64 bionic — all dead with BIND_NOW
PLT0_SIZE = 32


def strb_w8_sp(offset: int) -> int:
    """Encode strb w8, [sp, #offset] (unsigned 12-bit immediate)."""
    return 0x390003e8 | ((offset & 0xfff) << 10)


def add_x1_sp(imm: int) -> int:
    """Encode ADD X1, SP, #imm (12-bit unsigned immediate, LSL #0)."""
    return 0x910003e1 | ((imm & 0xfff) << 10)


# ── ELF / encoding helpers ─────────────────────────────────────────────────────

def movz_w8_encode(n: int) -> bytes:
    """Encode movz w8, #n as little-endian 4 bytes."""
    word = MOVZ_W8_BASE | ((n & 0xffff) << 5)
    return struct.pack('<I', word)


def movz_w8_decode(b: bytes) -> int | None:
    """If bytes are movz w8, #N return N, else None."""
    if len(b) < 4:
        return None
    word = struct.unpack('<I', b[:4])[0]
    if (word & 0xffe0001f) == MOVZ_W8_BASE:
        return (word >> 5) & 0xffff
    return None


def read_word(data: bytes, offset: int) -> int:
    return struct.unpack_from('<I', data, offset)[0]


def encode_branch(from_va: int, to_va: int, link: bool = False) -> bytes:
    """Encode AArch64 B (link=False) or BL (link=True) as 4 LE bytes."""
    offset = (to_va - from_va) // 4
    if offset < -(1 << 25) or offset >= (1 << 25):
        raise ValueError(
            f"Branch out of range: 0x{from_va:x} → 0x{to_va:x} (offset {offset:+d})")
    imm26 = offset & 0x3FFFFFF
    opcode = 0x94000000 if link else 0x14000000
    return struct.pack('<I', opcode | imm26)


def va_to_offset(va: int, load_segments: list) -> int | None:
    """Convert virtual address to file offset using PT_LOAD segments."""
    for (p_vaddr, p_offset, p_filesz) in load_segments:
        if p_vaddr <= va < p_vaddr + p_filesz:
            return va - p_vaddr + p_offset
    return None


def offset_to_va(file_off: int, load_segments: list) -> int | None:
    """Convert file offset to virtual address using PT_LOAD segments."""
    for (p_vaddr, p_offset, p_filesz) in load_segments:
        if p_offset <= file_off < p_offset + p_filesz:
            return file_off - p_offset + p_vaddr
    return None


def decode_branch_target(data: bytes, file_off: int, load_segments: list,
                         link: bool | None = None) -> int | None:
    """Decode B/BL at file_off; return target VA, or None if opcode mismatch."""
    word = struct.unpack_from('<I', data, file_off)[0]
    opcode = word >> 26
    if link is True and opcode != 0b100101:
        return None
    if link is False and opcode != 0b000101:
        return None
    if link is None and opcode not in (0b000101, 0b100101):
        return None
    imm26 = word & 0x3FFFFFF
    if imm26 & (1 << 25):  # sign-extend
        imm26 -= (1 << 26)
    from_va = offset_to_va(file_off, load_segments)
    if from_va is None:
        return None
    return from_va + imm26 * 4


def decode_bl_target(data: bytes, file_off: int, load_segments: list) -> int | None:
    """Decode BL at file_off; return target VA, or None if not a BL."""
    return decode_branch_target(data, file_off, load_segments, link=True)


# ── ELF parsing ───────────────────────────────────────────────────────────────

def parse_elf(data: bytes):
    """Parse ELF64 LE: return (load_segments, symbols)."""
    assert data[:4] == b'\x7fELF', "Not an ELF file"
    e_phoff     = struct.unpack_from('<Q', data, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
    e_phnum     = struct.unpack_from('<H', data, 0x38)[0]
    e_shoff     = struct.unpack_from('<Q', data, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', data, 0x3a)[0]
    e_shnum     = struct.unpack_from('<H', data, 0x3c)[0]
    e_shstrndx  = struct.unpack_from('<H', data, 0x3e)[0]

    # PT_LOAD segments
    load_segments = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type   = struct.unpack_from('<I', data, off)[0]
        p_offset = struct.unpack_from('<Q', data, off + 0x08)[0]
        p_vaddr  = struct.unpack_from('<Q', data, off + 0x10)[0]
        p_filesz = struct.unpack_from('<Q', data, off + 0x20)[0]
        if p_type == 1:  # PT_LOAD
            load_segments.append((p_vaddr, p_offset, p_filesz))

    # Section headers
    shstrtab_off = None
    sections_raw = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh = {
            'name_idx': struct.unpack_from('<I',  data, off)[0],
            'type':     struct.unpack_from('<I',  data, off + 4)[0],
            'flags':    struct.unpack_from('<Q',  data, off + 8)[0],
            'addr':     struct.unpack_from('<Q',  data, off + 16)[0],
            'offset':   struct.unpack_from('<Q',  data, off + 24)[0],
            'size':     struct.unpack_from('<Q',  data, off + 32)[0],
            'link':     struct.unpack_from('<I',  data, off + 40)[0],
            'entsize':  struct.unpack_from('<Q',  data, off + 56)[0],
        }
        sections_raw.append(sh)

    if e_shstrndx < len(sections_raw):
        shstrtab_off = sections_raw[e_shstrndx]['offset']

    def sh_name(sh):
        if shstrtab_off is None:
            return ''
        idx = sh['name_idx']
        end = data.index(b'\x00', shstrtab_off + idx)
        return data[shstrtab_off + idx:end].decode('utf-8', errors='replace')

    dynsym = dynstr = None
    sections_by_name = {}
    for sh in sections_raw:
        name = sh_name(sh)
        sections_by_name[name] = sh
        if name == '.dynsym':
            dynsym = sh
        elif name == '.dynstr':
            dynstr = sh

    symbols = []
    if dynsym and dynstr:
        sym_data = data[dynsym['offset']:dynsym['offset'] + dynsym['size']]
        str_data = data[dynstr['offset']:dynstr['offset'] + dynstr['size']]
        entsize  = dynsym['entsize'] or 24
        for i in range(0, len(sym_data), entsize):
            if i + entsize > len(sym_data):
                break
            st_name  = struct.unpack_from('<I', sym_data, i)[0]
            st_value = struct.unpack_from('<Q', sym_data, i + 8)[0]
            st_size  = struct.unpack_from('<Q', sym_data, i + 16)[0]
            st_info  = sym_data[i + 4]
            if st_value == 0:
                continue
            end  = str_data.index(b'\x00', st_name)
            name = str_data[st_name:end].decode('utf-8', errors='replace')
            symbols.append({'name': name, 'va': st_value, 'size': st_size, 'info': st_info})

    return load_segments, symbols, sections_by_name


def check_bind_now(data: bytes) -> bool:
    """Return True if DT_FLAGS has DF_BIND_NOW or DT_FLAGS_1 has DF_1_NOW."""
    DF_BIND_NOW = 0x8
    DF_1_NOW    = 0x1

    e_phoff     = struct.unpack_from('<Q', data, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
    e_phnum     = struct.unpack_from('<H', data, 0x38)[0]

    dyn_off = dyn_size = None
    for i in range(e_phnum):
        off    = e_phoff + i * e_phentsize
        p_type = struct.unpack_from('<I', data, off)[0]
        if p_type == 2:  # PT_DYNAMIC
            dyn_off  = struct.unpack_from('<Q', data, off + 8)[0]
            dyn_size = struct.unpack_from('<Q', data, off + 32)[0]
            break

    if dyn_off is None:
        return False

    i = 0
    while i + 16 <= dyn_size:
        d_tag = struct.unpack_from('<q', data, dyn_off + i)[0]
        d_val = struct.unpack_from('<Q', data, dyn_off + i + 8)[0]
        if d_tag == 0x1e:           # DT_FLAGS
            if d_val & DF_BIND_NOW:
                return True
        elif d_tag == 0x6ffffffb:   # DT_FLAGS_1
            if d_val & DF_1_NOW:
                return True
        elif d_tag == 0:            # DT_NULL
            break
        i += 16

    return False


# ── Cave / trampoline ─────────────────────────────────────────────────────────

def find_cave(data: bytes, sections: dict, load_segments: list, need_bytes: int = 36):
    """
    Find a safe executable cave for the trampoline.

    Uses the zero gap between .text end and .plt start (12 bytes) plus the
    dead PLT[0] resolver stub (32 bytes).  PLT[0] is never called at runtime
    when BIND_NOW is set; overwriting it is safe.

    Returns (cave_va, cave_file_off, available_size) or None.
    """
    text = sections.get('.text')
    plt  = sections.get('.plt')
    if not text or not plt:
        return None

    text_end_off  = text['offset'] + text['size']
    plt_start_off = plt['offset']

    if plt_start_off <= text_end_off:
        return None

    gap       = plt_start_off - text_end_off
    available = gap + PLT0_SIZE   # gap + dead PLT[0]

    if available < need_bytes:
        return None

    cave_va = offset_to_va(text_end_off, load_segments)
    if cave_va is None:
        return None

    return (cave_va, text_end_off, available)


def build_tier_cave(cave_va: int, push_back_va: int,
                    extra_values: list[int]) -> bytes:
    """
    Build a dynamic trampoline cave for multiple extra capabilities.

    On entry: x0=IEntry*, x1=ptr to slot value at caller's sp+16.
    The slot's value (already stored by caller's strb) is pushed first,
    then each value in extra_values is pushed.

    Layout (16 + 20*K bytes for K extra values):
      stp x29, x30, [sp, #-16]!
      bl push_back              ; push slot value
      for k, val in enumerate(extra_values):
        movz w8, #val
        strb w8, [sp, #32+16*k]
        sub x0, x29, #0x50
        add x1, sp, #0x20+16*k
        bl push_back
      ldp x29, x30, [sp], #16
      ret
    """
    out = bytearray()
    pos = cave_va

    out += struct.pack('<I', STP_X29_X30_PRE16);           pos += 4
    out += encode_branch(pos, push_back_va, link=True);    pos += 4

    for k, val in enumerate(extra_values):
        store_off = 32 + k * 16
        ptr_off   = 0x20 + k * 16
        out += struct.pack('<I', MOVZ_W8_BASE | ((val & 0xffff) << 5)); pos += 4
        out += struct.pack('<I', strb_w8_sp(store_off));   pos += 4
        out += struct.pack('<I', SUB_X0_X29_0x50);         pos += 4
        out += struct.pack('<I', add_x1_sp(ptr_off));      pos += 4
        out += encode_branch(pos, push_back_va, link=True); pos += 4

    out += struct.pack('<I', LDP_X29_X30_POST16);          pos += 4
    out += struct.pack('<I', RET)

    return bytes(out)


def build_append_cave(cave_va: int, push_back_va: int,
                      burst_cap: int) -> bytes:
    """
    Build 36-byte (9-instruction) shared trampoline cave (legacy).
    Delegates to build_tier_cave for backward compatibility.
    """
    return build_tier_cave(cave_va, push_back_va, [burst_cap])


# ── Capability block scanner ───────────────────────────────────────────────────

def find_capability_patch_site(data: bytes, func_va: int, func_size: int,
                                load_segments: list) -> dict | None:
    """
    Within a PLATFORM_PROJECT function, find the 0xc000c capability block and
    return info about where to patch.

    Returns dict with:
      capabilities: list of (file_offset, value) for each push_back slot
      tag_file_offset: file offset of 'mov w1, #0xc000c' instruction
    or None if not found.
    """
    func_off = va_to_offset(func_va, load_segments)
    if func_off is None:
        return None

    size = func_size if func_size > 0 else 0x800
    body = data[func_off:func_off + size]

    tag_pattern = struct.pack('<I', MOV_W1_C000C_LO)
    tag_pos = body.find(tag_pattern)
    if tag_pos < 0:
        return None

    tag_file_off = func_off + tag_pos
    capabilities = []
    i   = tag_pos + 4
    end = min(len(body), tag_pos + 0x100)

    while i < end - 4:
        w = read_word(body, i)

        if w == STRBWZR_SP16:
            if (i + 12 < end and
                    read_word(body, i + 4) == SUB_X0_X29_0x50 and
                    read_word(body, i + 8) == ADD_X1_SP_0x10):
                capabilities.append((func_off + i - 4, 0))
                i += 16
                continue

        n = movz_w8_decode(body[i:i+4])
        if n is not None and 0 < n <= 21:
            if i + 4 < end and read_word(body, i + 4) == STRB_W8_SP16:
                if (i + 16 < end and
                        read_word(body, i + 8)  == SUB_X0_X29_0x50 and
                        read_word(body, i + 12) == ADD_X1_SP_0x10):
                    capabilities.append((func_off + i, n))
                    i += 16
                    continue

        if w == SUB_X0_X29_0x50:
            break

        i += 4

    return {
        'tag_file_offset': tag_file_off,
        'capabilities':    capabilities,
    }


# ── File patching ──────────────────────────────────────────────────────────────

def sensor_name_from_symbol(sym_name: str) -> str:
    prefix = 'constructCustStaticMetadata_PLATFORM_PROJECT_SENSOR_DRVNAME_'
    if sym_name.startswith(prefix):
        return sym_name[len(prefix):]
    return sym_name


def patch_file(path: Path, patches: list[tuple[int, bytes]], dry_run: bool) -> bool:
    if dry_run:
        print("[DRY RUN] Would apply patches:")
        for off, b in patches:
            print(f"  offset 0x{off:x}: → {b.hex()}")
        return True

    data = bytearray(path.read_bytes())
    for off, b in patches:
        data[off:off+len(b)] = b
    path.write_bytes(bytes(data))
    md5 = hashlib.md5(bytes(data)).hexdigest()
    print(f"Patched. MD5: {md5}")
    return True


# ── Append-mode logic ──────────────────────────────────────────────────────────

def do_append(path: Path, data: bytes, sym: dict, load_segments: list,
              sections: dict, dry_run: bool, sensor_name: str):
    """
    Add RAW alongside BURST_CAPTURE via a shared trampoline in the PLT[0] cave.
    Safe only when BIND_NOW is set (PLT[0] is never called at runtime).
    """
    result = find_capability_patch_site(data, sym['va'], sym['size'], load_segments)
    if result is None:
        print(f"  {sensor_name}: [SKIP] no 0xc000c block found")
        return

    caps      = result['capabilities']
    cap_vals  = [v for _, v in caps]
    cap_str   = ' '.join(f"{CAP_NAMES.get(v, str(v))}({v})" for v in cap_vals)

    if CAP_RAW in cap_vals and CAP_BURST_CAPTURE in cap_vals:
        print(f"  {sensor_name}: both RAW and BURST_CAPTURE present  [{cap_str}]")
        return

    slot = next(((off, v) for off, v in caps if v == CAP_BURST_CAPTURE), None)
    if slot is None:
        slot = next(((off, v) for off, v in caps if v == CAP_RAW), None)
    if slot is None:
        print(f"  {sensor_name}: [SKIP] no BURST_CAPTURE or RAW slot found  [{cap_str}]")
        return

    if not check_bind_now(data):
        print(f"  {sensor_name}: [SKIP] BIND_NOW not set; PLT[0] cave is unsafe")
        return

    cave = find_cave(data, sections, load_segments, need_bytes=36)
    if cave is None:
        print(f"  {sensor_name}: [SKIP] no suitable cave found (need 36B near .text/.plt gap)")
        return
    cave_va, cave_off, cave_avail = cave

    slot_off, slot_val = slot
    call_off = slot_off + 16   # call push_back is always 4 instructions after movz
    call_va = offset_to_va(call_off, load_segments)
    if call_va is None:
        print(f"  {sensor_name}: [SKIP] cannot compute VA for callsite")
        return

    call_word = read_word(data, call_off)
    opcode = call_word >> 26
    old_b_to_cave = False
    if opcode == 0b100101:  # BL
        target_va = decode_branch_target(data, call_off, load_segments, link=True)
        if target_va == cave_va:
            print(f"  {sensor_name}: shared trampoline already applied (BL cave at 0x{call_off:x})")
            return
        push_back_va = target_va
    elif opcode == 0b000101:  # old broken append mode used B cave
        target_va = decode_branch_target(data, call_off, load_segments, link=False)
        if target_va != cave_va:
            print(f"  {sensor_name}: [SKIP] unexpected B target at 0x{call_off:x}: "
                  f"0x{target_va:x} (expected cave 0x{cave_va:x})")
            return
        old_b_to_cave = True
        push_back_va = decode_bl_target(data, cave_off, load_segments)
        if push_back_va is None:
            push_back_va = decode_bl_target(data, cave_off + 4, load_segments)
        if push_back_va is None:
            print(f"  {sensor_name}: [SKIP] old trampoline has no decodable push_back BL")
            return
    else:
        print(f"  {sensor_name}: [SKIP] unexpected instruction at 0x{call_off:x}: "
              f"0x{call_word:08x} (expected BL/B)")
        return

    print(f"  {sensor_name}: appending BURST_CAPTURE({CAP_BURST_CAPTURE}) via shared trampoline")
    print(f"    slot 0x{call_va - 16:x}: cap={slot_val} ({CAP_NAMES.get(slot_val,'?')})")
    print(f"    push_back PLT: 0x{push_back_va:x}")
    print(f"    trampoline: call@0x{call_va:x} -> bl cave@0x{cave_va:x}")
    print(f"    cave: 36B at file 0x{cave_off:x}..0x{cave_off+36:x}  "
          f"(avail {cave_avail}B)")
    if old_b_to_cave:
        print(f"    repair: old B cave callsite will become BL cave")

    patches = []

    if slot_val == CAP_BURST_CAPTURE:
        patches.append((slot_off, movz_w8_encode(CAP_RAW)))
        print(f"    patch[0]: 0x{slot_off:x}  movz w8,#6 -> movz w8,#3 (RAW)")

    bl_cave = encode_branch(call_va, cave_va, link=True)
    patches.append((call_off, bl_cave))
    print(f"    patch[1]: 0x{call_off:x}  call push_back -> bl 0x{cave_va:x}")

    cave_code = build_append_cave(cave_va, push_back_va, CAP_BURST_CAPTURE)
    patches.append((cave_off, cave_code))
    print(f"    patch[2]: cave  {cave_code.hex()}")

    patch_file(path, patches, dry_run)


# ── Tier mode logic ──────────────────────────────────────────────────────────

CAP_NAME_MAP = {v: k for k, v in CAP_NAMES.items()}


def parse_tier(value: str) -> list[int]:
    """Parse --tier argument: '3,6' → [3, 6], 'RAW,BURST_CAPTURE' → [3, 6]."""
    result = []
    for token in value.split(','):
        token = token.strip()
        if not token:
            continue
        if token.isdigit():
            result.append(int(token))
        elif token.upper() in CAP_NAME_MAP:
            result.append(CAP_NAME_MAP[token.upper()])
        else:
            raise ValueError(f"Unknown capability: {token!r}")
    return result


def do_ensure_tier(path: Path, data: bytes, sym: dict, load_segments: list,
                   sections: dict, dry_run: bool, sensor_name: str,
                   tier_caps: list[int], allow_replace: bool = False):
    """
    Ensure a sensor exposes all capabilities in `tier_caps`.

    Strategy:
      1. Scan the sensor's 0xc000c capability block.
      2. Find which tier caps are missing.
      3. If none → skip.
      4. Pick SLOT: prefer BURST_CAPTURE, else last cap position.
      5. SLOT gets the first missing cap, with RAW(3) sorted first.
      6. If BIND_NOW + cave fits remaining caps → build trampoline.
      7. Else if allow_replace → single-slot replace (first missing cap only).
      8. Else → warn and skip.
    """
    result = find_capability_patch_site(data, sym['va'], sym['size'], load_segments)
    if result is None:
        print(f"  {sensor_name}: [SKIP] no 0xc000c block found")
        return

    caps      = result['capabilities']
    cap_vals  = [v for _, v in caps]
    cap_str   = ' '.join(f"{CAP_NAMES.get(v, str(v))}({v})" for v in cap_vals)

    missing = [c for c in tier_caps if c not in cap_vals]
    if not missing:
        print(f"  {sensor_name}: all tier caps present  [{cap_str}]")
        return

    # Order missing caps: RAW(3) first, then by value
    ordered = sorted(missing, key=lambda c: (0 if c == CAP_RAW else 1, c))

    # Pick a slot to repurpose — never replace a cap the tier requires.
    # 1) BURST_CAPTURE(6) if it is NOT a tier cap itself (common optional)
    slot = None
    if CAP_BURST_CAPTURE not in tier_caps:
        slot = next(((off, v) for off, v in caps if v == CAP_BURST_CAPTURE), None)
    # 2) Last non-tier cap (scan from end so we touch least-important-looking values)
    if slot is None:
        for off, v in reversed(caps):
            if v not in tier_caps:
                slot = (off, v)
                break
    # 3) All slots hold tier-required values — take the last one anyway
    if slot is None:
        slot = caps[-1] if caps else None
        if slot and slot[1] in tier_caps:
            print(f"    (all slots are tier-caps — "
                  f"replacing {CAP_NAMES.get(slot[1],slot[1])}({slot[1]}))")
    if slot is None:
        print(f"  {sensor_name}: [SKIP] no usable slot found")
        return

    slot_off, slot_val = slot
    first_cap = ordered[0]
    remaining = ordered[1:]

    if slot_val == first_cap and not remaining:
        print(f"  {sensor_name}: {CAP_NAMES.get(first_cap, first_cap)} already at slot "
              f"0x{slot_off:x}  [{cap_str}]")
        return

    missing_str = ', '.join(f"{CAP_NAMES.get(c,str(c))}({c})" for c in missing)
    print(f"  {sensor_name}: missing {missing_str}  [{cap_str}]")
    print(f"    slot 0x{slot_off:x}: {CAP_NAMES.get(slot_val,str(slot_val))}({slot_val}) "
          f"→ {CAP_NAMES.get(first_cap,str(first_cap))}({first_cap})")
    if remaining:
        extra_str = ', '.join(f"{CAP_NAMES.get(c,str(c))}({c})" for c in remaining)
        print(f"    extras: {extra_str}")

    needed = 16 + 20 * len(remaining)

    # If no extra caps needed, just do a simple slot replace (no trampoline)
    if not remaining:
        if first_cap == slot_val:
            print(f"  {sensor_name}: already correct  [{cap_str}]")
            return
        name = CAP_NAMES.get(first_cap, str(first_cap))
        print(f"    simple replace: slot 0x{slot_off:x} → {first_cap}({name})")
        patch_file(path, [(slot_off, movz_w8_encode(first_cap))], dry_run)
        return

    # ── Try trampoline for remaining caps ─────────────────────────────────
    trampoline_ok = False
    push_back_va = None
    call_off = call_va = cave = None

    if check_bind_now(data):
        cave = find_cave(data, sections, load_segments, need_bytes=needed)
        if cave:
            cave_va, cave_off, cave_avail = cave
            call_off = slot_off + 16
            call_va  = offset_to_va(call_off, load_segments)

            if call_va is not None:
                call_word = read_word(data, call_off)
                opcode = call_word >> 26

                push_back_va = decode_bl_target(data, call_off, load_segments)
                if push_back_va is None and opcode == 0b000101:
                    old_target = decode_branch_target(
                        data, call_off, load_segments, link=False)
                    if old_target == cave_va:
                        push_back_va = (
                            decode_bl_target(data, cave_off, load_segments) or
                            decode_bl_target(data, cave_off + 4, load_segments)
                        )

                if push_back_va is not None:
                    trampoline_ok = True

    if trampoline_ok:
        patches = []

        if first_cap != slot_val:
            patches.append((slot_off, movz_w8_encode(first_cap)))
            print(f"    patch[0]: 0x{slot_off:x}  movz w8,#{slot_val} → "
                  f"movz w8,#{first_cap} ({CAP_NAMES.get(first_cap,str(first_cap))})")

        bl_cave = encode_branch(call_va, cave_va, link=True)
        patches.append((call_off, bl_cave))
        print(f"    patch[1]: 0x{call_off:x}  call push_back → bl 0x{cave_va:x}")

        cave_code = build_tier_cave(cave_va, push_back_va, remaining)
        patches.append((cave_off, cave_code))
        print(f"    patch[2]: cave ({len(cave_code)}B) → {cave_code.hex()}")

        patch_file(path, patches, dry_run)
        return

    # ── Fallback: single-slot replace ──────────────────────────────────────
    if allow_replace:
        name = CAP_NAMES.get(first_cap, str(first_cap))
        print(f"    (fallback replace) slot→{first_cap}({name}) ; "
              f"{len(remaining)} cap(s) still missing without trampoline")
        patch_file(path, [(slot_off, movz_w8_encode(first_cap))], dry_run)
        return

    needed = 16 + 20 * len(remaining)
    bindnow = "BIND_NOW not set; " if not check_bind_now(data) else ""
    cave_info = f"need {needed}B cave, "
    cave_info += f"avail {cave[2] if cave else '?'}B; "
    print(f"    [SKIP] {bindnow}{cave_info}"
          f"use --allow-replace for single-slot or provide BIND_NOW binary")
    return


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Add RAW capability to MediaTek camera sensors')
    parser.add_argument('so', help='Path to libmtkcam_metastore.so')
    parser.add_argument('out', nargs='?', default=None,
                        help='Output path (default: patch in-place)')
    parser.add_argument('--append', action='store_true',
                        help='Add RAW via trampoline without removing BURST_CAPTURE '
                             '(requires BIND_NOW; uses PLT[0] gap as cave)')
    parser.add_argument('--va', help='Manual VA of movz instruction to patch (hex)')
    parser.add_argument('--sensor', help='Only patch specific sensor name substring')
    parser.add_argument('--replace', type=int, default=6,
                        help='(replace mode) Capability to replace with RAW (default: 6=BURST_CAPTURE)')
    parser.add_argument('--allow-fallback', action='store_true',
                        help='(replace mode) Replace last cap if --replace target not found')
    parser.add_argument('--allow-submodes', action='store_true',
                        help='Also patch sub-mode sensor variants')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show patches without writing')
    parser.add_argument('--list', action='store_true',
                        help='List capabilities per sensor, do not patch')
    parser.add_argument('--tier', type=str,
                        help='Comma-separated caps to ensure (e.g. "3" or "3,6" or '
                             '"RAW,BURST_CAPTURE"); trampoline-adds missing ones with '
                             'RAW first; falls back to replace with --allow-replace')
    parser.add_argument('--allow-replace', action='store_true',
                        help='(tier mode) Allow single-slot replacement as trampoline fallback')
    args = parser.parse_args()

    # --append is shorthand for --tier=3,6
    if args.append:
        if args.tier is not None:
            parser.error("--append and --tier are mutually exclusive")
        args.tier = '3,6'

    in_path = Path(args.so)
    if not in_path.exists():
        print(f"ERROR: {in_path} not found")
        sys.exit(1)

    path = in_path
    out_path = Path(args.out) if args.out else None
    if out_path and not args.dry_run:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(in_path.read_bytes())
        print(f"Copied {in_path} → {out_path}")
        path = out_path
    elif out_path and args.dry_run:
        print(f"[DRY RUN] Would copy {in_path} → {out_path}")

    data = path.read_bytes()

    # Manual VA mode (replace only, no --append support)
    if args.va:
        load_segments, _, _ = parse_elf(data)
        va  = int(args.va, 16)
        off = va_to_offset(va, load_segments)
        if off is None:
            print(f"ERROR: VA 0x{va:x} not in any PT_LOAD segment")
            sys.exit(1)
        current = data[off:off+4]
        n = movz_w8_decode(current)
        if n is None:
            print(f"ERROR: bytes at 0x{va:x} ({current.hex()}) are not movz w8, #N")
            sys.exit(1)
        print(f"VA 0x{va:x} (offset 0x{off:x}): movz w8, #{n} ({CAP_NAMES.get(n, '?')}) → #3 (RAW)")
        patch_file(path, [(off, movz_w8_encode(3))], args.dry_run)
        return

    load_segments, symbols, sections = parse_elf(data)
    if not symbols:
        print("ERROR: No symbols found. Try --va for manual mode.")
        sys.exit(1)

    prefix      = 'constructCustStaticMetadata_PLATFORM_PROJECT_SENSOR_DRVNAME_'
    sensor_syms = [s for s in symbols if s['name'].startswith(prefix)]

    if not sensor_syms:
        print("No PLATFORM_PROJECT_SENSOR_DRVNAME symbols found.")
        print("Available PLATFORM_PROJECT symbols:")
        for s in symbols:
            if 'PLATFORM_PROJECT' in s['name']:
                print(f"  0x{s['va']:x}  {s['name']}")
        sys.exit(1)

    if args.sensor:
        sensor_syms = [s for s in sensor_syms if args.sensor.upper() in s['name'].upper()]
        if not sensor_syms:
            print(f"No sensors matching '{args.sensor}'")
            sys.exit(1)

    patches = []

    for sym in sorted(sensor_syms, key=lambda s: s['va']):
        sname  = sensor_name_from_symbol(sym['name'])
        result = find_capability_patch_site(data, sym['va'], sym['size'], load_segments)

        if result is None:
            print(f"  {sname}: [SKIP] no 0xc000c block found")
            continue

        caps      = result['capabilities']
        cap_vals  = [c[1] for c in caps]
        cap_str   = ' '.join(f"{CAP_NAMES.get(v, str(v))}({v})" for v in cap_vals)

        # ── tier mode (also handles --append via args.tier='3,6') ──────────
        if args.tier is not None:
            if not args.allow_submodes:
                lower = sname.lower()
                if any(lower.endswith(sfx.lower()) for sfx in SKIP_SUFFIXES):
                    print(f"  {sname}: [SKIP] sub-mode (--allow-submodes to include)")
                    continue
            tier_caps = parse_tier(args.tier)
            do_ensure_tier(path, data, sym, load_segments, sections,
                           args.dry_run, sname, tier_caps, args.allow_replace)
            # reload data after each patch so cave detection stays accurate
            if not args.dry_run:
                data = path.read_bytes()
            continue

        # ── replace mode (original behaviour) ────────────────────────────────
        if CAP_RAW in cap_vals:
            print(f"  {sname}: RAW already present  [{cap_str}]")
            continue

        if args.list:
            print(f"  {sname}: NO RAW  [{cap_str}]")
            continue

        if not args.allow_submodes:
            lower = sname.lower()
            if any(lower.endswith(sfx.lower()) for sfx in SKIP_SUFFIXES):
                print(f"  {sname}: [SKIP] sub-mode (--allow-submodes to include)")
                continue

        replace_val = args.replace
        target = next(((off, v) for off, v in caps if v == replace_val), None)
        if target is None:
            if not args.allow_fallback:
                print(f"  {sname}: [SKIP] no cap "
                      f"{CAP_NAMES.get(replace_val,'?')}({replace_val}) to replace")
                continue
            target = caps[-1] if caps else None
            if target:
                replace_val = target[1]
                print(f"  {sname}: fallback → replacing last cap "
                      f"{CAP_NAMES.get(replace_val,'?')}({replace_val})")

        if target is None:
            print(f"  {sname}: [SKIP] cannot find patch site")
            continue

        off, old_val = target
        new_bytes = movz_w8_encode(3)
        old_bytes = data[off:off+4]
        expected  = movz_w8_encode(old_val)

        if old_val == 0:
            print(f"  {sname}: [SKIP] replace target is value=0 (wzr path)")
            continue

        print(f"  {sname}: patch 0x{off:x}  "
              f"{CAP_NAMES.get(old_val,'?')}({old_val}) → RAW(3)  [{cap_str}]")

        if old_bytes != expected:
            print(f"    WARNING: expected {expected.hex()} got {old_bytes.hex()} — patching anyway")

        patches.append((off, new_bytes))

    if args.list:
        return

    if args.tier is not None:
        return  # do_ensure_tier / do_append handle their own patch_file calls

    if not patches:
        print("Nothing to patch.")
        return

    print(f"\n{len(patches)} sensor(s) to patch.")
    patch_file(path, patches, args.dry_run)


if __name__ == '__main__':
    main()
