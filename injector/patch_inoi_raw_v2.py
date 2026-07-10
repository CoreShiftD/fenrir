#!/usr/bin/env python3
"""
patch_inoi_raw_v2.py — Append RAW16 stream config entries
via LOAD2 gap trampoline + optional anti-tamper verification.

Strategy:
   1. Extend LOAD2 backwards into the LOAD1-LOAD2 zero gap
      (3124 B at 0x263CC-0x27000) → executable cave space
   2. Write per-camera trampolines that hook entryFor for tag 0xd0012
   3. Push additional RAW16 entries to the same IEntry (append, not replace)
   4. (--verify) Add DT_INIT stub checking ro.coreshift=raw via syscall

Usage:
    python3 patch_inoi_raw_v2.py stock_clean.so -o patched.so
    python3 patch_inoi_raw_v2.py --verify input.so -o patched.so  # + anti-tamper
"""

import sys
import struct

# ──────────────────────────────── ELF ───────────────────────────
LOAD2_PH_OFF = 0xb0   # file offset of LOAD2 (r-x) program header

# ──────────────────────────────── PLT helpers ───────────────────
ENTRY_FOR = 0xab0a0   # entryFor(IMetadata*, tag) → IEntry*
PUSH_LONG = 0xab190   # push_long(IMetadata*, int64*)
GET_TAG   = 0xab0c0   # IEntry::tag() → w0
UPDATE    = 0xab0d0   # update(outer, tag, local) → w0

# ──────────────────────────────── Cave ──────────────────────────
CAVE_VA  = 0x263CC
CAVE_OFF = 0x263CC

# ──────────────────────────────── Hooks ─────────────────────────
# Hook the entryFor call (bl 0xab0a0) for tag 0xd0012 in each camera constructor.
# After entryFor returns with the IEntry populated, we push additional RAW16 entries
# to the SAME IEntry before returning to the normal push_back sequence.
CAM0_HOOK_VA = 0x3f9f8   # bl entryFor for Camera 0 tag 0xd0012
CAM0_RET_VA  = 0x3f9fc   # return address (instruction after the bl)
CAM1_HOOK_VA = 0x5d204   # bl entryFor for Camera 1 tag 0xd0012
CAM1_RET_VA  = 0x5d208   # return address (instruction after the bl)

# Camera 0: tag 0xd0012
CAM0_TAG_LO = 0x12
CAM0_TAG_HI = 0x000d    # movk w1, #0xd, lsl #16

# Camera 1: same tag
CAM1_TAG_LO = 0x12
CAM1_TAG_HI = 0x000d

# ──────────────────────────────── RAW16 entries ─────────────────
# Each entry: [format, width, height, direction, internal1, internal2]
RAW16_ENTRIES_CAM0 = [
    (32, 0xFF0, 0xC00, 0, 0x3f940aa, 0x1fca055),   # 4080×3072
    (32, 0xCC0, 0x990, 0, 0x3f940aa, 0x1fca055),   # 3264×2448
]

RAW16_ENTRIES_CAM1 = [
    (32, 0x1040, 0xC30, 0, 0x3f940aa, 0x1fca055),  # 4160×3120
    (32, 0xD00, 0x990, 0, 0x3f940aa, 0x1fca055),   # 3328×2448
]

# ──────────────────────────────── AArch64 encoding ──────────────

def w(v: int) -> bytes:
    return struct.pack('<I', v)

STP_X29_X30   = w(0xa9bf7bfd)  # stp x29, x30, [sp, #-16]!
LDP_X29_X30   = w(0xa8c17bfd)  # ldp x29, x30, [sp], #16
SUB_X0_X29_50 = w(0xd10143a0)  # sub x0, x29, #0x50
ADD_X1_SP_16  = w(0x910043e1)  # add x1, sp, #0x10
STR_X8_SP16   = w(0xf9000be8)  # str x8, [sp, #0x10]
STR_XZR_SP16  = w(0xf9000bff)  # str xzr, [sp, #0x10]
MOV_W1_W0     = w(0x2a0003e1)  # mov w1, w0
MOV_X0_X19    = w(0xaa1303e0)  # mov x0, x19
SUB_X2_X29_50 = w(0xd10143a2)  # sub x2, x29, #0x50
MOV_W0_WZR    = w(0x2a1f03e0)  # mov w0, wzr
MOV_W2_0x40   = w(0x52800802)  # mov w2, #0x40
RET           = w(0xd65f03c0)  # ret

def movz_w8(n: int) -> bytes:
    return w(0x52800008 | ((n & 0xffff) << 5))

def movk_w8(n: int) -> bytes:
    return w(0x72800008 | ((n & 0xffff) << 5))

def movz_w1(n: int) -> bytes:
    return w(0x52800001 | ((n & 0xffff) << 5))

def movk_w1(n: int) -> bytes:
    return w(0x72800001 | ((n & 0xffff) << 5))

def encode_bl(at_va: int, target_va: int) -> bytes:
    """Encode BL from at_va to target_va."""
    offset = (target_va - at_va) // 4
    if offset < -(1 << 25) or offset >= (1 << 25):
        raise ValueError(f"BL range: 0x{at_va:x} -> 0x{target_va:x} ({offset})")
    return w(0x94000000 | (offset & 0x3FFFFFF))

def cbnz_w0(offset_insns: int) -> bytes:
    """cbnz w0, #offset (offset in instructions = bytes/4)."""
    return w(0x35000000 | ((offset_insns & 0x3FFFF) << 5))


def movz(rd: int, n: int) -> bytes:
    """movz w{rd}, #{n} (32-bit)."""
    return w(0x52800000 | ((n & 0xffff) << 5) | (rd & 0x1f))

def movk(rd: int, n: int, shift: int = 0) -> bytes:
    """movk w{rd}, #{n}, lsl #{shift*16} (32-bit)."""
    return w(0x72800000 | ((n & 0xffff) << 5) | ((shift & 3) << 21) | (rd & 0x1f))

def encode_adr(at_va: int, target_va: int, rd: int = 0) -> bytes:
    """adr x{rd}, <target> (pc-relative)."""
    offset = target_va - at_va
    immlo = (offset >> 0) & 3
    immhi = (offset >> 2) & 0x7FFFF
    return w(0x10000000 | (immlo << 29) | (immhi << 5) | rd)

def encode_beq(at_va: int, target_va: int) -> bytes:
    """b.eq <target>."""
    offset_insns = (target_va - at_va) // 4
    return w(0x54000000 | ((offset_insns & 0x7FFFF) << 5))


# ──────────────────────────────── Verify / Anti-tamper ──────────

VERIFY_VA    = 0x265E0   # after trampolines (0x263CC-0x265DC = 528B)
MARKER_PATH  = b"/vendor/lib64/.coreshift_ok\x00"

def build_verify_function(cave_va: int) -> tuple[bytes, int]:
    """
    Build a DT_INIT stub that:
      1. openat(AT_FDCWD, MARKER_PATH, O_RDONLY)
      2. On failure (< 0): exit_group(1)
      3. On success: close(fd) and return
    Uses only standard Linux syscalls (works on any kernel, any SELinux).
    The marker file /vendor/lib64/.coreshift_ok gets vendor_file SELinux
    context — accessible by mtk_hal_camera domain.
    """
    code = bytearray()
    pos = cave_va

    code += STP_X29_X30                     # stp x29, x30, [sp, #-16]!
    pos += 4

    # openat(AT_FDCWD=-100, path, O_RDONLY=0)
    code += w(0x12800c60)                    # movn w0, #99    → w0 = ~99 = -100 = AT_FDCWD
    pos += 4

    adr_pos = pos
    code += b'\x00\x00\x00\x00'              # adr x1, marker_path (placeholder)
    pos += 4

    code += w(0x2a1f03e2)                    # mov w2, wzr     → w2 = 0 = O_RDONLY
    pos += 4
    code += movz(8, 257)                     # mov w8, #257    = __NR_openat
    pos += 4
    code += w(0xd4000001)                    # svc #0
    pos += 4

    code += w(0x7100001f)                    # cmp w0, #0      (test sign; fail if < 0)
    pos += 4

    bge_pos = pos
    code += b'\x00\x00\x00\x00'              # b.ge ok (placeholder)
    pos += 4

    # exit_group(1)
    code += movz(0, 1)                       # mov w0, #1
    pos += 4
    code += movz(8, 94)                      # mov w8, #94 = __NR_exit_group
    pos += 4
    code += w(0xd4000001)                    # svc #0
    pos += 4

    # ok: close(fd) + return
    ok_va = pos
    code += movz(8, 57)                      # mov w8, #57 = __NR_close
    pos += 4
    code += w(0xd4000001)                    # svc #0
    pos += 4
    code += LDP_X29_X30                      # ldp x29, x30, [sp], #16
    pos += 4
    code += RET                              # ret
    pos += 4

    # Fix up B.GE
    bge_enc = encode_bge(bge_pos, ok_va)
    code[bge_pos - cave_va:bge_pos - cave_va + 4] = bge_enc

    # Fix up ADR for marker path
    path_va = pos
    adr_enc = encode_adr(adr_pos, path_va, rd=1)
    code[adr_pos - cave_va:adr_pos - cave_va + 4] = adr_enc

    # Append marker path string
    code += MARKER_PATH
    pos += len(MARKER_PATH)

    return bytes(code), pos


def encode_bge(at_va: int, target_va: int) -> bytes:
    """b.ge <target> (conditional branch, signed >=)."""
    offset_insns = (target_va - at_va) // 4
    return w(0x54000000 | ((offset_insns & 0x7FFFF) << 5) | 0xA)


def patch_dt_init(data: bytearray, verify_fn_va: int) -> bool:
    """Extend PT_DYNAMIC: convert first DT_NULL → DT_INIT + add new DT_NULL terminator.

    Critical: must NOT replace the only DT_NULL (terminator) — that makes the
    linker read garbage. Instead we extend the DYNAMIC segment by 16 bytes:
    DT_INIT + DT_NULL, then update PT_DYNAMIC p_filesz/p_memsz.
    """
    e_phoff = struct.unpack_from('<Q', data, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
    e_phnum = struct.unpack_from('<H', data, 0x38)[0]

    dyn_ph_idx = None
    dyn_ph = None
    p_offset = p_vaddr = p_filesz = p_memsz = 0

    for i in range(e_phnum):
        ph = e_phoff + i * e_phentsize
        p_type = struct.unpack_from('<I', data, ph)[0]
        if p_type == 2:  # PT_DYNAMIC
            dyn_ph = ph
            dyn_ph_idx = i
            p_offset = struct.unpack_from('<Q', data, ph + 8)[0]
            p_vaddr = struct.unpack_from('<Q', data, ph + 16)[0]
            p_filesz = struct.unpack_from('<Q', data, ph + 32)[0]
            p_memsz = struct.unpack_from('<Q', data, ph + 40)[0]
            break

    if dyn_ph is None:
        print("  ERROR: no PT_DYNAMIC found")
        return False

    # Find first DT_NULL
    null_off = None
    for j in range(0, p_filesz, 16):
        d_tag = struct.unpack_from('<Q', data, p_offset + j)[0]
        if d_tag == 0:  # DT_NULL
            null_off = p_offset + j
            null_va = p_vaddr + j
            break

    if null_off is None:
        print("  ERROR: no DT_NULL found in PT_DYNAMIC")
        return False

    # Write DT_INIT at the DT_NULL position
    struct.pack_into('<Q', data, null_off, 12)   # d_tag = DT_INIT
    struct.pack_into('<Q', data, null_off + 8, verify_fn_va)

    # Write DT_NULL at the next entry (extends by 16 bytes)
    struct.pack_into('<Q', data, null_off + 16, 0)  # d_tag = DT_NULL
    struct.pack_into('<Q', data, null_off + 24, 0)  # d_val = 0

    # Update PT_DYNAMIC p_filesz and p_memsz
    new_filesz = p_filesz + 16
    new_memsz = p_memsz + 16
    struct.pack_into('<Q', data, dyn_ph + 32, new_filesz)
    struct.pack_into('<Q', data, dyn_ph + 40, new_memsz)

    print(f"  DT_NULL at 0x{null_va:x} → DT_INIT = 0x{verify_fn_va:x}")
    print(f"  Extended PT_DYNAMIC: filesz 0x{p_filesz:x} → 0x{new_filesz:x}")

    return True


# ──────────────────────────────── Trampoline builder ────────────

def build_push_field(at_va: int, value: int):
    """
    Emit push_long call sequence.
    Returns (bytes, next_va).
    """
    code = bytearray()
    pos = at_va

    if value == 0:
        code += STR_XZR_SP16
        pos += 4
    elif value <= 0xffff:
        code += movz_w8(value)
        code += STR_X8_SP16
        pos += 8
    else:
        lo = value & 0xffff
        hi = (value >> 16) & 0xffff
        code += movz_w8(lo)
        code += movk_w8(hi)
        code += STR_X8_SP16
        pos += 12

    # sub x0, x29, #0x50  (4B) + add x1, sp, #0x10 (4B)
    code += SUB_X0_X29_50
    code += ADD_X1_SP_16
    pos += 8

    # bl push_long — BL is at 'pos' now
    code += encode_bl(pos, PUSH_LONG)
    pos += 4

    return bytes(code), pos


def build_trampoline(cave_va: int, ret_va: int,
                     tag_lo: int, tag_hi: int,
                     entries: list) -> bytes:
    """
    Build a trampoline at cave_va that:
    1. Calls the original entryFor (args already in x0/x1/x2 from caller)
    2. Pushes additional RAW16 entries to the IEntry at x29-0x50
    3. Returns to ret_va (the instruction after the original bl entryFor)

    The original code at (hook_va) was 'bl entryFor'. We replace it with 'bl cave_va'.
    Our trampoline saves x29/x30 (x30=ret_va), calls entryFor, adds entries,
    restores x29/x30, and ret.
    """
    code = bytearray()
    pos = cave_va

    # ── stp x29, x30, [sp, #-16]!  (x30 = ret_va from the hook's bl)
    code += STP_X29_X30
    pos += 4

    # ── bl entryFor (original function, args already in x0/x1/x2)
    code += encode_bl(pos, ENTRY_FOR)
    pos += 4

    # ── Push each RAW16 entry's 6 fields to the SAME IEntry at x29-0x50
    for entry in entries:
        for field in entry:
            fbytes, pos = build_push_field(pos, field)
            code += fbytes

    # ── ldp x29, x30, [sp], #16  (x30 = ret_va again)
    code += LDP_X29_X30
    pos += 4
    # ret  (returns to ret_va = instruction after original bl entryFor)
    code += RET
    pos += 4

    return bytes(code)


# ──────────────────────────────── Main patch ────────────────────

def patch(data: bytearray, verify: bool = False) -> bool:
    # ── Step 1: Extend LOAD2 backwards ──────────────────────────
    print("Step 1: Extending LOAD2 backwards...")
    cur_off = struct.unpack_from('<Q', data, LOAD2_PH_OFF + 8)[0]
    cur_va  = struct.unpack_from('<Q', data, LOAD2_PH_OFF + 16)[0]
    cur_fz  = struct.unpack_from('<Q', data, LOAD2_PH_OFF + 32)[0]
    cur_msz = struct.unpack_from('<Q', data, LOAD2_PH_OFF + 40)[0]

    print(f"  Current: p_offset=0x{cur_off:x} p_vaddr=0x{cur_va:x}")
    print(f"           p_filesz=0x{cur_fz:x} p_memsz=0x{cur_msz:x}")

    gap_size = cur_off - CAVE_OFF
    new_fz  = cur_fz + gap_size
    new_msz = cur_msz + gap_size

    print(f"  New:     p_offset=0x{CAVE_OFF:x} p_vaddr=0x{CAVE_VA:x}")
    print(f"           p_filesz=0x{new_fz:x} (+{gap_size}) p_memsz=0x{new_msz:x}")

    struct.pack_into('<Q', data, LOAD2_PH_OFF + 8,  CAVE_OFF)
    struct.pack_into('<Q', data, LOAD2_PH_OFF + 16, CAVE_VA)
    struct.pack_into('<Q', data, LOAD2_PH_OFF + 32, new_fz)
    struct.pack_into('<Q', data, LOAD2_PH_OFF + 40, new_msz)

    # ── Step 2: Build trampolines ───────────────────────────────
    print("Step 2: Building trampoline code...")
    file_pos = CAVE_OFF

    # Camera 0
    cam0_code = build_trampoline(CAVE_VA, CAM0_RET_VA,
                                  CAM0_TAG_LO, CAM0_TAG_HI,
                                  RAW16_ENTRIES_CAM0)
    cam0_va = CAVE_VA
    cam0_file_off = file_pos
    print(f"  Camera 0: {len(cam0_code)}B at VA=0x{cam0_va:x} file=0x{cam0_file_off:x}")
    data[cam0_file_off:cam0_file_off + len(cam0_code)] = cam0_code
    file_pos += len(cam0_code)

    # Camera 1 (immediately after Camera 0)
    cam1_va = CAVE_VA + len(cam0_code)
    cam1_code = build_trampoline(cam1_va, CAM1_RET_VA,
                                  CAM1_TAG_LO, CAM1_TAG_HI,
                                  RAW16_ENTRIES_CAM1)
    cam1_file_off = file_pos
    print(f"  Camera 1: {len(cam1_code)}B at VA=0x{cam1_va:x} file=0x{cam1_file_off:x}")
    data[cam1_file_off:cam1_file_off + len(cam1_code)] = cam1_code
    file_pos += len(cam1_code)

    total_cave = file_pos - CAVE_OFF
    print(f"  Total trampoline code: {total_cave}B (of 3124 available)")

    # ── Step 3: Hook constructors ────────────────────────────────
    print("Step 3: Hooking constructors...")

    def hook_bl(insn_va: int, cave_va: int, name: str):
        """Replace bl at insn_va with bl cave_va."""
        file_off = insn_va  # LOAD2: p_offset == p_vaddr after extension
        cur_w = struct.unpack_from('<I', data, file_off)[0]
        opc = cur_w >> 26
        if opc != 0b100101:  # BL
            print(f"  {name} @0x{insn_va:x}: unexpected opcode 0x{cur_w:08x}")
            return False
        # Decode current BL target
        imm = cur_w & 0x3FFFFFF
        if imm & 0x2000000:
            imm -= 0x4000000
        cur_target = insn_va + imm * 4
        print(f"  {name} @0x{insn_va:x}: bl 0x{cur_target:x} → bl 0x{cave_va:x}")

        bl_bytes = encode_bl(insn_va, cave_va)
        data[file_off:file_off+4] = bl_bytes
        return True

    hook_bl(CAM0_HOOK_VA, CAVE_VA, "Camera 0")
    hook_bl(CAM1_HOOK_VA, cam1_va, "Camera 1")

    # ── Step 4 (optional): Anti-tamper verify ─────────────────────
    if verify:
        print("Step 4: Adding anti-tamper verification...")
        verify_fn_va = VERIFY_VA
        verify_code, next_va = build_verify_function(verify_fn_va)
        # Ensure no overlap with trampolines
        assert verify_fn_va >= CAVE_OFF + total_cave, \
            f"Verify 0x{verify_fn_va:x} overlaps trampolines (end 0x{CAVE_OFF + total_cave:x})"
        cave_end = CAVE_OFF + 3124
        assert verify_fn_va + len(verify_code) <= cave_end, \
            f"Verify exceeds cave (0x{verify_fn_va + len(verify_code):x} > 0x{cave_end:x})"
        file_off = CAVE_OFF + (verify_fn_va - CAVE_VA)
        data[file_off:file_off + len(verify_code)] = verify_code
        print(f"  verify: {len(verify_code)}B at VA=0x{verify_fn_va:x}")
        patch_dt_init(data, verify_fn_va)

    return True


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Append RAW16 stream configs via LOAD2 gap trampoline")
    parser.add_argument("input", help="Input .so file")
    parser.add_argument("-o", "--output", default=None, help="Output path")
    parser.add_argument("--verify", action="store_true",
                        help="Add anti-tamper: check ro.coreshift=raw, crash on mismatch")
    args = parser.parse_args()

    with open(args.input, "rb") as f:
        data = bytearray(f.read())

    print(f"Patching {args.input} ({len(data)} bytes)...")
    if not patch(data, verify=args.verify):
        print("ERROR: patch failed")
        sys.exit(1)

    outpath = args.output or args.input + ".patched"
    with open(outpath, "wb") as f:
        f.write(data)
    print(f"Written to {outpath}")
    print("DONE")

if __name__ == "__main__":
    main()
