#!/usr/bin/env python3
"""
Patch stock camera libraries to add raw/DNG support.

Modes:
  3rdparty (default): Patch libmtkcam_3rdparty.customer.so to add raw/DNG capture
    support. Extends the LOAD-2 segment, writes a trampoline that checks vendor
    metadata tag 0x80150005, setting bits 35/36 in ScenarioFeatures when found.

  metastore-raw16: Patch libmtkcam_metastore.so to inject RAW16 format entries
    into the recommended stream configurations layout. Intercepts the
    updateRecommendedStreamConfiguration function and appends a RAW16
    (format=0x20) resolution entry via IEntry::push_back before the
    IMetadata::update() call.

Usage:
    python3 patch_raw_3rdparty.py [--mode 3rdparty] <stock.so> [output.so]
    python3 patch_raw_3rdparty.py --mode metastore-raw16 [--width 4352] [--height 2448] <metastore.so> [output.so]
"""

import struct
import sys
import os

# ─── ELF constants ────────────────────────────────────────────────────
PT_LOAD = 1

# ─── Shared helpers ──────────────────────────────────────────────────

def bl_encode(pc, target):
    """Encode AArch64 BL from pc to target as 4 LE bytes."""
    offset = (target - pc) >> 2
    if offset < -(1 << 25) or offset >= (1 << 25):
        raise ValueError(f"BL offset 0x{offset:x} out of range")
    offset &= 0x3FFFFFF
    return struct.pack('<I', 0x94000000 | offset)


def b_encode(pc, target):
    """Encode AArch64 B from pc to target as 4 LE bytes."""
    offset = (target - pc) >> 2
    if offset < -(1 << 25) or offset >= (1 << 25):
        raise ValueError(f"B offset 0x{offset:x} out of range")
    offset &= 0x3FFFFFF
    return struct.pack('<I', 0x14000000 | offset)


# ─── Mode: 3rdparty ──────────────────────────────────────────────────

# Trampoline for libmtkcam_3rdparty.customer.so (mode 3rdparty).
# The trampoline is placed at virtual address 0x2c690 (cave).
# It replaces the instruction at stock 0xe1b4 (orr x7, x28, 0x10).
# After the trampoline runs, it branches back to 0xe1bc.

def make_3rdparty_trampoline(cave_va, return_va, plt_entry_for, plt_count,
                              plt_item_at, plt_dtor):
    """
    Build the trampoline bytecode for 3rdparty mode.
    
    All addresses are VA. Returns bytes.
    """
    code = bytearray()
    
    def emit_u32(val):
        code.extend(struct.pack('<I', val))
    
    def op_b_bl(is_bl, from_va, to_va):
        """Emit B (is_bl=False) or BL (is_bl=True) relative branch.
        ARM64 encoding: bits[31:26] = {!is_bl:1}_{00101}"""
        offset = (to_va - from_va) >> 2
        imm26 = offset & 0x3FFFFFF
        opcode = 0x25 if is_bl else 0x05
        return (opcode << 26) | imm26
    
    pc = cave_va  # current PC, updated as we emit
    
    # stp x0, x1, [sp, #-0x20]!
    emit_u32(0xa9be07e0); pc += 4
    # stp x2, x30, [sp, #0x10]
    emit_u32(0xa9017be2); pc += 4
    # stp x28, x3, [sp, #-0x20]!   (save x28 which holds features)
    emit_u32(0xa9be1f9c); pc += 4
    # stp x8, x9, [sp, #0x10]
    emit_u32(0xa90127e8); pc += 4
    
    # ─── Simulate replaced instructions ───
    # orr x7, x28, #0x10
    emit_u32(0xb27c03c7); pc += 4
    # str x7, [x27, #0x38]
    emit_u32(0xf9001f67); pc += 4
    
    # ─── Prepare IEntry storage on stack ───
    # stp x10, x11, [sp, #-0x30]!
    emit_u32(0xa9bd2fea); pc += 4
    # stp x12, x13, [sp, #0x10]
    emit_u32(0xa90137ec); pc += 4
    # stp x14, x15, [sp, #0x20]
    emit_u32(0xa9023fee); pc += 4
    # movi v0.2d, #0
    emit_u32(0x6f00e400); pc += 4
    # stp q0, q0, [sp, #0x10]   ; IEntry on stack
    emit_u32(0xad0083e0); pc += 4
    
    # ─── Check tag 0x80150005 ───
    # mov x0, x23             ; x23 = IMetadata*
    emit_u32(0xaa1703e0); pc += 4
    # mov w1, #5
    emit_u32(0x528000a1); pc += 4
    # movk w1, #0x8015, lsl #16  ; tag = 0x80150005
    emit_u32(0x72b002a1); pc += 4
    # mov w2, wzr             ; flags = 0
    emit_u32(0x2a1f03e2); pc += 4
    # bl entryFor
    emit_u32(op_b_bl(True, pc, plt_entry_for)); pc += 4
    
    # add x0, sp, #0x10       ; x0 = &IEntry
    emit_u32(0x910043e0); pc += 4
    # bl count
    emit_u32(op_b_bl(True, pc, plt_count)); pc += 4
    # cbz w0, skip_raw (offset calculated later)
    skip_raw_patch_loc = len(code)
    emit_u32(0); pc += 4  # placeholder
    
    # add x0, sp, #0x10
    emit_u32(0x910043e0); pc += 4
    # mov w1, wzr
    emit_u32(0x2a1f03e1); pc += 4
    # bl itemAt
    emit_u32(op_b_bl(True, pc, plt_item_at)); pc += 4
    # mov w8, w0
    emit_u32(0x2a0003e8); pc += 4
    
    # add x0, sp, #0x10
    emit_u32(0x910043e0); pc += 4
    # bl ~IEntry
    emit_u32(op_b_bl(True, pc, plt_dtor)); pc += 4
    
    # cbz w8, done_raw (tag value is zero → skip)
    done_raw_patch_loc = len(code)
    emit_u32(0); pc += 4  # placeholder
    
    # ─── Set bits 35 and 36 ───
    # ldr x8, [x27, #0x38]
    emit_u32(0xf9401f68); pc += 4
    # orr x8, x8, #0x800000000    ; bit 35
    emit_u32(0xb25d0108); pc += 4
    # orr x8, x8, #0x1000000000   ; bit 36
    emit_u32(0xb25c0108); pc += 4
    # str x8, [x27, #0x38]
    emit_u32(0xf9001f68); pc += 4
    
    # ─── done_restore_branch (will patch below) ───
    done_restore_branch_loc = len(code)
    emit_u32(0); pc += 4  # placeholder for "b done_restore"
    
    # ─── skip_raw: ───
    # Patch the cbz at skip_raw_patch_loc
    skip_raw_addr = pc  # skip lands here
    cbz_skip_pc = skip_raw_patch_loc + cave_va
    imm19 = ((skip_raw_addr - cbz_skip_pc) >> 2) & 0x7FFFF
    cbz_encoding = (0x1a << 25) | (imm19 << 5) | 0  # Rt=w0
    struct.pack_into('<I', code, skip_raw_patch_loc, cbz_encoding)
    
    # skip_raw code:
    # add x0, sp, #0x10
    emit_u32(0x910043e0); pc += 4
    # bl ~IEntry
    emit_u32(op_b_bl(True, pc, plt_dtor)); pc += 4
    # fall through to done_restore
    
    # ─── done_restore: ───
    done_restore_addr = pc  # both cbz w8 done_raw and done_restore_branch target here
    
    # Patch the cbz w8 at done_raw_patch_loc
    cbz_done_pc = done_raw_patch_loc + cave_va
    imm19 = ((done_restore_addr - cbz_done_pc) >> 2) & 0x7FFFF
    cbz_encoding = (0x1a << 25) | (imm19 << 5) | 8  # Rt=w8
    struct.pack_into('<I', code, done_raw_patch_loc, cbz_encoding)
    
    # Patch the done_restore_branch at done_restore_branch_loc
    b_done_pc = done_restore_branch_loc + cave_va
    offset = (done_restore_addr - b_done_pc) >> 2
    struct.pack_into('<I', code, done_restore_branch_loc, (5 << 26) | (offset & 0x3FFFFFF))
    # Restore regs
    # ldp x14, x15, [sp, #0x20]
    emit_u32(0xa9423fee); pc += 4
    # ldp x12, x13, [sp, #0x10]
    emit_u32(0xa94137ec); pc += 4
    # ldp x10, x11, [sp], #0x30
    emit_u32(0xa8c32fea); pc += 4
    # ldp x8, x9, [sp, #0x10]
    emit_u32(0xa94127e8); pc += 4
    # ldp x28, x3, [sp], #0x20
    emit_u32(0xa8c21f9c); pc += 4
    # ldp x2, x30, [sp, #0x10]
    emit_u32(0xa9417be2); pc += 4
    # ldp x0, x1, [sp], #0x20
    emit_u32(0xa8c207e0); pc += 4
    # b return_point
    emit_u32(op_b_bl(False, pc, return_va)); pc += 4
    
    return bytes(code)


# ─── Mode: metastore-raw16 ───────────────────────────────────────────

def make_metastore_raw16_trampoline(tramp_va, push_back_va, tag_va, update_va,
                                    raw16_res):
    """
    Build a 164-byte AArch64 trampoline that injects a RAW16 entry into the
    recommended stream configuration IEntry before IMetadata::update().

    On entry (from original call site at 0x76174):
      x0 = IMetadata*  (saved to x20)
      x2 = IEntry*     (saved to x19)

    The trampoline saves registers, pushes 4 int32 values (format=0x20,
    width, height, input=0) via IEntry::push_back, calls IEntry::tag() to
    get the tag, then calls IMetadata::update().
    """
    width, height = raw16_res
    code = bytearray()
    pc = tramp_va

    def emit(b):
        nonlocal code, pc
        code += b
        pc += len(b)

    def emit_u32(v):
        nonlocal code, pc
        code += struct.pack('<I', v)
        pc += 4

    def emit_bl(target):
        nonlocal code, pc
        code += bl_encode(pc, target)
        pc += 4

    # Verified AArch64 encodings
    E = {}
    E['sub_sp_0x20']   = struct.pack('<I', 0xD10083FF)  # sub sp, sp, #0x20
    E['stp_29_30_sp']  = struct.pack('<I', 0xA9007BFD)  # stp x29, x30, [sp]
    E['add_x29_sp_0']  = struct.pack('<I', 0x910003FD)  # add x29, sp, #0
    E['stp_19_20_sp_10'] = struct.pack('<I', 0xA90153F3) # stp x19, x20, [sp, #0x10]
    E['mov_x19_x2']    = struct.pack('<I', 0xAA0203F3)  # mov x19, x2
    E['mov_x20_x0']    = struct.pack('<I', 0xAA0003F4)  # mov x20, x0
    E['sub_sp_0x10']   = struct.pack('<I', 0xD10043FF)  # sub sp, sp, #0x10
    E['str_w0_sp']     = struct.pack('<I', 0xB9001FE0)  # str w0, [sp]
    E['str_wzr_sp']    = struct.pack('<I', 0xB9001FFF)  # str wzr, [sp]
    E['mov_x0_x19']    = struct.pack('<I', 0xAA1303E0)  # mov x0, x19
    E['add_x1_sp_0']   = struct.pack('<I', 0x910003E1)  # add x1, sp, #0
    E['mov_x2_xzr']    = struct.pack('<I', 0xAA1F03E2)  # mov x2, xzr
    E['add_sp_0x10']   = struct.pack('<I', 0x910043FF)  # add sp, sp, #0x10
    E['mov_x0_x20']    = struct.pack('<I', 0xAA1403E0)  # mov x0, x20
    E['mov_w1_w0']     = struct.pack('<I', 0x2A0003E1)  # mov w1, w0
    E['mov_x2_x19']    = struct.pack('<I', 0xAA1303E2)  # mov x2, x19
    E['ldp_19_20_sp_10'] = struct.pack('<I', 0xA94153F3) # ldp x19, x20, [sp, #0x10]
    E['ldp_29_30_sp']  = struct.pack('<I', 0xA9407BFD)  # ldp x29, x30, [sp]
    E['add_sp_0x20']   = struct.pack('<I', 0x910083FF)  # add sp, sp, #0x20
    E['ret']           = struct.pack('<I', 0xD65F03C0)   # ret

    # movz w0, #N lower/high for values > 16 bits
    def mov_w0_val(val):
        if val <= 0xFFFF:
            return struct.pack('<I', 0x52800000 | (val << 5))  # movz w0, #val
        else:
            low = val & 0xFFFF
            high = (val >> 16) & 0xFFFF
            enc = bytearray()
            enc += struct.pack('<I', 0x52800000 | (low << 5))
            enc += struct.pack('<I', 0x72A00000 | (high << 5))  # movk w0, #high, lsl 16
            return bytes(enc)

    # Prologue
    emit(E['sub_sp_0x20'])
    emit(E['stp_29_30_sp'])
    emit(E['add_x29_sp_0'])
    emit(E['stp_19_20_sp_10'])
    emit(E['mov_x19_x2'])
    emit(E['mov_x20_x0'])
    emit(E['sub_sp_0x10'])

    # push_back format=0x20
    emit(mov_w0_val(0x20))
    emit(E['str_w0_sp'])
    emit(E['mov_x0_x19'])
    emit(E['add_x1_sp_0'])
    emit(E['mov_x2_xzr'])
    emit_bl(push_back_va)

    # push_back width
    emit(mov_w0_val(width))
    emit(E['str_w0_sp'])
    emit(E['mov_x0_x19'])
    emit(E['add_x1_sp_0'])
    emit(E['mov_x2_xzr'])
    emit_bl(push_back_va)

    # push_back height
    emit(mov_w0_val(height))
    emit(E['str_w0_sp'])
    emit(E['mov_x0_x19'])
    emit(E['add_x1_sp_0'])
    emit(E['mov_x2_xzr'])
    emit_bl(push_back_va)

    # push_back input=0
    emit(E['str_wzr_sp'])
    emit(E['mov_x0_x19'])
    emit(E['add_x1_sp_0'])
    emit(E['mov_x2_xzr'])
    emit_bl(push_back_va)

    # Restore temp sp
    emit(E['add_sp_0x10'])

    # IEntry::tag() → returns tag in w0
    emit(E['mov_x0_x19'])
    emit_bl(tag_va)

    # IMetadata::update(tag, IEntry)
    emit(E['mov_x0_x20'])
    emit(E['mov_w1_w0'])
    emit(E['mov_x2_x19'])
    emit_bl(update_va)

    # Epilogue
    emit(E['ldp_19_20_sp_10'])
    emit(E['ldp_29_30_sp'])
    emit(E['add_sp_0x20'])
    emit(E['ret'])

    return bytes(code)


def patch_metastore_raw16(in_path, out_path, dry_run=False, raw16_res=(4352, 2448)):
    """
    Patch libmtkcam_metastore.so to inject RAW16 entries into the
    recommended stream configurations layout.

    Addresses (stock libmtkcam_metastore.so for A75):
      patch_va    = 0x76174  (BL to IMetadata::update)
      tramp_va    = 0x761d4  (gap after __stack_chk_fail, overwrites updateAfRegions)
      push_back   = 0xab110  (IEntry::push_back(int))
      tag_fn      = 0xab0c0  (IEntry::tag)
      update_fn   = 0xab0d0  (IMetadata::update)
    """
    with open(in_path, 'rb') as f:
        data = bytearray(f.read())

    width, height = raw16_res

    # Fixed addresses for stock A75 libmtkcam_metastore.so
    patch_va    = 0x76174
    tramp_va    = 0x761d4
    push_back   = 0xab110
    tag_fn      = 0xab0c0
    update_fn   = 0xab0d0

    # Verify: original bytes at patch point should be BL to update
    orig_bytes = bytes(data[patch_va:patch_va+4])
    print(f"Patch point 0x{patch_va:x}: current bytes = {orig_bytes.hex()}")

    trampoline = make_metastore_raw16_trampoline(
        tramp_va, push_back, tag_fn, update_fn, (width, height))

    print(f"Trampoline: {len(trampoline)} bytes at VA 0x{tramp_va:x} → 0x{tramp_va + len(trampoline):x}")

    # Verify BL targets in trampoline
    for off in range(0, len(trampoline), 4):
        insn = struct.unpack_from('<I', trampoline, off)[0]
        if (insn & 0xFC000000) == 0x94000000:
            imm26 = insn & 0x3FFFFFF
            if imm26 & (1 << 25):
                imm26 -= (1 << 26)
            tgt = (tramp_va + off) + imm26 * 4
            name = {push_back: 'push_back', tag_fn: 'tag()', update_fn: 'update()'}.get(tgt, 'UNKNOWN')
            print(f"  BL at 0x{tramp_va+off:x} → 0x{tgt:x} ({name})")

    # Write trampoline
    data[tramp_va:tramp_va + len(trampoline)] = trampoline

    # Patch BL at call site to redirect to trampoline
    new_bl = bl_encode(patch_va, tramp_va)
    data[patch_va:patch_va+4] = new_bl
    print(f"Patched BL at 0x{patch_va:x}: {orig_bytes.hex()} → {new_bl.hex()}")

    # Write output
    if dry_run:
        print(f"\n✓ [DRY RUN] Would write patched metastore to {out_path}")
    else:
        with open(out_path, 'wb') as f:
            f.write(data)
        print(f"\n✓ Patched metastore written to {out_path}")
    print(f"  RAW16 resolution: {width}×{height}")


# ─── ELF patching (3rdparty mode) ────────────────────────────────────
def patch_3rdparty_customer(in_path, out_path, dry_run=False):
    with open(in_path, 'rb') as f:
        data = bytearray(f.read())
    
    # Parse ELF header
    # e_phoff at offset 0x20
    phoff = struct.unpack_from('<Q', data, 0x20)[0]
    phnum = struct.unpack_from('<H', data, 0x38)[0]
    phentsize = struct.unpack_from('<H', data, 0x36)[0]
    
    print(f"Program headers: offset=0x{phoff:x}, count={phnum}, ent_size={phentsize}")
    
    # Find LOAD 2 (executable segment)
    load2_idx = -1
    load2_offset = 0
    load2_vaddr = 0
    load2_filesz = 0
    load2_memsz = 0
    
    for i in range(phnum):
        ph = data[phoff + i * phentsize : phoff + (i+1) * phentsize]
        p_type = struct.unpack_from('<I', ph, 0)[0]
        if p_type == PT_LOAD:
            p_flags = struct.unpack_from('<I', ph, 4)[0]
            p_offset = struct.unpack_from('<Q', ph, 8)[0]
            p_vaddr = struct.unpack_from('<Q', ph, 16)[0]
            p_filesz = struct.unpack_from('<Q', ph, 32)[0]
            p_memsz = struct.unpack_from('<Q', ph, 40)[0]
            print(f"  LOAD[{i}]: flags={p_flags:#x} off=0x{p_offset:x} "
                  f"vaddr=0x{p_vaddr:x} filesz=0x{p_filesz:x} memsz=0x{p_memsz:x}")
            
            if p_flags & 1:  # executable
                load2_idx = i
                load2_offset = p_offset
                load2_vaddr = p_vaddr
                load2_filesz = p_filesz
                load2_memsz = p_memsz
    
    if load2_idx < 0:
        print("ERROR: no executable LOAD segment found")
        sys.exit(1)
    
    print(f"\nExecutable LOAD[{load2_idx}]:")
    print(f"  Current filesz = 0x{load2_filesz:x} → end at 0x{load2_vaddr + load2_filesz:x}")
    print(f"  Current memsz  = 0x{load2_memsz:x}")
    
    # Calculate new sizes
    cave_va = 0x2c690
    new_end = 0x2d000  # extend to next section start
    new_filesz = new_end - load2_vaddr
    patch_end_va = 0x2d000
    
    print(f"  Cave VA = 0x{cave_va:x}")
    print(f"  Extending to VA 0x{patch_end_va:x}")
    print(f"  New filesz = 0x{new_filesz:x} (+0x{new_filesz - load2_filesz:x})")
    
    # Patch program header
    ph_off = phoff + load2_idx * phentsize
    struct.pack_into('<Q', data, ph_off + 32, new_filesz)   # p_filesz
    struct.pack_into('<Q', data, ph_off + 40, new_filesz)   # p_memsz
    
    # ─── Generate and write trampoline ───
    # PLT addresses in stock binary
    plt_entry_for = 0x2bed0
    plt_count = 0x2bee0
    plt_item_at = 0x2bef0
    plt_dtor = 0x2bf00
    
    # Return point: instruction after the replaced str
    return_va = 0xe1bc
    
    trampoline = make_3rdparty_trampoline(cave_va, return_va, plt_entry_for,
                                          plt_count, plt_item_at, plt_dtor)
    
    tramp_file_off = cave_va  # file offset = VA (identity mapping for LOAD 2)
    print(f"\nTrampoline: {len(trampoline)} bytes")
    print(f"  Written at file offset 0x{tramp_file_off:x}, VA 0x{cave_va:x}")
    print(f"  Returns to VA 0x{return_va:x}")
    
    # Verify the cave is clear
    cave_bytes = data[tramp_file_off : tramp_file_off + len(trampoline)]
    if any(b != 0 for b in cave_bytes):
        print("WARNING: cave not all zeros! Overwriting non-zero data.")
    
    data[tramp_file_off : tramp_file_off + len(trampoline)] = trampoline
    
    # ─── Patch the stock function ───
    # Replace instruction at 0xe1b4 (orr x7, x28, 0x10) with:
    #   b 0x2c690  (branch to trampoline)
    # The bytes at 0xe1b8 (str x7, [x27, 0x38]) become dead code
    
    b_from_va = 0xe1b4
    b_to_va = cave_va
    b_offset = (b_to_va - b_from_va) >> 2
    b_encoding = (5 << 26) | (b_offset & 0x3FFFFFF)
    
    print(f"\nPatching instruction at VA 0x{b_from_va:x}:")
    print(f"  Original: {data[b_from_va:b_from_va+4].hex()}")
    print(f"  New:      b 0x{b_to_va:x} → {b_encoding:#010x}")
    
    struct.pack_into('<I', data, b_from_va, b_encoding)
    
    print(f"\n  Verified new bytes: {data[b_from_va:b_from_va+4].hex()}")
    
    # ─── Write output ───
    if dry_run:
        print(f"\n✓ [DRY RUN] Would write patched binary to {out_path}")
    else:
        with open(out_path, 'wb') as f:
            f.write(data)
        print(f"\n✓ Patched binary written to {out_path}")
    print(f"  File size: {len(data)} bytes")
    print(f"  LOAD[{load2_idx}] filesz updated to 0x{new_filesz:x}")


def main():
    import argparse
    ap = argparse.ArgumentParser(
        description='Patch camera libraries to add raw/DNG support')
    ap.add_argument('--mode', choices=['3rdparty', 'metastore-raw16'],
                    default='3rdparty',
                    help='Which library to patch (default: 3rdparty)')
    ap.add_argument('--width', type=int, default=4352,
                    help='RAW16 width (metastore-raw16 mode, default: 4352)')
    ap.add_argument('--height', type=int, default=2448,
                    help='RAW16 height (metastore-raw16 mode, default: 2448)')
    ap.add_argument('so', help='Path to stock .so file')
    ap.add_argument('out', nargs='?', help='Output path (default: <so>.patched)')
    ap.add_argument('--dry-run', '-n', action='store_true', help='Simulate; write nothing')
    args = ap.parse_args()

    in_path = args.so
    out_path = args.out if args.out else in_path + '.patched'

    if not os.path.exists(in_path):
        sys.exit(f"ERROR: input file not found: {in_path}")

    if args.mode == 'metastore-raw16':
        patch_metastore_raw16(in_path, out_path, dry_run=args.dry_run,
                              raw16_res=(args.width, args.height))
    else:
        patch_3rdparty_customer(in_path, out_path, dry_run=args.dry_run)


if __name__ == '__main__':
    main()
