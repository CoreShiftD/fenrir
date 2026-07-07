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
                                    entry_for_va, ientry_dtor_va,
                                    raw16_res, stream_cfg_tag=0xd000a):
    """
    Build an AArch64 trampoline that injects RAW16 entries into BOTH the
    recommended and standard MTK_SCALER_AVAILABLE_STREAM_CONFIGURATIONS.

    On entry (from original call site at 0x76174):
      x0 = IMetadata*  (saved to x20)
      x2 = IEntry*     (saved to x19, points to recommended IEntry)

    The trampoline:
      1. Pushes 4 int32 values (format=0x20, w, h, dir=0) to the
         recommended IEntry and calls update().
      2. Calls IMetadata::entryFor(stream_cfg_tag, 0) to get a copy of
         the standard stream config IEntry, pushes the same RAW16 tuple,
         calls update(), and destructs the copy.
    """
    SC = stream_cfg_tag
    w, h = raw16_res
    code = bytearray()
    pc = tramp_va

    def emit(b):
        nonlocal code, pc
        code += b; pc += len(b)

    def emit_u32(v):
        nonlocal code, pc
        code += struct.pack('<I', v); pc += 4

    def emit_bl(tgt):
        nonlocal code, pc
        code += bl_encode(pc, tgt); pc += 4

    # Atomic instruction helpers
    def mov_w0_val(v):
        if v > 0xFFFF:
            low = v & 0xFFFF; high = (v >> 16) & 0xFFFF
            emit_u32(0x52800000 | (low << 5))
            emit_u32(0x72A00000 | (high << 5))
        else:
            emit_u32(0x52800000 | (v << 5))

    def pushback_one():
        """push_back one int32 from [sp] into IEntry at x0, clobbers x1,x2"""
        emit_u32(0x910003E1)  # add x1, sp, #0
        emit_u32(0xAA1F03E2)  # mov x2, xzr
        emit_bl(push_back_va)

    def push_raw16_quad(ientry_reg):
        """push 4 int32s (0x20, w, h, 0) to IEntry in ientry_reg."""
        # format=0x20
        mov_w0_val(0x20)
        emit_u32(0xB90003E0)  # str w0, [sp]
        if ientry_reg == 'sp+0x10':
            emit_u32(0x910043E0)  # add x0, sp, #0x10
        else:
            emit_u32(0xAA1303E0)  # mov x0, x19
        pushback_one()
        # width
        mov_w0_val(w)
        emit_u32(0xB90003E0)
        if ientry_reg == 'sp+0x10':
            emit_u32(0x910043E0)
        else:
            emit_u32(0xAA1303E0)
        pushback_one()
        # height
        mov_w0_val(h)
        emit_u32(0xB90003E0)
        if ientry_reg == 'sp+0x10':
            emit_u32(0x910043E0)
        else:
            emit_u32(0xAA1303E0)
        pushback_one()
        # direction = 0
        emit_u32(0xB90003FF)  # str wzr, [sp]
        if ientry_reg == 'sp+0x10':
            emit_u32(0x910043E0)
        else:
            emit_u32(0xAA1303E0)
        pushback_one()

    # ─── stack: 0x80 bytes ───
    #   sp+0x00: temp int32 (4B + padding)
    #   sp+0x10: IEntry buffer for stream cfg (0x50 bytes, 16-aligned)
    #   sp+0x60: x29, x30
    #   sp+0x70: x19, x20
    # Total: 0x80
    emit_u32(0xD10203FF)  # sub sp, sp, #0x80
    emit_u32(0xA90E7BFD)  # stp x29, x30, [sp, #0x60]
    emit_u32(0xA90D53F3)  # stp x19, x20, [sp, #0x50]
    emit_u32(0xAA0203F3)  # mov x19, x2        ; recommended IEntry* (= sp+0x90 in caller)
    emit_u32(0xAA0003F4)  # mov x20, x0        ; IMetadata*

    # ─── Part 0: inline updateAfRegions logic ───
    # The original BL at 0x76174 called updateAfRegions() which pushes 4
    # int32 values (0x20, 0x1100=4352, 0x990=2448, 0) then calls update().
    # updateAfRegions itself has a use-after-free race so we inline its
    # push_back work here instead.  Format=0x20, width=4352, height=2448.
    mov_w0_val(0x20)
    emit_u32(0xB90003E0)  # str w0, [sp]
    emit_u32(0xAA1303E0)  # mov x0, x19
    pushback_one()
    mov_w0_val(0x1100)    # width = 4352
    emit_u32(0xB90003E0)
    emit_u32(0xAA1303E0)
    pushback_one()
    mov_w0_val(0x990)     # height = 2448
    emit_u32(0xB90003E0)
    emit_u32(0xAA1303E0)
    pushback_one()
    emit_u32(0xB90003FF)  # str wzr, [sp]      ; direction = 0
    emit_u32(0xAA1303E0)
    pushback_one()

    # ─── Part 1: recommended entry (inject RAW16) ───
    push_raw16_quad('x19')
    emit_u32(0xAA1303E0)  # mov x0, x19
    emit_bl(tag_va)
    emit_u32(0xAA1403E0)  # mov x0, x20
    emit_u32(0x2A0003E1)  # mov w1, w0
    emit_u32(0xAA1303E2)  # mov x2, x19
    emit_bl(update_va)

    # ─── Part 2: standard stream config ───
    # entryFor(IMetadata* x20, SC, 0) → IEntry at sp+0x10 via x8
    emit_u32(0x910043E8)  # add x8, sp, #0x10  ; return buffer
    low = SC & 0xFFFF; high = (SC >> 16) & 0xFFFF
    emit_u32(0x52800001 | (low << 5))           # movz w1, #low
    if high:
        emit_u32(0x72A00001 | (high << 5))       # movk w1, #high, lsl 16
    emit_u32(0xAA1F03E2)  # mov w2, wzr          ; flags = 0
    emit_u32(0xAA1403E0)  # mov x0, x20          ; IMetadata*
    emit_bl(entry_for_va)

    push_raw16_quad('sp+0x10')
    emit_u32(0x910043E0)  # add x0, sp, #0x10
    emit_bl(tag_va)
    emit_u32(0xAA1403E0)  # mov x0, x20
    emit_u32(0x2A0003E1)  # mov w1, w0
    emit_u32(0x910043E2)  # add x2, sp, #0x10
    emit_bl(update_va)
    emit_u32(0x910043E0)  # add x0, sp, #0x10
    emit_bl(ientry_dtor_va)

    # ─── Epilogue ───
    emit_u32(0xA94D53F3)  # ldp x19, x20, [sp, #0x50]
    emit_u32(0xA94E7BFD)  # ldp x29, x30, [sp, #0x60]
    emit_u32(0x910203FF)  # add sp, sp, #0x80
    # Load W20 from the original PC-relative data (at VA 0x76184).
    # The original instruction at 0x76174 was LDR W20, [PC, #16]
    # (in 0ea09e version it was BL, but handle correctly either way)
    ldr_pc = pc
    ldr_offset = (0x76184 - ldr_pc)
    ldr_imm19 = ldr_offset >> 2
    emit_u32(0x18000000 | ((ldr_imm19 & 0x7FFFF) << 5) | 20)  # ldr w20, [pc, #imm]
    b_pc = pc
    b_imm26 = (0x76178 - b_pc) >> 2
    emit_u32(0x14000000 | (b_imm26 & 0x3FFFFFF))  # b #0x76178

    return bytes(code)


def _find_rx_load(data):
    """Find the RX (executable) LOAD segment. Returns (idx, offset, vaddr, filesz, memsz)."""
    phoff = struct.unpack_from('<Q', data, 0x20)[0]
    phnum = struct.unpack_from('<H', data, 0x38)[0]
    phentsize = struct.unpack_from('<H', data, 0x36)[0]

    for i in range(phnum):
        ph = data[phoff + i * phentsize : phoff + (i+1) * phentsize]
        p_type = struct.unpack_from('<I', ph, 0)[0]
        if p_type == PT_LOAD:
            p_flags = struct.unpack_from('<I', ph, 4)[0]
            p_offset = struct.unpack_from('<Q', ph, 8)[0]
            p_vaddr = struct.unpack_from('<Q', ph, 16)[0]
            p_filesz = struct.unpack_from('<Q', ph, 32)[0]
            p_memsz = struct.unpack_from('<Q', ph, 40)[0]
            if p_flags & 1:
                return i, p_offset, p_vaddr, p_filesz, p_memsz
    raise RuntimeError("No executable LOAD segment found")


def patch_metastore_raw16(in_path, out_path, dry_run=False, raw16_res=(4352, 2448)):
    """
    Patch libmtkcam_metastore.so to inject RAW16 entries into the
    recommended stream configurations layout via an ELF trampoline.

    The trampoline is placed at the end of the executable LOAD segment,
    extending it so no existing code is overwritten.
    """
    with open(in_path, 'rb') as f:
        data = bytearray(f.read())

    width, height = raw16_res

    # Hardcoded VA for stock A75 libmtkcam_metastore.so
    patch_va    = 0x76174
    push_back   = 0xab110     # IEntry::push_back(int32)
    tag_fn      = 0xab0c0     # IEntry::tag()
    update_fn   = 0xab0d0     # IMetadata::update()
    entry_for   = 0xab140     # IMetadata::entryFor(tag, flags)
    ientry_dtor = 0xab100     # IEntry::~IEntry()

    # Parse ELF to find safe trampoline location at end of RX LOAD
    load2_idx, load2_offset, load2_vaddr, load2_filesz, load2_memsz = \
        _find_rx_load(data)
    tramp_va = load2_vaddr + load2_filesz  # right after last mapped byte
    # Convert VAs to file offsets for accessing data[]
    patch_file_off  = patch_va - load2_vaddr + load2_offset
    tramp_file_off  = load2_offset + load2_filesz

    print(f"Executable LOAD: VA 0x{load2_vaddr:x}-0x{tramp_va:x} "
          f"(size 0x{load2_filesz:x})")

    # Build the trampoline
    trampoline = make_metastore_raw16_trampoline(
        tramp_va, push_back, tag_fn, update_fn,
        entry_for, ientry_dtor, (width, height))
    tramp_len = len(trampoline)
    new_filesz = load2_filesz + tramp_len
    new_memsz = max(load2_memsz, new_filesz)

    print(f"Trampoline: {tramp_len} bytes at VA 0x{tramp_va:x} → 0x{tramp_va + tramp_len:x}")

    # Verify BL targets in trampoline
    name_map = {
        push_back: 'push_back', tag_fn: 'tag()', update_fn: 'update()',
        entry_for: 'entryFor', ientry_dtor: '~IEntry()',
    }
    for off in range(0, tramp_len, 4):
        insn = struct.unpack_from('<I', trampoline, off)[0]
        if (insn & 0xFC000000) == 0x94000000:
            imm26 = insn & 0x3FFFFFF
            if imm26 & (1 << 25):
                imm26 -= (1 << 26)
            tgt = (tramp_va + off) + imm26 * 4
            name = name_map.get(tgt, f'0x{tgt:x}')
            print(f"  BL at 0x{tramp_va+off:x} → 0x{tgt:x} ({name})")

    # Verify: original bytes at patch point (using file offset)
    orig_bytes = bytes(data[patch_file_off:patch_file_off+4])
    print(f"Patch point VA 0x{patch_va:x} (file offset 0x{patch_file_off:x}): "
          f"current bytes = {orig_bytes.hex()}")

    # Extend file and write trampoline (using file offset)
    needed = tramp_file_off + tramp_len - len(data)
    if needed > 0:
        data.extend(b'\x00' * needed)
    data[tramp_file_off:tramp_file_off + tramp_len] = trampoline

    # Update RX LOAD segment header
    phoff = struct.unpack_from('<Q', data, 0x20)[0]
    phentsize = struct.unpack_from('<H', data, 0x36)[0]
    ph_off = phoff + load2_idx * phentsize
    struct.pack_into('<Q', data, ph_off + 32, new_filesz)
    struct.pack_into('<Q', data, ph_off + 40, new_memsz)
    print(f"  Extended LOAD p_filesz: 0x{load2_filesz:x} → 0x{new_filesz:x}")
    print(f"  Extended LOAD p_memsz:  0x{load2_memsz:x} → 0x{new_memsz:x}")

    # Patch BL at call site to redirect to trampoline (VAs, not file offsets)
    new_bl = bl_encode(patch_va, tramp_va)
    data[patch_file_off:patch_file_off+4] = new_bl
    print(f"Patched BL at VA 0x{patch_va:x} (file off 0x{patch_file_off:x}): "
          f"{orig_bytes.hex()} → {new_bl.hex()}")

    # NOP updateAfRegions at VA 0x761d4 to work around a use-after-free race
    # (FORTIFY: pthread_mutex_lock on destroyed mutex).
    # Replace first instruction with RET (0xD65F03C0).
    nop_va = 0x761d4
    nop_file_off = nop_va - load2_vaddr + load2_offset
    orig_nop = bytes(data[nop_file_off:nop_file_off+4])
    data[nop_file_off:nop_file_off+4] = struct.pack('<I', 0xD65F03C0)
    print(f"NOP'd updateAfRegions at VA 0x{nop_va:x}: {orig_nop.hex()} → d65f03c0 (ret)")

    # Write output
    if dry_run:
        print(f"\n✓ [DRY RUN] Would write patched metastore to {out_path}")
    else:
        with open(out_path, 'wb') as f:
            f.write(data)
        print(f"\n✓ Patched metastore written to {out_path}")
    print(f"  RAW16 resolution: {width}×{height}")
    print(f"  File size: {len(data)} bytes")


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
