#!/usr/bin/env python3
"""
Patch DA_BR.bin to disable security checks for MT6789 (unfused).
Based on mtkclient's v6.py patching logic.

The DA2 in DA_BR.bin is ARM32 code. This script:
1. Locates security-related functions via string cross-references
2. Patches them to disable hash binding, image auth, etc.
3. Patches OEM-specific security (SLA, Vivo, OPlus)
"""

import os
import struct
import sys
from typing import Optional, Tuple

# ARM32 helpers (mirrors ArmTools from mtkclient)
ARM32_MOV_R0_0 = 0xE3A00000
ARM32_MOV_R0_1 = 0xE3A00001
ARM32_BX_LR = 0xE12FFF1E
ARM32_RET_R0 = b"\x00\x00\xA0\xE3\x1E\xFF\x2F\xE1"  # MOV R0,#0; BX LR
ARM32_RET_R1 = b"\x01\x00\xA0\xE3\x1E\xFF\x2F\xE1"  # MOV R0,#1; BX LR


def find_binary(data: bytes, pattern: bytes, start: int = 0) -> Optional[int]:
    idx = data.find(pattern, start)
    return idx if idx >= 0 else None


class ArmTools:
    def __init__(self, data: bytes, base_addr: int):
        self.data = data
        self.base_addr = base_addr

    def va_to_offset(self, va: int) -> Optional[int]:
        off = va - self.base_addr
        if off < 0 or off >= len(self.data):
            return None
        return off

    def offset_to_va(self, offset: int) -> Optional[int]:
        if offset < 0 or offset >= len(self.data):
            return None
        return self.base_addr + offset

    def read_u32(self, offset: int) -> Optional[int]:
        if offset + 4 > len(self.data):
            return None
        return int.from_bytes(self.data[offset:offset+4], 'little')

    def find_string(self, s: str) -> Optional[int]:
        target = s.encode('utf-8')
        pos = self.data.find(target + b'\x00')
        if pos >= 0:
            return pos
        pos = self.data.find(target)
        if pos >= 0:
            return pos
        return None

    def decode_bl(self, instr: int, pc: int) -> Optional[int]:
        opcode = instr & 0xFF000000
        if opcode not in (0xEB000000, 0xEA000000):
            return None
        imm24 = instr & 0x00FFFFFF
        if imm24 & 0x00800000:
            imm24 -= 0x01000000
        arm_pc = pc + 8
        return arm_pc + (imm24 * 4)

    def get_bl_target(self, offset: int) -> Optional[int]:
        instr = self.read_u32(offset)
        if instr is None:
            return None
        pc = self.offset_to_va(offset)
        if pc is None:
            return None
        return self.decode_bl(instr, pc)

    def decode_movw(self, instr: int) -> Optional[Tuple[int, int]]:
        if (instr & 0x0FF00000) == 0x03000000:
            rd = (instr >> 12) & 0xF
            imm4 = (instr >> 16) & 0xF
            imm12 = instr & 0xFFF
            imm16 = (imm4 << 12) | imm12
            return rd, imm16
        return None

    def decode_movt(self, instr: int) -> Optional[Tuple[int, int]]:
        if (instr & 0x0FF00000) == 0x03400000:
            rd = (instr >> 12) & 0xF
            imm4 = (instr >> 16) & 0xF
            imm12 = instr & 0xFFF
            imm16 = (imm4 << 12) | imm12
            return rd, imm16
        return None

    def is_movw_imm(self, instr: int, imm16: int) -> bool:
        decoded = self.decode_movw(instr)
        if decoded is None:
            return False
        _, val = decoded
        return val == imm16

    def is_movt_imm(self, instr: int, imm16: int) -> bool:
        decoded = self.decode_movt(instr)
        if decoded is None:
            return False
        _, val = decoded
        return val == imm16

    def get_movw_reg(self, instr: int) -> int:
        return (instr >> 12) & 0xF

    def get_movt_reg(self, instr: int) -> int:
        return (instr >> 12) & 0xF

    def decode_ldr_pc(self, instr: int, pc: int) -> Optional[Tuple[int, int]]:
        if (instr & 0x0C5F0000) == 0x041F0000:
            u_bit = (instr >> 23) & 1
            rd = (instr >> 12) & 0xF
            imm12 = instr & 0xFFF
            arm_pc = pc + 8
            target = arm_pc + imm12 if u_bit else arm_pc - imm12
            return rd, target
        return None

    def find_string_xref(self, s: str) -> Optional[int]:
        str_off = self.find_string(s)
        if str_off is None:
            return None
        str_va = self.base_addr + str_off
        low16 = str_va & 0xFFFF
        high16 = (str_va >> 16) & 0xFFFF
        for off in range(0, len(self.data) - 8, 4):
            instr1 = self.read_u32(off)
            if instr1 is None:
                continue
            if self.is_movw_imm(instr1, low16):
                reg = self.get_movw_reg(instr1)
                found = False
                for la in range(off + 4, min(off + 80, len(self.data)), 4):
                    instr2 = self.read_u32(la)
                    if instr2 is None:
                        break
                    if self.is_movt_imm(instr2, high16) and self.get_movt_reg(instr2) == reg:
                        found = True
                        break
                if found:
                    return off
        for off in range(0, len(self.data) - 4, 4):
            instr = self.read_u32(off)
            if instr is None:
                continue
            pc = self.offset_to_va(off)
            if pc is None:
                continue
            ldr = self.decode_ldr_pc(instr, pc)
            if ldr is not None:
                _, addr = ldr
                if addr == str_va:
                    return off
        return None

    def is_prologue(self, instr: int) -> bool:
        return (instr & 0xFFFF0000) == 0xE92D0000 and (instr & (1 << 14)) != 0

    def find_function_start_from_off(self, offset: int) -> Optional[int]:
        limit = 0x2000
        search_start = max(0, offset - limit)
        for off in range(offset, search_start - 1, -4):
            instr = self.read_u32(off)
            if instr is None:
                continue
            if self.is_prologue(instr):
                return off
        return None

    def find_function_from_string(self, s: str) -> Optional[int]:
        xref = self.find_string_xref(s)
        if xref is None:
            return None
        return self.find_function_start_from_off(xref)

    def get_next_bl_from_off(self, offset: int) -> Optional[int]:
        off = offset
        while off < len(self.data):
            if self.get_bl_target(off) is not None:
                return off
            off += 4
        return None

    def get_previous_bl_from_off(self, offset: int) -> Optional[int]:
        scan_off = offset - 4
        limit = max(0, offset - 0x1000)
        while scan_off >= limit:
            if self.get_bl_target(scan_off) is not None:
                return scan_off
            scan_off -= 4
        return None

    def force_return(self, data: bytearray, offset: int, value: int) -> bytearray:
        mov_r0 = 0xE3A00000 | (value & 0xFF)
        bx_lr = 0xE12FFF1E
        data[offset:offset+4] = mov_r0.to_bytes(4, 'little')
        data[offset+4:offset+8] = bx_lr.to_bytes(4, 'little')
        return data

    def mem_patch(self, data: bytearray, offset: int, value: int) -> bytearray:
        data[offset:offset+4] = value.to_bytes(4, 'little')
        return data


def patch_da2(da2: bytes, base: int = 0x40000000) -> bytearray:
    da2p = bytearray(da2)
    at = ArmTools(da2, base)
    patched = False

    print("=" * 60)
    print("DA Security Patch Tool for MT6789 (ARM32)")
    print("=" * 60)

    # ============================================================
    # 1. Hash binding policy (5 functions): make them return R0=0
    # ============================================================
    print("\n[1] Hash binding policy...")
    flash_policy = at.find_function_from_string("hash_binding = %d\n")
    if flash_policy is not None:
        get_policy_entry_idx = at.get_next_bl_from_off(flash_policy)
        if get_policy_entry_idx is not None:
            hash_binding = at.get_next_bl_from_off(get_policy_entry_idx + 4)
            img_auth = at.get_next_bl_from_off(hash_binding + 4)
            dl_forbidden = at.get_next_bl_from_off(img_auth + 4)
            vfy_pol = at.get_next_bl_from_off(dl_forbidden + 4)
            dl_pol = at.get_next_bl_from_off(vfy_pol + 4)

            for name, bl_off in [
                ("hash_binding", hash_binding),
                ("img_auth", img_auth),
                ("dl_forbidden", dl_forbidden),
                ("vfy_pol", vfy_pol),
                ("dl_pol", dl_pol),
            ]:
                if bl_off is not None:
                    target = at.va_to_offset(at.get_bl_target(bl_off))
                    if target is not None:
                        da2p = at.mem_patch(da2p, target, ARM32_MOV_R0_0)
                        print(f"  ✓ {name} at da2+0x{target:x}")
                        patched = True
                    else:
                        print(f"  ✗ {name}: target invalid")
                else:
                    print(f"  ✗ {name}: BL not found")
        else:
            print("  ✗ get_policy_entry_idx not found")
    else:
        print("  ✗ 'hash_binding = %d' not found")

    # ============================================================
    # 2. Partial protect: make is_partitial_protect_enabled return 0
    # ============================================================
    print("\n[2] Partial protect...")
    erase_write_func = at.find_function_from_string("%s: partial_protect is enabled, start...")
    if erase_write_func is not None:
        is_pp_enabled_ptr = at.get_next_bl_from_off(erase_write_func)
        if is_pp_enabled_ptr is not None:
            is_pp_enabled = at.va_to_offset(at.get_bl_target(is_pp_enabled_ptr))
            if is_pp_enabled is not None:
                da2p = at.force_return(da2p, is_pp_enabled, 0)
                print(f"  ✓ is_partitial_protect_enabled at da2+0x{is_pp_enabled:x} returned 0")
                patched = True
            else:
                print("  ✗ target invalid")
        else:
            print("  ✗ BL not found after erase_write_func")
    else:
        print("  ✗ 'partial_protect is enabled' not found")

    # ============================================================
    # 3. DA version check: make it return 0 immediately
    # ============================================================
    print("\n[3] DA version check...")
    da_version = at.find_function_from_string("[%s] da version check, status(0x%x), CFI(0x%x)\n")
    if da_version is not None:
        da2p = at.force_return(da2p, da_version, 0)
        print(f"  ✓ da version check at da2+0x{da_version:x} force-returned")
        patched = True
    else:
        print("  ✗ 'da version check' not found")

    # ============================================================
    # 4. Read/write register check (32-bit specific)
    # ============================================================
    print("\n[4] Read/write register check...")
    read_write_ptr = at.find_function_from_string("R/W on this address is forbidden.")
    if read_write_ptr is not None:
        idx2 = find_binary(da2p, b"\x00\x00\x99\xE5", read_write_ptr)
        if idx2 is not None:
            check_allow_ptr = at.get_previous_bl_from_off(idx2)
            if check_allow_ptr is not None:
                allow_write_func = at.get_bl_target(check_allow_ptr)
                if allow_write_func is not None:
                    offs = at.va_to_offset(allow_write_func)
                    if offs is not None:
                        if da2p[offs:offs+4] == b"\x00\x00\xA0\xE3":
                            da2p[offs:offs+4] = b"\x01\x00\xA0\xE3"
                            print(f"  ✓ patched allow_read_register at da2+0x{offs:x}")
                            patched = True
                        if da2p[offs-8:offs-8+4] == b"\x00\x00\xA0\xE3":
                            da2p[offs-8:offs-8+4] = b"\x01\x00\xA0\xE3"
                            print(f"  ✓ patched allow_storage at da2+0x{offs-8:x}")
                            patched = True
                        if da2p[offs+8:offs+8+4] == b"\x00\x00\xA0\xE3":
                            da2p[offs+8:offs+8+4] = b"\x01\x00\xA0\xE3"
                            print(f"  ✓ patched allow_write_register at da2+0x{offs+8:x}")
                            patched = True
        else:
            print("  ✗ LDR R0,[R9] pattern not found after function")
    else:
        print("  - R/W forbidden string not found (DA may not have this check)")

    # ============================================================
    # 5. Hash binding printf patch (MOV R1, #1 -> MOV R1, #0)
    # ============================================================
    print("\n[5] Hash binding printf patch...")
    hash_bind_str = at.find_string_xref("hash_binding:%d, img_auth_required:%d\n")
    if hash_bind_str is not None:
        get_log_level_ptr = at.get_previous_bl_from_off(hash_bind_str)
        if get_log_level_ptr is not None:
            branch_ptr = at.get_previous_bl_from_off(get_log_level_ptr - 4)
            if branch_ptr is not None:
                hash_bind_ptr = at.get_previous_bl_from_off(branch_ptr - 4)
                if hash_bind_ptr is not None:
                    hash_bind_func = at.va_to_offset(at.get_bl_target(hash_bind_ptr))
                    if hash_bind_func is not None:
                        da2p[hash_bind_func:hash_bind_func+4] = b"\x00\x10\xA0\xE3"
                        print(f"  ✓ hash_bind_func at da2+0x{hash_bind_func:x} (MOV R1,#1->#0)")
                        patched = True
                    else:
                        print("  ✗ target invalid")
                else:
                    print("  ✗ hash_bind_ptr not found")
            else:
                print("  ✗ branch_ptr not found")
        else:
            print("  ✗ get_log_level_ptr not found")
    else:
        print("  ✗ 'hash_binding:%d...' xref not found")

    # ============================================================
    # 6. cust_security_verify_sec_policy (Oppo Remote SLA)
    # ============================================================
    print("\n[6] cust_security_verify_sec_policy...")
    cust_sec_ptr = at.find_function_from_string("cust_security_verify_sec_policy")
    if cust_sec_ptr is not None:
        da2p[cust_sec_ptr:cust_sec_ptr + 8] = ARM32_RET_R0
        print(f"  ✓ patched at da2+0x{cust_sec_ptr:x}")
        patched = True
    else:
        print("  - cust_security_verify_sec_policy not found")

    # ============================================================
    # 7. OPlus allowance
    # ============================================================
    print("\n[7] OPlus allowance...")
    oppo_allowance_xref = at.find_string_xref("[oplus] do not get oplus permission\n")
    if oppo_allowance_xref is not None:
        flag_offset = oppo_allowance_xref - 0x28
        decoded = at.decode_movw(at.read_u32(flag_offset))
        if decoded is not None:
            rd, imm16 = decoded
            decoded2 = at.decode_movt(at.read_u32(flag_offset + 4))
            if decoded2 is not None:
                rd2, imm32 = decoded2
                addr = (imm32 << 16) | imm16
                offset = at.va_to_offset(addr)
                if offset is not None:
                    da2p[offset:offset + 4] = b"\xFF\x00\x00\x00"
                    print(f"  ✓ patched OPlus allowance flag at da2+0x{offset:x} -> 0xFF")
                    patched = True
    else:
        print("  - OPlus allowance not found")

    # ============================================================
    # 8. OPlus auth
    # ============================================================
    print("\n[8] OPlus download authorization...")
    oppo_auth = at.find_string_xref("[OPLUS] Download authorization Ok in oplus")
    if oppo_auth is not None:
        if da2p[oppo_auth - 0x24:oppo_auth - 0x20] == b"\x03\x10\xA0\xE3":
            da2p[oppo_auth - 0x24:oppo_auth - 0x20] = b"\x05\x10\xA0\xE3"
            print("  ✓ patched oppo cust_security_get_dev_fw_info")
            patched = True
    else:
        print("  - OPlus download auth not found")

    # ============================================================
    # 9. SEC_POLICY sboot_state
    # ============================================================
    print("\n[9] SEC_POLICY sboot_state...")
    sec_pol = at.find_function_from_string("[SEC_POLICY] sboot_state = 0x%x\n")
    if sec_pol is not None:
        da2p[sec_pol:sec_pol + 8] = ARM32_RET_R0
        print(f"  ✓ patched at da2+0x{sec_pol:x}")
        patched = True
    else:
        print("  - SEC_POLICY sboot_state not found")

    # ============================================================
    # 10. SLA signature checks
    # ============================================================
    print("\n[10] SLA signature checks...")
    # Pattern: MOV R0, #0xC0020032
    idx3 = find_binary(da2p, b"\x32\x00\x00\xE3\x02\x00\x4C\xE3")
    if idx3 is not None:
        da2p[idx3:idx3 + 12] = b"\x00\x00\xA0\xE3\x00\x00\xA0\xE3\x00\x40\xA0\xE3"
        print(f"  ✓ patched SLA signature check 1 at da2+0x{idx3:x}")
        patched = True
    # Pattern: MOV R4, #0xC0020032
    idx4 = find_binary(da2p, b"\x32\x40\x00\xE3\x02\x40\x4C\xE3")
    if idx4 is not None:
        da2p[idx4:idx4 + 8] = b"\x00\x40\xA0\xE3\x00\x40\xA0\xE3"
        print(f"  ✓ patched SLA RND signature check at da2+0x{idx4:x}")
        patched = True
    if idx3 is None and idx4 is None:
        print("  - SLA signature checks not found")

    # Change "DA.SLA ENABLED" to "DA.SLA DISABLE"
    sla_idx = da2p.find(b"DA.SLA\x00ENABLED")
    if sla_idx != -1:
        da2p[sla_idx:sla_idx + 14] = b"DA.SLA\x00DISABLE"
        print("  ✓ marked SLA as DISABLE")
        patched = True
    else:
        print("  - DA.SLA ENABLED not found")

    # ============================================================
    # 11. Infinix Remote SLA v3
    # ============================================================
    print("\n[11] Infinix Remote SLA v3...")
    idx2 = find_binary(da2p, b"\xF0\x4D\x2D\xE9\x18\xB0\x8D\xE2\xF0\xD0\x4D\xE2\x01\x50\xA0\xE1")
    if idx2 is not None:
        da2p[idx2:idx2 + 8] = ARM32_RET_R0
        print(f"  ✓ patched at da2+0x{idx2:x}")
        patched = True
    else:
        print("  - Infinix SLA v3 not found")

    # ============================================================
    # 12. Vivo Remote SLA
    # ============================================================
    print("\n[12] Vivo Remote SLA...")
    vivo_remote_sla = at.find_function_from_string("vivo_infobak SIG Verify Fail! ret:%d")
    if vivo_remote_sla is not None:
        da2p[vivo_remote_sla:vivo_remote_sla + 8] = ARM32_RET_R0
        print(f"  ✓ patched at da2+0x{vivo_remote_sla:x}")
        patched = True
    else:
        print("  - Vivo Remote SLA not found")

    # ============================================================
    print(f"\n{'='*60}")
    if patched:
        print("✅ Patches applied successfully.")
    else:
        print("❌ No patches were applied!")
    return da2p


def patch_da1(da1: bytes, base: int = 0x200000) -> bytearray:
    da1p = bytearray(da1)
    at = ArmTools(da1, base)
    patched = False

    print("\n" + "=" * 60)
    print("DA1 Patches (entry fix + hash bypass)")
    print("=" * 60)

    # ============================================================
    # 0. Entry point: B #-4 -> B #0x14
    #    BROM jumps to 0x200000, but the first instruction is an
    #    infinite loop (parasite check). The real init code is at +0x14.
    # ============================================================
    print("\n[0] Entry point parasite fix...")
    entry_off = 0
    orig_4b = int.from_bytes(da1[entry_off:entry_off+4], 'little')
    entry_valid = False

    # Two possible stock values:
    #   0xEAFFFFFE  B #-4      (self-loop -- parasitic dead-man switch)
    #   0xEAFFFFFF  B 0x200004 (enters helper, then BX LR -> garbage)
    # Both need to become: B #0x14 -> jump directly to real init at 0x200014
    if orig_4b in (0xEAFFFFFE, 0xEAFFFFFF):
        # Decode original target for display
        imm24 = orig_4b & 0xFFFFFF
        if imm24 & 0x800000:
            imm24 -= 0x1000000
        orig_target = 0x200008 + imm24 * 4
        da1p[entry_off:entry_off+4] = b"\x03\x00\x00\xEA"  # B #0x14
        print(f"  ✓ Entry 0x{orig_4b:08x} (B {hex(orig_target)}) -> B #0x14")
        patched = True
    else:
        print(f"  ⚠ Entry is 0x{orig_4b:08x} (unexpected pattern), patching anyway...")
        da1p[entry_off:entry_off+4] = b"\x03\x00\x00\xEA"  # B #0x14
        print(f"  ✓ Forced entry to B #0x14")
        patched = True

    # ============================================================
    # 1. Force hash byte-comparison skip
    #    At VA 0x2012fc: CMP R0, #0 (0xE3500000) -> CMP R0, R0 (0xE1500000)
    #    This makes BEQ at 0x201300 always taken, skipping the
    #    byte-by-byte comparison against the stored hash at 0x226db8.
    # ============================================================
    cmp_off = 0x2012fc - base
    if cmp_off < len(da1):
        orig = int.from_bytes(da1[cmp_off:cmp_off+4], 'little')
        if orig == 0xE3500000:  # CMP R0, #0
            da1p[cmp_off:cmp_off+4] = b"\x00\x00\x50\xE1"  # CMP R0, R0
            print(f"  ✓ Patched hash skip check at da1+0x{cmp_off:x} (VA 0x{base+cmp_off:x})")
            patched = True
        else:
            print(f"  ✗ Expected CMP R0,#0 at da1+0x{cmp_off:x}, got 0x{orig:08x}")

    # ============================================================
    # 2. NOP the BNE in the byte-by-byte comparison loop
    #    At VA 0x20131c: BNE -> NOP
    #    Backup: makes byte comparison never trigger mismatch
    # ============================================================
    bne_off = 0x20131c - base
    if bne_off < len(da1):
        orig = int.from_bytes(da1[bne_off:bne_off+4], 'little')
        if (orig & 0xFF000000) == 0x1A000000:  # BNE
            da1p[bne_off:bne_off+4] = b"\x00\x00\x00\x1A"  # NOP (conditional NOP for ARM32)
            print(f"  ✓ Patched BNE->NOP at da1+0x{bne_off:x} (VA 0x{base+bne_off:x})")
            patched = True
        else:
            print(f"  ✗ Expected BNE at da1+0x{bne_off:x}, got 0x{orig:08x}")

    # ============================================================
    # 3. Also force CMP in the byte loop to always match
    #    At VA 0x201318: CMP R3, R2 (0xE1530002) -> CMP R3, R3 (0xE1530003)
    # ============================================================
    cmp2_off = 0x201318 - base
    if cmp2_off < len(da1):
        orig = int.from_bytes(da1[cmp2_off:cmp2_off+4], 'little')
        if orig == 0xE1530002:  # CMP R3, R2
            da1p[cmp2_off:cmp2_off+4] = b"\x03\x00\x53\xE1"  # CMP R3, R3
            print(f"  ✓ Patched byte CMP at da1+0x{cmp2_off:x} (VA 0x{base+cmp2_off:x})")
            patched = True
        else:
            print(f"  ✗ Expected CMP R3,R2 at da1+0x{cmp2_off:x}, got 0x{orig:08x}")

    if not patched:
        print("  ❌ No DA1 patches were applied!")

    return da1p


def main():
    import argparse
    sys.path.insert(0, os.path.dirname(__file__))
    from devices import DA_DEVICES

    parser = argparse.ArgumentParser(description="Patch DA_BR.bin to disable security checks")
    parser.add_argument('--device', default='a75', help='Device name (default: a75)')
    parser.add_argument('--input', help='Input DA_BR.bin path (overrides device lookup)')
    parser.add_argument('--output', help='Output path (default: same dir as input, suffixed _patched)')
    parser.add_argument('--no-da1', action='store_true', help='Skip DA1 patching')
    parser.add_argument('--no-da2', action='store_true', help='Skip DA2 patching')
    args = parser.parse_args()

    device_name = args.device.lower()
    da_dev = DA_DEVICES.get(device_name)
    if da_dev is None:
        known = list(DA_DEVICES.keys())
        print(f"Device '{device_name}' not found in DA_DEVICES. Known: {known}")
        return 1

    if args.input:
        bin_path = args.input
    else:
        fw_dir = f"bin/firmware/{device_name}/download_agent"
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        bin_path = os.path.join(repo_root, fw_dir, "DA_BR.bin")

    out_path = args.output or bin_path.replace(".bin", "_patched.bin")
    print(f"Input:  {bin_path}")
    print(f"Output: {out_path}")

    with open(bin_path, 'rb') as f:
        stock = f.read()

    da1_off = 0xbc
    da1_len = 0x62ee8
    da2_off = 0x62fa4
    da2_len = 0x51bf8

    da1 = stock[da1_off:da1_off+da1_len]
    da2 = stock[da2_off:da2_off+da2_len]

    print(f"Stock DA_BR.bin: {len(stock)} bytes")
    print(f"DA1 at offset 0x{da1_off:x}, size 0x{da1_len:x} ({da1_len} bytes)")
    print(f"DA2 at offset 0x{da2_off:x}, size 0x{da2_len:x} ({da2_len} bytes)")

    # Patch DA2 security policies
    da2p = da2
    if args.no_da2 or not da_dev.get('da2_patch', True):
        print("\n[SKIP] DA2 patching disabled")
    else:
        da2p = patch_da2(da2)

    # Patch DA1 hash verification
    da1p = da1
    if args.no_da1 or not da_dev.get('da1_patch', True):
        print("\n[SKIP] DA1 patching disabled")
    else:
        da1p = patch_da1(da1)

    # Rebuild full binary
    patched = bytearray(stock)
    patched[da1_off:da1_off+da1_len] = da1p
    patched[da2_off:da2_off+da2_len] = da2p
    with open(out_path, 'wb') as f:
        f.write(patched)
    print(f"\nPatched DA written to {out_path}")
    print(f"Size: {len(patched)} bytes")

    # Verify integrity
    import hashlib
    orig_hash = hashlib.sha256(stock).hexdigest()[:16]
    patched_hash = hashlib.sha256(patched).hexdigest()[:16]
    print(f"SHA256 (first 16): orig={orig_hash} patched={patched_hash}")
    if orig_hash != patched_hash:
        changed = sum(1 for a, b in zip(stock, patched) if a != b)
        print(f"Bytes changed: {changed} / {len(stock)}")
    else:
        print("WARNING: Files are identical!")

    return 0


if __name__ == "__main__":
    sys.exit(main())
