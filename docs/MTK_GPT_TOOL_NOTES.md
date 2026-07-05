# MTK GPT partition table construction and patching

**Goal:** generate or modify MediaTek-style GPT partition tables (PGPT.img /
SGPT.img) from a scatter XML file, preserving the quirks of MTK's vendor GPT
format.

Tool: `injector/mtk_gpt_tool.py`

---

## 1. Background — MediaTek GPT layout

Unlike a standard UEFI GPT where partition table size is spec-minimal (34 LBAs
for the protective MBR + primary header + entries table + padding), MediaTek
devices use fixed-size **image blocks** for PGPT and SGPT — typically 32 KiB
each (`image_block_bytes = 0x8000`). The scatter file's `pgpt` and `sgpt`
partition entries define this size, not the number of partition entries.

### Key MTK GPT quirks

| quirk | detail |
|-------|--------|
| **Fixed-size images** | PGPT.img / SGPT.img are always 32 KiB (default), even if the entries table would fit in 2 LBAs. |
| **Protective MBR** | Included at PGPT offset 0 (1 sector, typically 512 or 4096 B). |
| **Primary header** | At LBA 1 (sector 1 of the PGPT image). |
| **Entries table** | At LBA 2+ (immediately after the header). |
| **Backup header** | At the very last sector of SGPT.img. |
| **Disk GUID** | Unique per device — preserved across patches so the OS sees the same disk. |
| **Partition GUIDs** | Deterministic: `struct.pack("<I", index) + 0xc23988449bb000cb43c9ccd4`. |
| **Type GUID** | `a2a0d0ebe5b9334487c068b6b72699c7` — all MTK partitions use the same type GUID. |

---

## 2. Scatter file oddities this tool handles

### 2a. NEEDRESIZE partitions

A scatter entry marked `operation_type=NEEDRESIZE` (normally `userdata`) has a
**placeholder** `partition_size`, not the real size. The real size is computed
at build time as whatever space remains on the disk after all fixed-size
partitions are placed. This tool handles NEEDRESIZE by snapping the end of
the partition to `reserved_start_lba - 1`.

### 2b. Reserved-from-end addresses

Entries with `linear_start_addr` / `physical_start_addr` in the form
`0xFFFFxxxx` are positioned relative to the **end** of the disk, not the
start — the sentinel `0xFFFFFFFF` means "the very last byte". These are
typically RESERVED partitions (`flashinfo`, `sgpt` itself). The offset from
end is computed as `0xFFFFFFFF - addr + 1`.

### 2c. pgpt/sgpt entries themselves

The scatter file's own `pgpt` (operation_type=INVISIBLE) and `sgpt`
(operation_type=RESERVED) entries describe the **GPT structures themselves**.
They are NEVER included as partition entries in the GPT — they only determine
the `image_block_bytes` size for PGPT and SGPT images, and the `sgpt_size_lba`
for the backup GPT region at the end of the disk.

### 2d. Multiple LUNs/regions

A single scatter file can describe multiple storage regions (e.g., UFS LUNs:
`UFS_LU0` = preloader, `UFS_LU1` = backup, `UFS_LU2` = user data GPT). The
tool isolates the correct region by finding the one that contains `pgpt` with
`operation_type=INVISIBLE`.

---

## 3. Partition layout resolution

### Rules for converting scatter entries to LBA ranges

1. Skip `pgpt`/`sgpt` entries (they describe the GPT structures, not actual
   partitions).
2. Reserved-from-end entries (`0xFFFFxxxx`) are placed starting from the end
   of the disk, sorted by proximity to `0xFFFFFFFF` (closest to end first).
3. Normal entries are placed at `linear_start_addr / sector_size` with
   `partition_size / sector_size` length.
4. NEEDRESIZE entries have their end snapped to `reserved_start_lba - 1`
   (the first LBA before the reserved tail region).

### Sector size

Sector size is **not always 512**. eMMC regions use 512-byte LBAs; UFS regions
commonly use 4096-byte LBAs. Pass `--sector-size` explicitly or let the tool
guess from `--storage` (4096 for UFS, 512 for eMMC).

---

## 4. GPT binary construction

### Protective MBR

Standard type-0xEE protective MBR covering the whole disk (or up to 2 TiB for
512-byte sectors), with signature `55 AA`.

### GPT header

Standard fields per UEFI spec:
- Signature: `EFI PART`
- Revision: 0x00010000
- Header CRC computed over header bytes [0..91] after zeroing the CRC field.
- `my_lba`, `alt_lba` swapped between primary and backup copies.
- `entries_lba`: 2 for primary, computed for backup.
- `first_usable_lba`: after the reserved front region (PGPT size).
- `last_usable_lba`: before the reserved back region (SGPT size).

### Partition entries

Each entry (128 bytes):
- Type GUID (constant): `a2a0d0ebe5b9334487c068b6b72699c7`
- Unique GUID: `struct.pack("<I", index) + c23988449bb000cb43c9ccd4`
- First LBA, Last LBA, Attribute flags
- Name: UTF-16-LE, 36 characters max, null-padded to 72 bytes

### Image assembly

PGPT.img = MBR + primary header + entries table, zero-padded to 32 KiB.
SGPT.img = entries table + zero padding + backup header at last sector,
zero-padded to 32 KiB.

---

## 5. Patch mode — GUID preservation

When `patch` mode is used instead of `generate`, the tool:

1. Reads the existing PGPT.img to extract unique GUIDs for each existing
   partition name.
2. Reuses those GUIDs in the new layout (GUIDs for partitions that exist in
   both old and new layout are byte-identical).
3. Preserves the disk GUID from the original header — so the OS sees the
   same disk identity.
4. Partitions new to the layout get a freshly derived GUID.

This means flashing a patched PGPT/SGPT pair over an existing install does
not change partition UUIDs — critical for `by-name` mounts, `fstab`, and
`init_boot` AVB rollback protection.

---

## 6. `to-scatter` mode — reconstructing a scatter file from an actual device

The `to-scatter` subcommand reads a real PGPT.img from a device and rewrites
a template scatter XML's address/size fields to reflect the actual on-disk
layout. It:

1. Identifies the target region in the template scatter by finding the `pgpt`
   entry with `operation_type=INVISIBLE`.
2. For each template partition present in the real GPT, updates
   `linear_start_addr` / `physical_start_addr` / `partition_size` to match.
3. Leaves RESERVED entries alone (their addresses are flash-time computed).
4. Leaves NEEDRESIZE entries' `partition_size` alone (it's a placeholder).
5. Inserts new `<partition_index>` blocks for partitions found on the device
   but absent from the template — cloned from the `userdata` entry as a
   structural template (operation_type is set to `UPDATE` as a best guess).

---

## 7. Usage

### Generate fresh GPT images from a scatter file

```bash
python3 mtk_gpt_tool.py generate \
    --scatter scatter.xml \
    --storage ufs \
    --disk-size 512GB \
    --out-dir ./out
```

### Patch existing GPT images with a new layout from a scatter

```bash
python3 mtk_gpt_tool.py patch \
    --scatter scatter.xml \
    --storage ufs \
    --pgpt PGPT.img \
    --disk-size 512GB \
    --out-dir ./out
```

### Inspect an existing PGPT.img

```bash
python3 mtk_gpt_tool.py inspect --pgpt PGPT.img
```

### Reconstruct a scatter XML from a device dump

```bash
python3 mtk_gpt_tool.py to-scatter \
    --scatter template_scatter.xml \
    --storage ufs \
    --pgpt PGPT.img \
    --out reconstructed_scatter.xml
```

---

## 8. Advanced options

| flag | applies to | description |
|------|-----------|-------------|
| `--sector-size` | all | Override sector size detection (default: 4096 for UFS, 512 for eMMC) |
| `--num-entries` | generate, patch | GPT entry slot count (default: exact partition count; use 128 for spec-typical GPTs) |
| `--first-usable-lba` | generate, patch | Override `firstUsableLBA` header field. Some vendor tools hardcode 34 (the 512-byte classic) even on 4096-byte disks. |
| `--sgpt` | patch | Optional path to existing SGPT.img for additional verification |

---

## 9. File format reference

PGPT.img layout (32 KiB default):

| offset | content |
|--------|---------|
| 0x0000 | Protective MBR (1 sector) |
| 0x0200 | Primary GPT header (1 sector, LBA 1) |
| 0x0400 | Partition entries start (LBA 2+) |
| ... | entries (128 B each, up to image size) |
| 0x7FFF | end of image |

SGPT.img layout (32 KiB default):

| offset | content |
|--------|---------|
| 0x0000 | Partition entries (same bytes as PGPT) |
| ... | zero padding |
| 0x7E00 | Backup GPT header (last sector) |
| 0x7FFF | end of image |

The 32 KiB block size is per-device convention (from the scatter file's
`pgpt`/`sgpt` `partition_size`). Other devices may use different sizes.
