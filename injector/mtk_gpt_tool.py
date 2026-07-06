#!/usr/bin/env python3
"""
mtk_gpt_tool.py

Build or patch MediaTek-style GPT partition tables (PGPT.img / SGPT.img)
directly from an MTK scatter XML file.

Key facts this tool encodes (learned from inspecting real scatter +
GPT dumps):

  * A scatter file's <partition_size> for an entry marked
    operation_type=NEEDRESIZE (normally "userdata") is only a placeholder.
    The real size is computed at build time as whatever space is left
    on the target disk.

  * Entries with linear_start_addr/physical_start_addr in the form
    0xFFFFxxxx are positioned relative to the END of the disk, not the
    start. These are usually RESERVED partitions (flashinfo, sgpt itself).
    0xFFFFFFFF is "the very last byte", so offset-from-end = 0xFFFFFFFF - addr + 1.

  * "pgpt" (operation_type=INVISIBLE) and "sgpt" (operation_type=RESERVED)
    entries describe the GPT structures themselves and are NEVER written
    as partition-table entries.

  * Sector size is NOT always 512. eMMC regions use 512-byte LBAs; UFS
    regions commonly use 4096-byte LBAs. Pass --sector-size explicitly
    if you know it, otherwise the tool guesses from --storage.

Usage:
    python3 mtk_gpt_tool.py generate --scatter scatter.xml --storage ufs \
        --disk-size 512GB --out-dir ./out

    python3 mtk_gpt_tool.py patch --scatter scatter.xml --storage ufs \
        --pgpt PGPT.img --sgpt SGPT.img --disk-size 512GB --out-dir ./out

    python3 mtk_gpt_tool.py inspect --pgpt PGPT.img [--sector-size 4096]
"""

import argparse
import struct
import sys
import xml.etree.ElementTree as ET
import zlib
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GPT_SIGNATURE = b"EFI PART"
GPT_REVISION = 0x00010000
GPT_HEADER_SIZE = 92
ENTRY_SIZE = 128
NUM_ENTRIES_DEFAULT = 128  # matches observed MTK GPTs (numEntries field can be lower; array is padded)

# --- Defaults so you only need to pass --scatter (or nothing at all) ---
# Override any of these per-invocation with --device / --scatter / --pgpt /
# --sgpt / --disk-size / --storage.
DEFAULT_DEVICE = "a75"
DEFAULT_FIRMWARE_DIR = "bin/firmware/{device}"
DEFAULT_SCATTER_NAME = "MT6789_Android_scatter.xml"
DEFAULT_PGPT_NAME = "PGPT.img"
DEFAULT_SGPT_NAME = "SGPT.img"
DEFAULT_DISK_SIZE_BYTES = 511839305728  # confirmed real device size (~512GB nominal)
DEFAULT_STORAGE = "ufs"

# Type GUID used by MediaTek for every "normal" partition entry (raw 16 bytes,
# already in on-disk mixed-endian order -- copy verbatim, do not re-encode).
MTK_TYPE_GUID = bytes.fromhex("a2a0d0ebe5b9334487c068b6b72699c7")

# Fixed 12-byte suffix MediaTek appends after a 4-byte little-endian partition
# index to build each partition's "unique" GUID.
MTK_GUID_SUFFIX = bytes.fromhex("c23988449bb000cb43c9ccd4")


def mtk_unique_guid(index: int) -> bytes:
    return struct.pack("<I", index) + MTK_GUID_SUFFIX


# ---------------------------------------------------------------------------
# Scatter parsing
# ---------------------------------------------------------------------------

@dataclass
class ScatterPartition:
    name: str
    linear_start_addr: int
    partition_size: int
    operation_type: str
    is_reserved: bool
    region: str
    storage: str
    raw_index: int  # order of appearance in the scatter file (for this storage block)


def parse_scatter(path: str, storage: str) -> list[ScatterPartition]:
    """
    Parse an MTK scatter XML and return partitions belonging to the given
    storage type ('emmc' or 'ufs'), in file order.
    """
    storage = storage.lower()
    want_storage_tag = "HW_STORAGE_EMMC" if storage == "emmc" else "HW_STORAGE_UFS"

    tree = ET.parse(path)
    root = tree.getroot()

    all_matches = []
    idx = 0
    for pi in root.iter("partition_index"):
        def gettext(tag, default=None):
            el = pi.find(tag)
            return el.text.strip() if el is not None and el.text else default

        storage_tag = gettext("storage")
        if storage_tag != want_storage_tag:
            continue

        name = gettext("partition_name")
        linear_start_addr = int(gettext("linear_start_addr", "0x0"), 16)
        partition_size = int(gettext("partition_size", "0x0"), 16)
        operation_type = gettext("operation_type", "")
        is_reserved = gettext("is_reserved", "false") == "true"
        region = gettext("region", "")

        all_matches.append(ScatterPartition(
            name=name,
            linear_start_addr=linear_start_addr,
            partition_size=partition_size,
            operation_type=operation_type,
            is_reserved=is_reserved,
            region=region,
            storage=storage_tag,
            raw_index=idx,
        ))
        idx += 1

    if not all_matches:
        raise ValueError(f"No partitions found for storage={storage!r} in {path}")

    # A storage tag (esp. HW_STORAGE_UFS) can span multiple LUNs/regions
    # (e.g. UFS_LU0 = preloader lun, UFS_LU1 = backup lun, UFS_LU2 = the
    # actual user-data GPT). Only one region contains the "pgpt" entry with
    # operation_type INVISIBLE -- that's the region this GPT describes.
    # Everything on a different region belongs to a different LUN/partition
    # table entirely and must be excluded.
    pgpt_regions = {p.region for p in all_matches
                    if p.name == "pgpt" and p.operation_type.upper() == "INVISIBLE"}
    if len(pgpt_regions) != 1:
        raise ValueError(
            f"Expected exactly one 'pgpt' region for storage={storage!r}, "
            f"found {pgpt_regions or 'none'}. Pass matches manually if this "
            f"scatter file has an unusual layout.")
    target_region = next(iter(pgpt_regions))

    partitions = [p for p in all_matches if p.region == target_region]
    return partitions


# ---------------------------------------------------------------------------
# Layout resolution
# ---------------------------------------------------------------------------

@dataclass
class ResolvedPartition:
    name: str
    first_lba: int
    last_lba: int  # inclusive
    guid_index: int  # stable index used to derive this partition's unique GUID


def resolve_layout(partitions: list[ScatterPartition], disk_size_bytes: int,
                    sector_size: int) -> list[ResolvedPartition]:
    """
    Turn scatter entries into concrete first/last LBA ranges for a disk of
    the given total size.

    Rules:
      - Skip entries that just describe the GPT itself (pgpt/sgpt,
        operation_type in {INVISIBLE, RESERVED} AND name in {pgpt, sgpt}).
      - "Reserved-from-end" entries (addr like 0xFFFFxxxx) are placed
        starting from the end of the disk, in the order they appear
        (closest-to-end first is whichever has the *largest* raw addr,
        i.e. addr closest to 0xFFFFFFFF sits at the very last LBA).
      - Everything else with a normal addr is placed at addr // sector_size,
        for partition_size // sector_size sectors -- EXCEPT an entry marked
        NEEDRESIZE, whose end is instead snapped to right before the
        reserved-from-end region.
    """
    total_lba = disk_size_bytes // sector_size

    # Split into: GPT-self entries (skip, but remember their sizes -- they
    # still occupy physical space), reserved-from-end, normal/needresize
    reserved_tail: list[ScatterPartition] = []
    normal: list[ScatterPartition] = []
    sgpt_size_lba = 0

    for p in partitions:
        if p.name in ("pgpt", "sgpt"):
            if p.name == "sgpt":
                size_lba = p.partition_size // sector_size
                sgpt_size_lba = size_lba if size_lba else 1
            continue  # these represent the GPT structures themselves
        if 0xFFFF0000 <= p.linear_start_addr <= 0xFFFFFFFF:
            reserved_tail.append(p)
        else:
            normal.append(p)

    # The backup GPT (entries table + header) physically lives in the last
    # `sgpt_size_lba` sectors of the disk. Nothing else (incl. flashinfo)
    # may be placed there, so shrink the usable end-of-disk boundary first.
    disk_end_lba = total_lba - sgpt_size_lba

    # Reserved-from-end entries: larger addr == closer to disk end.
    # Sort ascending by addr so we can lay them out back-to-front correctly:
    # the one with addr closest to 0xFFFFFFFF occupies the very last LBAs.
    reserved_tail.sort(key=lambda p: p.linear_start_addr)

    resolved: list[ResolvedPartition] = []

    # Lay out the tail region from the end of the disk backwards.
    cursor = disk_end_lba  # exclusive upper bound, decreases as we place partitions
    tail_entries = []
    for p in reversed(reserved_tail):  # closest-to-end first
        size_lba = p.partition_size // sector_size
        if size_lba == 0:
            size_lba = 1
        first = cursor - size_lba
        last = cursor - 1
        tail_entries.append((p, first, last))
        cursor = first
    tail_entries.reverse()  # restore ascending-address order
    reserved_start_lba = cursor  # first LBA occupied by the reserved tail region

    # Lay out the normal region from the front, honoring given addresses,
    # but let a NEEDRESIZE entry's end snap to reserved_start_lba - 1.
    normal.sort(key=lambda p: p.linear_start_addr)
    for i, p in enumerate(normal):
        first = p.linear_start_addr // sector_size
        if p.operation_type.upper() == "NEEDRESIZE":
            next_first = (normal[i + 1].linear_start_addr // sector_size
                          if i + 1 < len(normal) else reserved_start_lba)
            last = min(next_first, reserved_start_lba) - 1
        else:
            size_lba = p.partition_size // sector_size
            if size_lba == 0:
                size_lba = 1
            last = first + size_lba - 1
        resolved.append(ResolvedPartition(p.name, first, last, p.raw_index))

    for p, first, last in tail_entries:
        resolved.append(ResolvedPartition(p.name, first, last, p.raw_index))

    resolved.sort(key=lambda r: r.first_lba)
    return resolved


# ---------------------------------------------------------------------------
# GPT binary construction
# ---------------------------------------------------------------------------

def build_entry_bytes(name: str, first_lba: int, last_lba: int, guid_index: int) -> bytes:
    type_guid = MTK_TYPE_GUID
    unique_guid = mtk_unique_guid(guid_index)
    attrs = 0
    name_utf16 = name.encode("utf-16-le")
    name_field = name_utf16[:72].ljust(72, b"\x00")
    return (type_guid + unique_guid +
            struct.pack("<QQQ", first_lba, last_lba, attrs) +
            name_field)


def build_entries_table(resolved: list[ResolvedPartition], num_entries: int) -> bytes:
    entries = bytearray(num_entries * ENTRY_SIZE)
    if len(resolved) > num_entries:
        raise ValueError(f"{len(resolved)} partitions but only {num_entries} entry slots")
    for i, r in enumerate(resolved):
        entries[i * ENTRY_SIZE:(i + 1) * ENTRY_SIZE] = build_entry_bytes(
            r.name, r.first_lba, r.last_lba, r.guid_index)
    return bytes(entries)


def build_protective_mbr(total_lba: int, sector_size: int) -> bytes:
    mbr = bytearray(sector_size)
    part_lba_count = min(total_lba - 1, 0xFFFFFFFF)
    # Partition entry: status=0x00, CHS start=0x000200 (dummy), type=0xEE,
    # CHS end=dummy, start LBA=1, size in LBA=part_lba_count
    entry = struct.pack("<B3sB3sII", 0x00, b"\x00\x00\x00", 0xEE,
                         b"\x00\x00\x00", 1, part_lba_count)
    mbr[0x1BE:0x1BE + len(entry)] = entry
    mbr[0x1FE:0x1FE + 2] = b"\x55\xaa"
    return bytes(mbr)


def build_gpt_header(*, my_lba: int, alt_lba: int, first_usable: int, last_usable: int,
                      disk_guid: bytes, entries_lba: int, num_entries: int,
                      entries_crc: int, sector_size: int) -> bytes:
    hdr = bytearray(sector_size)
    hdr[0:8] = GPT_SIGNATURE
    struct.pack_into("<I", hdr, 8, GPT_REVISION)
    struct.pack_into("<I", hdr, 12, GPT_HEADER_SIZE)
    # CRC32 field (offset 16) left as 0 for now, filled after
    struct.pack_into("<I", hdr, 20, 0)  # reserved
    struct.pack_into("<Q", hdr, 24, my_lba)
    struct.pack_into("<Q", hdr, 32, alt_lba)
    struct.pack_into("<Q", hdr, 40, first_usable)
    struct.pack_into("<Q", hdr, 48, last_usable)
    hdr[56:72] = disk_guid
    struct.pack_into("<Q", hdr, 72, entries_lba)
    struct.pack_into("<I", hdr, 80, num_entries)
    struct.pack_into("<I", hdr, 84, ENTRY_SIZE)
    struct.pack_into("<I", hdr, 88, entries_crc)

    header_crc = zlib.crc32(bytes(hdr[0:GPT_HEADER_SIZE])) & 0xFFFFFFFF
    struct.pack_into("<I", hdr, 16, header_crc)
    return bytes(hdr)


def make_disk_guid(existing: bytes | None) -> bytes:
    if existing:
        return existing
    import uuid
    return uuid.uuid4().bytes_le


def assemble_images(entries_bytes: bytes, disk_size_bytes: int, sector_size: int,
                     num_entries: int = NUM_ENTRIES_DEFAULT,
                     disk_guid: bytes | None = None, image_block_bytes: int = 0x8000,
                     pgpt_region_lba: int | None = None, sgpt_region_lba: int | None = None,
                     first_usable_override: int | None = None):
    """
    Build (pgpt_bytes, sgpt_bytes) from an already-constructed entries table.
    Used by both `generate` (fresh entries) and `patch` (entries with some
    GUIDs preserved from an existing image).

    pgpt_region_lba / sgpt_region_lba: total sectors reserved for the front
    and back GPT structures respectively. If omitted, sized from the entries
    array itself (spec-minimal, but may not match a specific device's
    convention -- real MTK devices size these off the pgpt/sgpt scatter
    entries, which are usually a fixed 32KiB regardless of entry count).
    """
    total_lba = disk_size_bytes // sector_size
    entries_sectors = -(-(num_entries * ENTRY_SIZE) // sector_size)  # ceil div

    my_lba = 1
    entries_lba_primary = 2
    alt_lba = total_lba - 1
    front_reserved = pgpt_region_lba if pgpt_region_lba is not None else (2 + entries_sectors)
    back_reserved = sgpt_region_lba if sgpt_region_lba is not None else (entries_sectors + 1)
    first_usable = first_usable_override if first_usable_override is not None else front_reserved
    last_usable = alt_lba - back_reserved + 1 - 1  # last sector NOT part of back-reserved region

    entries_crc = zlib.crc32(entries_bytes) & 0xFFFFFFFF
    guid = make_disk_guid(disk_guid)

    primary_header = build_gpt_header(
        my_lba=my_lba, alt_lba=alt_lba, first_usable=first_usable, last_usable=last_usable,
        disk_guid=guid, entries_lba=entries_lba_primary, num_entries=num_entries,
        entries_crc=entries_crc, sector_size=sector_size)

    backup_entries_lba = total_lba - back_reserved
    backup_header = build_gpt_header(
        my_lba=alt_lba, alt_lba=my_lba, first_usable=first_usable, last_usable=last_usable,
        disk_guid=guid, entries_lba=backup_entries_lba, num_entries=num_entries,
        entries_crc=entries_crc, sector_size=sector_size)

    mbr = build_protective_mbr(total_lba, sector_size)

    pgpt = bytearray(mbr + primary_header + entries_bytes)
    if len(pgpt) < image_block_bytes:
        pgpt.extend(b"\x00" * (image_block_bytes - len(pgpt)))

    sgpt = bytearray(entries_bytes)
    header_slot = image_block_bytes - sector_size
    if len(sgpt) < header_slot:
        sgpt.extend(b"\x00" * (header_slot - len(sgpt)))
    sgpt = sgpt[:header_slot] + bytearray(backup_header)
    if len(sgpt) < image_block_bytes:
        sgpt.extend(b"\x00" * (image_block_bytes - len(sgpt)))

    return bytes(pgpt), bytes(sgpt)


def get_reserved_region_sizes(partitions: list[ScatterPartition], sector_size: int):
    """Return (pgpt_region_lba, sgpt_region_lba) from the scatter's own pgpt/sgpt entries."""
    pgpt_lba = sgpt_lba = None
    for p in partitions:
        if p.name == "pgpt":
            pgpt_lba = max(1, p.partition_size // sector_size)
        elif p.name == "sgpt":
            sgpt_lba = max(1, p.partition_size // sector_size)
    return pgpt_lba, sgpt_lba


def generate_gpt_images(resolved: list[ResolvedPartition], disk_size_bytes: int,
                         sector_size: int, num_entries: int = NUM_ENTRIES_DEFAULT,
                         disk_guid: bytes | None = None, image_block_bytes: int = 0x8000,
                         pgpt_region_lba: int | None = None, sgpt_region_lba: int | None = None,
                         first_usable_override: int | None = None):
    """Build a fresh entries table (new GUIDs) and assemble PGPT/SGPT from it."""
    entries_bytes = build_entries_table(resolved, num_entries)
    return assemble_images(entries_bytes, disk_size_bytes, sector_size,
                            num_entries=num_entries, disk_guid=disk_guid,
                            image_block_bytes=image_block_bytes,
                            first_usable_override=first_usable_override,
                            pgpt_region_lba=pgpt_region_lba, sgpt_region_lba=sgpt_region_lba)


# ---------------------------------------------------------------------------
# Reading existing GPT images (for `patch` mode / `inspect`)
# ---------------------------------------------------------------------------

def read_existing_entries(pgpt_path: str, sector_size: int):
    """
    Returns dict: name -> (unique_guid_bytes, first_lba, last_lba)
    by reading a PGPT.img (mbr + header @ sector1 + entries @ sector2+).
    """
    data = Path(pgpt_path).read_bytes()
    header_off = sector_size
    hdr = data[header_off:header_off + GPT_HEADER_SIZE]
    if hdr[0:8] != GPT_SIGNATURE:
        raise ValueError("No 'EFI PART' signature found at expected header offset; "
                          "try a different --sector-size")
    entries_lba = struct.unpack_from("<Q", hdr, 72)[0]
    num_entries = struct.unpack_from("<I", hdr, 80)[0]
    entries_off = entries_lba * sector_size

    result = {}
    for i in range(num_entries):
        off = entries_off + i * ENTRY_SIZE
        e = data[off:off + ENTRY_SIZE]
        if len(e) < ENTRY_SIZE or e[0:16] == b"\x00" * 16:
            continue
        unique_guid = e[16:32]
        first_lba, last_lba = struct.unpack_from("<QQ", e, 32)
        name = e[56:56 + 72].decode("utf-16-le").rstrip("\x00")
        result[name] = (unique_guid, first_lba, last_lba)
    return result, hdr


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def to_scatter(template_path: str, storage: str, pgpt_path: str, sector_size: int) -> ET.ElementTree:
    """
    Rewrite a template scatter XML's addr/size fields (for the region matching
    `storage`) to reflect the real, concrete layout found in an actual GPT
    dump. Partitions in the template keep their operation_type/type/etc as-is
    (so NEEDRESIZE stays NEEDRESIZE, RESERVED stays RESERVED) -- only
    linear_start_addr/physical_start_addr get refreshed, and partition_size
    is refreshed for ordinary ("normal") partitions only, since NEEDRESIZE
    and RESERVED sizes are placeholders/fixed-by-convention, not literal.

    Partitions found in the real GPT but absent from the template (i.e. ones
    you added yourself, like custom "linux"/"backup" partitions) are inserted
    as new <partition_index> blocks, cloned from the template's "userdata"
    entry as a reasonable starting point -- review these manually, since
    file_name/type/operation_type are just a best guess.
    """
    want_storage_tag = "HW_STORAGE_EMMC" if storage.lower() == "emmc" else "HW_STORAGE_UFS"
    tree = ET.parse(template_path)
    root = tree.getroot()

    all_pi = list(root.iter("partition_index"))

    def field(pi, tag, default=None):
        el = pi.find(tag)
        return el.text.strip() if el is not None and el.text else default

    pgpt_regions = {field(pi, "region") for pi in all_pi
                    if field(pi, "storage") == want_storage_tag
                    and field(pi, "partition_name") == "pgpt"
                    and field(pi, "operation_type", "").upper() == "INVISIBLE"}
    if len(pgpt_regions) != 1:
        raise ValueError(f"Could not uniquely identify target region for storage={storage!r}")
    target_region = next(iter(pgpt_regions))

    def in_target(pi):
        return field(pi, "storage") == want_storage_tag and field(pi, "region") == target_region

    section_pis = [pi for pi in all_pi if in_target(pi)]

    real_entries, _hdr = read_existing_entries(pgpt_path, sector_size)

    template_names = {field(pi, "partition_name") for pi in section_pis}

    # --- Update existing entries ---
    for pi in section_pis:
        name = field(pi, "partition_name")
        if name in ("pgpt", "sgpt"):
            continue
        if name not in real_entries:
            continue  # partition existed in template but not in this real GPT; leave as-is
        _guid, first, last = real_entries[name]
        op = field(pi, "operation_type", "").upper()

        if op == "RESERVED":
            continue  # sentinel-addressed (0xFFFFxxxx); location is computed
                       # dynamically at flash time, never a literal address

        addr = first * sector_size
        size = (last - first + 1) * sector_size

        addr_hex = f"0x{addr:X}"
        pi.find("linear_start_addr").text = addr_hex
        pi.find("physical_start_addr").text = addr_hex

        if op != "NEEDRESIZE":
            pi.find("partition_size").text = f"0x{size:X}"

    # --- Insert brand-new partitions (present on-device, absent from template) ---
    # Find the container element these partition_index nodes live under, and
    # the "userdata" node to use as a structural clone source + insertion anchor.
    parent_map = {child: parent for parent in root.iter() for child in parent}
    userdata_pi = next((pi for pi in section_pis if field(pi, "partition_name") == "userdata"), None)
    if userdata_pi is None:
        raise ValueError("Template has no 'userdata' entry in the target region; "
                          "cannot use it as a clone source for new partitions.")
    container = parent_map[userdata_pi]

    existing_indices = []
    for pi in all_pi:
        m = pi.get("name", "")
        if m.startswith("SYS") and m[3:].isdigit():
            existing_indices.append(int(m[3:]))
    next_index = (max(existing_indices) + 1) if existing_indices else 0

    # Real partitions in on-device physical order, so we can find where to
    # splice each new one in (right after its physical predecessor).
    ordered_real = sorted(real_entries.items(), key=lambda kv: kv[1][1])
    new_names_in_order = [n for n, _ in ordered_real if n not in template_names]

    for name in new_names_in_order:
        _guid, first, last = real_entries[name]
        addr = first * sector_size
        size = (last - first + 1) * sector_size

        new_pi = ET.fromstring(ET.tostring(userdata_pi))  # deep clone
        new_pi.set("name", f"SYS{next_index}")
        next_index += 1
        new_pi.find("partition_name").text = name
        new_pi.find("file_name").text = f"{name}.img"
        new_pi.find("linear_start_addr").text = f"0x{addr:X}"
        new_pi.find("physical_start_addr").text = f"0x{addr:X}"
        new_pi.find("partition_size").text = f"0x{size:X}"
        new_pi.find("operation_type").text = "UPDATE"  # best guess; review manually

        # Find the physical predecessor already in the tree to insert after
        pred_name = None
        for n, (_g, f2, l2) in ordered_real:
            if l2 < first and (pred_name is None or f2 > real_entries[pred_name][1]):
                pred_name = n
        pred_pi = next((pi for pi in list(container) if
                         pi.tag == "partition_index" and field(pi, "partition_name") == pred_name),
                        userdata_pi)
        idx = list(container).index(pred_pi)
        container.insert(idx + 1, new_pi)

    try:
        ET.indent(tree, space="  ")
    except AttributeError:
        pass  # Python < 3.9: no auto-indent, still valid XML either way

    return tree


def parse_size(s: str) -> int:
    s = s.strip().upper()
    mult = 1
    for suffix, m in (("TIB", 1024**4), ("GIB", 1024**3), ("MIB", 1024**2),
                      ("TB", 10**12), ("GB", 10**9), ("MB", 10**6),
                      ("T", 1024**4), ("G", 1024**3), ("M", 1024**2)):
        if s.endswith(suffix):
            mult = m
            s = s[: -len(suffix)]
            break
    return int(float(s) * mult)


def cmd_to_scatter(args):
    args = resolve_defaults(args)
    sector_size = args.sector_size or (4096 if args.storage.lower() == "ufs" else 512)
    tree = to_scatter(args.scatter, args.storage, args.pgpt, sector_size)
    tree.write(args.out, encoding="UTF-8", xml_declaration=True)
    print(f"Wrote reconstructed scatter to {args.out}")


def _find_fw_dir(device: str) -> str:
    """Return the firmware directory for *device*, trying a case-insensitive
    match against existing subdirectories of ``bin/firmware/`` if the exact
    name doesn't exist."""
    exact = Path(DEFAULT_FIRMWARE_DIR.format(device=device))
    if exact.is_dir():
        return str(exact)

    base = exact.parent
    if not base.is_dir():
        return str(exact)

    lower = device.lower()
    for entry in base.iterdir():
        if entry.is_dir() and entry.name.lower() == lower:
            return str(entry)

    return str(exact)


def resolve_defaults(args):
    """
    Fill in any omitted --scatter/--pgpt/--sgpt/--disk-size/--storage from
    the --device firmware directory + built-in defaults, so you only need
    to pass what's actually different from your usual setup.

    Device name matching is case-insensitive with respect to the filesystem:
    if ``bin/firmware/<device>/`` doesn't exist, we scan for a subdirectory
    whose name matches case-insensitively.
    """
    device = getattr(args, "device", None) or DEFAULT_DEVICE
    fw_dir = _find_fw_dir(device)

    if getattr(args, "storage", None) is None:
        args.storage = DEFAULT_STORAGE
    if getattr(args, "scatter", None) is None:
        args.scatter = str(Path(fw_dir) / DEFAULT_SCATTER_NAME)
    if getattr(args, "pgpt", None) is None and hasattr(args, "pgpt"):
        args.pgpt = str(Path(fw_dir) / DEFAULT_PGPT_NAME)
    if getattr(args, "sgpt", None) is None and hasattr(args, "sgpt"):
        args.sgpt = str(Path(fw_dir) / DEFAULT_SGPT_NAME)
    if getattr(args, "disk_size", None) is None and hasattr(args, "disk_size"):
        args.disk_size = str(DEFAULT_DISK_SIZE_BYTES)

    for attr in ("scatter", "pgpt", "sgpt"):
        val = getattr(args, attr, None)
        if val is not None and not Path(val).exists():
            print(f"Warning: --{attr} default resolved to {val!r}, but that path "
                  f"doesn't exist. Pass --{attr} explicitly or check --device.",
                  file=sys.stderr)
    return args


def cmd_generate(args):
    args = resolve_defaults(args)
    partitions = parse_scatter(args.scatter, args.storage)
    sector_size = args.sector_size or (4096 if args.storage.lower() == "ufs" else 512)
    disk_bytes = parse_size(args.disk_size)
    resolved = resolve_layout(partitions, disk_bytes, sector_size)
    num_entries = args.num_entries or len(resolved)
    pgpt_region_lba, sgpt_region_lba = get_reserved_region_sizes(partitions, sector_size)

    pgpt, sgpt = generate_gpt_images(resolved, disk_bytes, sector_size, num_entries=num_entries,
                                      pgpt_region_lba=pgpt_region_lba, sgpt_region_lba=sgpt_region_lba,
                                      first_usable_override=args.first_usable_lba)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    pgpt_name = f"PGPT{args.output_suffix}.img"
    sgpt_name = f"SGPT{args.output_suffix}.img"
    (out_dir / pgpt_name).write_bytes(pgpt)
    (out_dir / sgpt_name).write_bytes(sgpt)

    print(f"Sector size used: {sector_size} bytes")
    print(f"Disk size: {disk_bytes} bytes ({disk_bytes/1e9:.2f} GB)")
    print(f"Wrote {len(resolved)} partitions to {out_dir}/{pgpt_name} and {sgpt_name}")
    print_layout(resolved, sector_size)


def cmd_patch(args):
    args = resolve_defaults(args)
    partitions = parse_scatter(args.scatter, args.storage)
    sector_size = args.sector_size or (4096 if args.storage.lower() == "ufs" else 512)
    disk_bytes = parse_size(args.disk_size)
    resolved = resolve_layout(partitions, disk_bytes, sector_size)

    existing, existing_hdr = read_existing_entries(args.pgpt, sector_size)
    num_entries = args.num_entries or len(resolved)

    # Reuse existing unique GUIDs where the partition name already existed;
    # partitions new to this scatter file get a freshly derived GUID.
    name_to_existing_guid = {name: g for name, (g, _f, _l) in existing.items()}

    entries = bytearray(build_entries_table(resolved, num_entries))
    for i, r in enumerate(resolved):
        if r.name in name_to_existing_guid:
            off = i * ENTRY_SIZE + 16
            entries[off:off + 16] = name_to_existing_guid[r.name]

    # Preserve the original disk GUID too, so this reads as an update to the
    # same disk rather than a brand new one.
    existing_disk_guid = existing_hdr[56:72]
    pgpt_region_lba, sgpt_region_lba = get_reserved_region_sizes(partitions, sector_size)

    pgpt, sgpt = assemble_images(bytes(entries), disk_bytes, sector_size,
                                  num_entries=num_entries, disk_guid=existing_disk_guid,
                                  pgpt_region_lba=pgpt_region_lba, sgpt_region_lba=sgpt_region_lba,
                                  first_usable_override=args.first_usable_lba)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    pgpt_name = f"PGPT{args.output_suffix}.img"
    sgpt_name = f"SGPT{args.output_suffix}.img"
    (out_dir / pgpt_name).write_bytes(pgpt)
    (out_dir / sgpt_name).write_bytes(sgpt)
    print(f"Patched layout written to {out_dir}/{pgpt_name} and {sgpt_name}")
    print(f"Preserved unique GUIDs for {len(name_to_existing_guid)} existing partitions")
    print_layout(resolved, sector_size)


def cmd_disable_gz(args):
    """
    Disable GenieZone by patching gz_a/gz_b GPT entries so their LBAs point
    beyond the device capacity. The partition names stay in the table (passes
    preloader existence checks) but any storage read will fail, triggering the
    internal NoGZ flag.
    """
    args = resolve_defaults(args)
    sector_size = args.sector_size or (4096 if args.storage.lower() == "ufs" else 512)
    pgpt_data = Path(args.pgpt).read_bytes()

    if pgpt_data[sector_size:sector_size + 8] != GPT_SIGNATURE:
        raise ValueError("No 'EFI PART' signature found; try adjusting --sector-size")
    hdr = pgpt_data[sector_size:sector_size + GPT_HEADER_SIZE]

    total_lba = struct.unpack_from("<Q", hdr, 32)[0] + 1
    num_entries = struct.unpack_from("<I", hdr, 80)[0]
    entry_size = struct.unpack_from("<I", hdr, 84)[0]
    entries_lba = struct.unpack_from("<Q", hdr, 72)[0]
    entries_off = entries_lba * sector_size
    data_len = entries_off + num_entries * entry_size

    if data_len > len(pgpt_data):
        raise ValueError("PGPT image is truncated or sector size is wrong")

    gz_names = {"gz_a", "gz_b", "gz1", "gz2"}
    gz_found = []
    modified_any = False
    entries = bytearray(pgpt_data[entries_off:data_len])

    for i in range(num_entries):
        off = i * entry_size
        e = entries[off:off + entry_size]
        if len(e) < entry_size or e[0:16] == b"\x00" * 16:
            continue
        name = e[56:56 + 72].decode("utf-16-le").rstrip("\x00")
        if name not in gz_names:
            continue
        first_lba = struct.unpack_from("<Q", e, 32)[0]
        last_lba = struct.unpack_from("<Q", e, 40)[0]
        gz_found.append((name, first_lba, last_lba))

        if first_lba >= total_lba or last_lba >= total_lba:
            print(f"  {name}: already disabled (LBA {first_lba:#x} >= {total_lba:#x})")
            continue

        new_first = total_lba
        new_last = total_lba + (last_lba - first_lba)
        struct.pack_into("<Q", entries, off + 32, new_first)
        struct.pack_into("<Q", entries, off + 40, new_last)
        print(f"  {name}: {first_lba:#x}..{last_lba:#x} -> {new_first:#x}..{new_last:#x}")
        modified_any = True

    if not gz_found:
        print("No GenieZone partitions (gz_a, gz_b, gz1, gz2) found in GPT")
        sys.exit(1)

    if not modified_any:
        print("\nAll gz partitions already have LBAs beyond disk capacity. Nothing to do.")
        sys.exit(0)

    entries_bytes = bytes(entries)

    my_lba = struct.unpack_from("<Q", hdr, 24)[0]
    alt_lba = struct.unpack_from("<Q", hdr, 32)[0]
    first_usable = struct.unpack_from("<Q", hdr, 40)[0]
    last_usable = struct.unpack_from("<Q", hdr, 48)[0]
    disk_guid = hdr[56:72]

    back_reserved = alt_lba - last_usable

    pgpt_bytes, sgpt_bytes = assemble_images(
        entries_bytes, total_lba * sector_size, sector_size,
        num_entries=num_entries, disk_guid=disk_guid,
        first_usable_override=first_usable,
        sgpt_region_lba=back_reserved,
        image_block_bytes=0x8000)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "PGPT_gz_disabled.img").write_bytes(pgpt_bytes)
    (out_dir / "SGPT_gz_disabled.img").write_bytes(sgpt_bytes)
    print(f"\nWrote {out_dir}/PGPT_gz_disabled.img and SGPT_gz_disabled.img")
    print(f"Flash both images to disable GenieZone on next boot.")


def cmd_inspect(args):
    args = resolve_defaults(args)
    sector_size = args.sector_size or (4096 if args.storage.lower() == "ufs" else 512)
    existing, hdr = read_existing_entries(args.pgpt, sector_size)
    total_lba = struct.unpack_from("<Q", hdr, 32)[0] + 1
    print(f"Sector size: {sector_size}  Total LBAs: {total_lba}  "
          f"Disk size: {total_lba*sector_size/1e9:.2f} GB")
    for name, (guid, first, last) in sorted(existing.items(), key=lambda kv: kv[1][1]):
        size = last - first + 1
        print(f"{name:20s} first={first:12d} last={last:12d} "
              f"size_lba={size:10d} size={size*sector_size/1024**2:10.2f} MiB")


def print_layout(resolved, sector_size):
    print(f"{'name':20s}{'first_lba':>14s}{'last_lba':>14s}{'size':>14s}")
    for r in resolved:
        size = r.last_lba - r.first_lba + 1
        print(f"{r.name:20s}{r.first_lba:14d}{r.last_lba:14d}"
              f"{size*sector_size/1024**2:12.2f}MiB")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="Build fresh PGPT.img/SGPT.img from a scatter file")
    g.add_argument("--device", default=None,
                    help=f"Firmware folder name under bin/firmware/. Default: {DEFAULT_DEVICE!r}")
    g.add_argument("--scatter", default=None,
                    help="Default: bin/firmware/{device}/MT6789_Android_scatter.xml")
    g.add_argument("--storage", choices=["emmc", "ufs"], default=None,
                    help=f"Default: {DEFAULT_STORAGE!r}")
    g.add_argument("--disk-size", default=None,
                    help=f"e.g. 512GB, 476GiB, 511834865664. Default: {DEFAULT_DISK_SIZE_BYTES}")
    g.add_argument("--sector-size", type=int, default=None)
    g.add_argument("--num-entries", type=int, default=None,
                    help="GPT entry slot count. Default: exact partition count "
                         "(matches how real MTK devices size it). Use 128 for "
                         "spec-typical GPTs.")
    g.add_argument("--first-usable-lba", type=int, default=None,
                    help="Override firstUsableLBA header field. Some vendor tools "
                         "hardcode 34 (the classic 512-byte-sector GPT constant) "
                         "even on 4096-byte-sector disks; set this to match exactly.")
    g.add_argument("--output-suffix", default="",
                    help="Suffix before .img, e.g. _gen → PGPT_gen.img")
    g.add_argument("--out-dir", default="./out")
    g.set_defaults(func=cmd_generate)

    p = sub.add_parser("patch", help="Update PGPT.img/SGPT.img layout from a scatter file, "
                                      "preserving existing unique GUIDs where possible")
    p.add_argument("--device", default=None)
    p.add_argument("--scatter", default=None,
                    help="Default: bin/firmware/{device}/MT6789_Android_scatter.xml")
    p.add_argument("--storage", choices=["emmc", "ufs"], default=None)
    p.add_argument("--pgpt", default=None, help="Default: bin/firmware/{device}/PGPT.img")
    p.add_argument("--sgpt", default=None, help="Default: bin/firmware/{device}/SGPT.img")
    p.add_argument("--disk-size", default=None)
    p.add_argument("--sector-size", type=int, default=None)
    p.add_argument("--num-entries", type=int, default=None)
    p.add_argument("--first-usable-lba", type=int, default=None)
    p.add_argument("--output-suffix", default="",
                    help="Suffix before .img, e.g. _patch → PGPT_patch.img")
    p.add_argument("--out-dir", default="./out")
    p.set_defaults(func=cmd_patch)

    i = sub.add_parser("inspect", help="Print the layout found in an existing PGPT.img")
    i.add_argument("--device", default=None)
    i.add_argument("--pgpt", default=None, help="Default: bin/firmware/{device}/PGPT.img")
    i.add_argument("--storage", choices=["emmc", "ufs"], default=None)
    i.add_argument("--sector-size", type=int, default=None)
    i.set_defaults(func=cmd_inspect)

    d = sub.add_parser("disable-gz", help="Disable GenieZone: point gz_a/gz_b LBAs beyond disk capacity")
    d.add_argument("--device", default=None)
    d.add_argument("--pgpt", default=None, help="Default: bin/firmware/{device}/PGPT.img")
    d.add_argument("--storage", choices=["emmc", "ufs"], default=None)
    d.add_argument("--sector-size", type=int, default=None)
    d.add_argument("--out-dir", default="./out")
    d.set_defaults(func=cmd_disable_gz)

    t = sub.add_parser("to-scatter", help="Reconstruct a scatter XML from a real PGPT.img, "
                                           "using another scatter file as a field template")
    t.add_argument("--device", default=None)
    t.add_argument("--scatter", default=None,
                    help="Template scatter XML. Default: bin/firmware/{device}/MT6789_Android_scatter.xml")
    t.add_argument("--storage", choices=["emmc", "ufs"], default=None)
    t.add_argument("--pgpt", default=None,
                    help="Real device PGPT.img to read the layout from. Default: bin/firmware/{device}/PGPT.img")
    t.add_argument("--sector-size", type=int, default=None)
    t.add_argument("--out", default="./reconstructed_scatter.xml")
    t.set_defaults(func=cmd_to_scatter)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
