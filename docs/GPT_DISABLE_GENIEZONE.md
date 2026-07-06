# GPT-based GenieZone disable — LBA redirection approach

**Goal:** disable GenieZone (TEE) by modifying the GPT partition table so
`gz_a`/`gz_b` LBAs point beyond the physical disk capacity.

Original discovery and approach: [jsbsbxjxh66/mtk-soc-disable-geniezone](https://github.com/jsbsbxjxh66/mtk-soc-disable-geniezone)

## Problem

Direct preloader patching (see `PRELOADER_GZ_PATCH.md`) invalidates the RSA
signature — fine in DA mode but blocks cold boot on locked devices. A
GPT-only approach avoids touching the signed boot chain entirely.

## Solution

Point the `gz_a`/`gz_b` GPT partition entries at LBAs beyond `lastUsableLBA`.
The partition names remain in the table (passing preloader existence checks),
but any storage read of those LBAs fails, which triggers the internal NoGZ
flag instead of the panic path.

### How it works

```
Stock GPT:
  gz_a:  LBA 0x123456..0x124567  ← valid range
  gz_b:  LBA 0x124568..0x125679  ← valid range

Patched GPT:
  gz_a:  LBA 0x1000000..0x1010111  ← beyond total_lba
  gz_b:  LBA 0x1010112..0x1020223  ← beyond total_lba
```

The preloader FSM finds the partitions (names match), attempts to load from
the given LBAs, the read fails, and the boot chain sets the GZ-disabled flag
without calling `panic()`.

## Tool

`injector/mtk_gpt_tool.py disable-gz` reads the existing PGPT.img, rewrites
the `gz_a`/`gz_b` (and `gz1`/`gz2`) entry LBAs, then reassembles both PGPT
and SGPT images with correct CRCs and disk GUID preservation.

```bash
python3 mtk_gpt_tool.py disable-gz \
    --device a75 \
    --pgpt bin/firmware/a75/PGPT.img \
    --storage ufs \
    --out-dir ./out
```

Output: `PGPT_gz_disabled.img` + `SGPT_gz_disabled.img` — flash both.

## Integration

Set `disable_geniezone: true` under the `gpt` key in `devices.py`:

```python
'gpt': {
    'storage': 'ufs',
    'disk_size': 511839305728,
    'sector_size': 4096,
    'disable_geniezone': True,
},
```

The firmware pipeline (`patch_firmware.py`) detects this flag and runs
`mtk_gpt_tool.py disable-gz` automatically during `build.sh --firmware`.

## Comparison

| Aspect | GPT disable (this doc) | Preloader patch (`PRELOADER_GZ_PATCH.md`) |
|--------|------------------------|-------------------------------------------|
| What it touches | Partition table (PGPT/SGPT) | Preloader binary |
| RSA signature | Preserved — GPT is unsigned | Invalidated |
| Cold boot safety | Safe on locked devices | Requires unlocked BL |
| Reversibility | Reflash stock GPT | Reflash stock preloader |
| Side effects | None visible | GZ/TEE unavailable |

## Credits

This approach is based on the original work by
[jsbsbxjxh66/mtk-soc-disable-geniezone](https://github.com/jsbsbxjxh66/mtk-soc-disable-geniezone),
which first demonstrated that redirecting gz partition LBAs beyond disk
capacity safely disables GenieZone on MediaTek SoCs.
