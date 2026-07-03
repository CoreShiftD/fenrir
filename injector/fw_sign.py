"""
fw_sign.py - shared MTK GFH/cert2 re-sign helper.

Uses fenrir's local liblk-based cert_bypass implementation so bootloader and
firmware images are signed through the same path as the upstream injector.
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


def have_liblk() -> bool:
    """True if liblk and fenrir's local cert_bypass are importable."""
    try:
        import liblk.image  # noqa: F401
        import cert_bypass  # noqa: F401
        return True
    except Exception:
        return False


def require_liblk() -> None:
    if not have_liblk():
        sys.exit(
            "ERROR: liblk/cert_bypass not importable - install requirements:\n"
            "  pip install -r requirements.txt\n"
            "or run under the repo venv:\n"
            "  /opt/src/fenrir/.venv/bin/python3 <tool> ..."
        )


def _compute_trailing(img) -> bytes:
    region_end = 0
    for partition in img.partitions.values():
        region_end = max(region_end, partition.end_offset)
        for cert in partition.certs:
            region_end = max(region_end, cert.end_offset)
    return bytes(img.contents[region_end:])


def sign_image(path: str, out_path: Optional[str] = None, wrap: bool = False) -> str:
    """Re-sign modified GFH partitions in an LK/GFH image.

    Only partitions whose cert2 no longer matches their current contents are
    touched. Returns the written path.
    """
    require_liblk()
    from liblk.image import LkImage
    from cert_bypass import apply_cert_bypass

    out_path = out_path or path
    img = LkImage(path)
    trailing = _compute_trailing(img)
    signed = apply_cert_bypass(img, trailing, wrap=wrap)

    if not signed:
        img._rebuild_contents()
        img.contents = bytearray(img.contents) + bytearray(trailing)

    with open(out_path, 'wb') as f:
        f.write(bytes(img.contents))
    return out_path


def main() -> int:
    parser = argparse.ArgumentParser(description='Re-sign modified GFH/cert2 images')
    parser.add_argument('image', help='Input image path')
    parser.add_argument('output', nargs='?', help='Output path (default: in-place)')
    parser.add_argument('--wrap', action='store_true', help='Use WRAP cert2 mode')
    args = parser.parse_args()

    out = sign_image(args.image, args.output, wrap=args.wrap)
    print('Signed: %s' % out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
