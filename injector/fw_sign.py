"""
fw_sign.py — shared MTK GFH/cert2 re-sign helper for fenrir firmware patchers.

Wraps liblk + lkpatcher.cert_bypass so mcupm_devices.py, sspm_devices.py,
pi_img_devices.py and patch_firmware.py all re-sign modified partition images
the same way ("cert every modification").

EXPERIMENTAL: cert_bypass forges a cert2 that MTK's parser accepts structurally
(prepend a [0] hash-override ahead of the untouched original), but ON-DEVICE
acceptance at boot is UNTESTED — see PI_IMG_KRAKEN_NOTES.md §4c/§6d. On an
unlocked device that does not enforce the partition signature, an unsigned raw
edit already boots (proven for mcupm); signing is for consistency / locked units.

Requires the liblk venv:  /opt/src/fenrir/.venv/bin/python3
Override the lkpatcher location with env LKPATCHER_PATH if needed.
"""
import os
import sys

LKPATCHER_PATH = os.environ.get('LKPATCHER_PATH', '/opt/src/lkpatcher')
if LKPATCHER_PATH not in sys.path:
    sys.path.insert(0, LKPATCHER_PATH)


def have_liblk() -> bool:
    """True if liblk + lkpatcher.cert_bypass are importable in this interpreter."""
    try:
        import liblk.image                 # noqa: F401
        import lkpatcher.cert_bypass        # noqa: F401
        return True
    except Exception:
        return False


def require_liblk():
    if not have_liblk():
        sys.exit(
            "ERROR: liblk/lkpatcher not importable — run under the venv:\n"
            "  /opt/src/fenrir/.venv/bin/python3 <tool> ...\n"
            "  (or set LKPATCHER_PATH / pip install liblk in the venv)")


def sign_image(path: str, out_path: str = None, wrap: bool = False) -> str:
    """Load a GFH partition image whose payload was already edited on disk,
    forge a fresh cert2, and save. In-place when out_path is None.

    liblk parses the GFH structure (no RSA verification on load), so an image
    with a now-stale cert2 loads fine; cert_bypass then replaces cert2 for the
    current payload. Returns the written path.
    """
    require_liblk()
    from liblk.image import LkImage
    from lkpatcher.cert_bypass import apply_cert_bypass, CertBypassMode
    out_path = out_path or path
    img = LkImage(path)
    mode = CertBypassMode.WRAP if wrap else CertBypassMode.OVERRIDE
    apply_cert_bypass(img, mode=mode)
    img.save(out_path)
    return out_path
