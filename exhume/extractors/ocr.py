"""OCR of images to extract credentials from screenshots."""
from __future__ import annotations

from functools import lru_cache


@lru_cache(maxsize=1)
def _ocr_ready() -> bool:
    try:
        import pytesseract  # noqa: F401
        from PIL import Image  # noqa: F401
    except ImportError:
        return False
    # Confirm the tesseract binary is actually callable.
    try:
        import pytesseract
        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


def tesseract_available() -> bool:
    """Whether OCR will actually work: pytesseract/Pillow import fine AND the system
    ``tesseract`` binary itself is callable. pip installs the former automatically; the
    latter is a native program pip can't install, so this can be False even when every
    Python package is present — the one case the generic "optional extras" check misses."""
    return _ocr_ready()


def ocr_image(path: str) -> tuple[str | None, str]:
    """Return (text, method) or (None, reason). Needs pillow + pytesseract + tesseract."""
    if not _ocr_ready():
        return None, "no-ocr"
    try:
        import pytesseract
        from PIL import Image
        return pytesseract.image_to_string(Image.open(path)), "ocr"
    except Exception as exc:
        return None, f"ocr-error:{type(exc).__name__}"
