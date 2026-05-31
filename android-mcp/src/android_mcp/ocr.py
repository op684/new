"""Optional OCR fallback: read text from a screenshot's pixels.

The UI-tree readers (``screen_text``/``screen_elements``/``ui_tree``) only see
what apps expose to accessibility. Canvas/game-engine UIs, some Flutter views,
DRM video, and ``FLAG_SECURE`` screens come back empty. OCR is the last resort:
rasterise the screen and recognise the text directly, returning each word with
its on-screen box so the model can even tap OCR'd words.

Dependencies are optional so the core server runs without them:

    pip install "android-mcp[ocr]"     # -> pytesseract + pillow
    # and the tesseract engine itself, e.g. `apt install tesseract-ocr`

``available()`` reports whether everything needed is importable + installed.
"""

from __future__ import annotations

import io
from dataclasses import dataclass


@dataclass
class Word:
    text: str
    left: int
    top: int
    width: int
    height: int
    confidence: float

    @property
    def center(self) -> tuple[int, int]:
        return (self.left + self.width // 2, self.top + self.height // 2)


def _imports():
    """Import the optional OCR deps, or raise a helpful error."""
    try:
        import pytesseract  # noqa: F401
        from PIL import Image  # noqa: F401
    except ImportError as exc:  # pragma: no cover - exercised only without deps
        raise RuntimeError(
            "OCR needs extra packages. Install with: pip install \"android-mcp[ocr]\" "
            "(and the tesseract engine, e.g. `apt install tesseract-ocr` / "
            "`brew install tesseract`)."
        ) from exc
    import pytesseract
    from PIL import Image
    return pytesseract, Image


def available() -> tuple[bool, str]:
    """Return (ok, detail). ``ok`` is True only if deps AND the engine work."""
    try:
        pytesseract, _ = _imports()
    except RuntimeError as exc:
        return False, str(exc)
    try:
        version = pytesseract.get_tesseract_version()
    except Exception as exc:  # tesseract binary missing / not on PATH
        return False, (
            f"Python packages found but the tesseract engine is unavailable: {exc}. "
            "Install it (apt install tesseract-ocr / brew install tesseract) or set "
            "pytesseract.pytesseract.tesseract_cmd."
        )
    return True, f"tesseract {version}"


def recognize_words(png_bytes: bytes, *, min_confidence: float = 40.0) -> list[Word]:
    """Run OCR on PNG bytes and return recognised words with boxes."""
    pytesseract, Image = _imports()
    img = Image.open(io.BytesIO(png_bytes))
    data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
    words: list[Word] = []
    n = len(data["text"])
    for i in range(n):
        text = (data["text"][i] or "").strip()
        if not text:
            continue
        try:
            conf = float(data["conf"][i])
        except (ValueError, TypeError):
            conf = -1.0
        if conf < min_confidence:
            continue
        words.append(
            Word(
                text=text,
                left=int(data["left"][i]),
                top=int(data["top"][i]),
                width=int(data["width"][i]),
                height=int(data["height"][i]),
                confidence=conf,
            )
        )
    return words


def group_lines(words: list[Word], *, y_tolerance: int = 12) -> list[str]:
    """Group recognised words into lines by their vertical position.

    Reconstructs readable lines so the model gets prose, not a word salad.
    """
    if not words:
        return []
    ordered = sorted(words, key=lambda w: (w.top, w.left))
    lines: list[list[Word]] = []
    for w in ordered:
        placed = False
        for line in lines:
            if abs(line[0].top - w.top) <= y_tolerance:
                line.append(w)
                placed = True
                break
        if not placed:
            lines.append([w])
    out: list[str] = []
    for line in lines:
        line.sort(key=lambda w: w.left)
        out.append(" ".join(w.text for w in line))
    return out
