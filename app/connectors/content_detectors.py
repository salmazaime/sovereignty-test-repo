"""
Content detection layer: regex-based PII/CIN detection, extended
with text extraction from PDF and image (OCR) formats. Every
external dependency (pypdf, pytesseract, PIL, the system tesseract
binary) is imported lazily and defensively -- per Rule 3, missing
system-level binaries must degrade to "skip this format" logging,
never crash the service.
"""

import logging
import re

logger = logging.getLogger(__name__)

# --- Regex patterns (unchanged from original Step 13 version) ---

_CIN_PATTERN = re.compile(r"\b[A-Za-z]{1,2}[0-9]{5,6}\b")
_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_PATTERN = re.compile(r"(?:\+212|0)[5-7][0-9]{8}\b")

# Text-native formats: read a small byte range directly.
MAX_SAMPLE_BYTES = 4096
# Binary formats (PDF/image): a 4KB range read would likely produce
# an unparseable, truncated file. These formats need a larger cap --
# still bounded (never "read the whole object"), but sized for
# format validity rather than pure text scanning. This is a
# deliberate, explainable tradeoff: a bigger memory/bandwidth cost
# per binary object, in exchange for the extraction actually working.
MAX_BINARY_SAMPLE_BYTES = 2_000_000  # 2 MB
# Extracted text (from PDF/OCR) is itself truncated back down to a
# small size before regex runs -- we don't need the FULL extracted
# text to detect a pattern, and capping keeps memory bounded even if
# a PDF is text-dense.
MAX_EXTRACTED_TEXT_CHARS = 20_000
MAX_PDF_PAGES_SAMPLED = 5

TEXT_EXTENSIONS = {".csv", ".txt", ".json", ".xml", ".log", ".md"}
PDF_EXTENSIONS = {".pdf"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".tiff"}
SAMPLEABLE_EXTENSIONS = TEXT_EXTENSIONS | PDF_EXTENSIONS | IMAGE_EXTENSIONS

MAX_OBJECTS_PER_CONTAINER = 20

# --- Lazy, defensive imports for optional binary-format dependencies ---
# Each flag is computed ONCE at import time and logged ONCE, rather
# than re-attempting the import (and re-logging the same warning) on
# every single file processed -- avoids log spam across a scan of
# thousands of objects when a dependency is simply not installed.

try:
    import pypdf
    _PYPDF_AVAILABLE = True
except ImportError:
    pypdf = None
    _PYPDF_AVAILABLE = False
    logger.warning("pypdf not installed -- PDF text extraction disabled, PDFs will be skipped.")

try:
    import pytesseract
    from PIL import Image
    _OCR_LIBS_AVAILABLE = True
except ImportError:
    pytesseract = None
    Image = None
    _OCR_LIBS_AVAILABLE = False
    logger.warning("pytesseract/Pillow not installed -- OCR disabled, images will be skipped.")


def get_sample_byte_range(filename: str) -> int:
    """
    Returns how many bytes a connector should request when fetching
    this object, based on its format. Connectors call this BEFORE
    fetching, so the byte-range request itself is sized correctly --
    avoiding either truncating a PDF unusably short or wastefully
    over-fetching a plain CSV.
    """
    lower = filename.lower()
    if any(lower.endswith(ext) for ext in PDF_EXTENSIONS) or any(lower.endswith(ext) for ext in IMAGE_EXTENSIONS):
        return MAX_BINARY_SAMPLE_BYTES
    return MAX_SAMPLE_BYTES


def is_sampleable(key_or_blob_name: str) -> bool:
    return any(key_or_blob_name.lower().endswith(ext) for ext in SAMPLEABLE_EXTENSIONS)


def _extract_pdf_text(raw_bytes: bytes) -> str:
    """
    Returns '' (never raises) if pypdf is missing, the bytes aren't a
    valid/complete PDF (likely because MAX_BINARY_SAMPLE_BYTES
    truncated a large file mid-structure), or extraction otherwise
    fails. An empty string flowing into detect_content_findings()
    simply means "no findings from this object" -- a safe, silent
    no-op, not a crash.
    """
    if not _PYPDF_AVAILABLE:
        return ""
    try:
        import io
        reader = pypdf.PdfReader(io.BytesIO(raw_bytes))
        text_parts = []
        for page in reader.pages[:MAX_PDF_PAGES_SAMPLED]:
            try:
                text_parts.append(page.extract_text() or "")
            except Exception as exc:  # noqa: BLE001 -- one bad page shouldn't fail the whole doc
                logger.warning("Could not extract text from a PDF page: %s", exc)
                continue
        return "".join(text_parts)[:MAX_EXTRACTED_TEXT_CHARS]
    except Exception as exc:  # noqa: BLE001 -- covers pypdf.errors.PdfReadError and any truncation issue
        logger.warning("PDF parsing failed (possibly truncated by sampling cap): %s", exc)
        return ""


def _extract_image_text(raw_bytes: bytes) -> str:
    """
    Returns '' (never raises) if pytesseract/Pillow are missing, OR
    if the tesseract SYSTEM BINARY itself isn't installed --
    pytesseract.TesseractNotFoundError is raised at call time, not
    at import time, which is exactly why this is wrapped here rather
    than only guarded by the import-time _OCR_LIBS_AVAILABLE flag.
    A missing system binary is a very likely real-world case (the
    Python packages install fine via pip; the OS-level `tesseract-ocr`
    binary is a separate apt/brew install most environments won't have
    by default) -- this must degrade gracefully, per Rule 3.
    """
    if not _OCR_LIBS_AVAILABLE:
        return ""
    try:
        import io
        image = Image.open(io.BytesIO(raw_bytes))
        text = pytesseract.image_to_string(image)
        return text[:MAX_EXTRACTED_TEXT_CHARS]
    except pytesseract.TesseractNotFoundError:
        logger.warning(
            "tesseract-ocr system binary not found (pip package present, OS binary missing) "
            "-- OCR skipped for this image. Install via 'apt-get install tesseract-ocr' "
            "or equivalent to enable image scanning."
        )
        return ""
    except Exception as exc:  # noqa: BLE001 -- covers corrupt/unsupported image data
        logger.warning("OCR extraction failed: %s", exc)
        return ""


def extract_text_by_extension(filename: str, raw_bytes: bytes) -> str:
    """
    Single dispatch point: given a filename and its raw bytes,
    returns whatever plain text we could extract, regardless of
    format. Connectors call ONLY this function -- they never need to
    know which extension implies which extraction method, keeping
    that logic in one place (same "single seam" discipline as
    app/connectors/transform.py).
    """
    lower = filename.lower()
    if any(lower.endswith(ext) for ext in PDF_EXTENSIONS):
        return _extract_pdf_text(raw_bytes)
    if any(lower.endswith(ext) for ext in IMAGE_EXTENSIONS):
        return _extract_image_text(raw_bytes)
    # Plain text formats
    return raw_bytes.decode("utf-8", errors="ignore")


def detect_content_findings(text: str) -> list[dict]:
    """Unchanged from the original Step 13 implementation."""
    findings: list[dict] = []

    if _CIN_PATTERN.search(text):
        findings.append({
            "category": "national_id",
            "field_or_location": "sampled_content",
            "confidence": 0.6,
            "detector": "regex",
        })
    if _EMAIL_PATTERN.search(text):
        findings.append({
            "category": "ordinary_pii",
            "field_or_location": "sampled_content",
            "confidence": 0.9,
            "detector": "regex",
        })
    if _PHONE_PATTERN.search(text):
        findings.append({
            "category": "ordinary_pii",
            "field_or_location": "sampled_content",
            "confidence": 0.75,
            "detector": "regex",
        })

    return findings
    