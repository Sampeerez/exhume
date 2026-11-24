"""Text extraction from office documents and emails.

Each extractor tolerates a missing library: it returns (None, reason) so the
scanner keeps going without breaking.
"""
from __future__ import annotations

_PDF_PAGES = 80


def _pdf(path: str) -> tuple[str | None, str]:
    try:
        import pdfplumber  # type: ignore
    except ImportError:
        return None, "sin-pdfplumber"
    try:
        parts = []
        with pdfplumber.open(path) as pdf:
            for page in pdf.pages[:_PDF_PAGES]:
                parts.append(page.extract_text() or "")
        return "\n".join(parts), "pdfplumber"
    except Exception as exc:
        return None, f"error:{type(exc).__name__}"


def _docx(path: str) -> tuple[str | None, str]:
    try:
        import docx  # type: ignore
    except ImportError:
        return None, "sin-python-docx"
    try:
        d = docx.Document(path)
        parts = [p.text for p in d.paragraphs]
        for table in d.tables:
            for row in table.rows:
                parts.append("\t".join(c.text for c in row.cells))
        return "\n".join(parts), "python-docx"
    except Exception as exc:
        return None, f"error:{type(exc).__name__}"


def _xlsx(path: str) -> tuple[str | None, str]:
    try:
        import openpyxl  # type: ignore
    except ImportError:
        return None, "sin-openpyxl"
    try:
        wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
        parts = []
        for ws in wb.worksheets:
            for row in ws.iter_rows(values_only=True):
                parts.append("\t".join("" if c is None else str(c) for c in row))
        wb.close()
        return "\n".join(parts), "openpyxl"
    except Exception as exc:
        return None, f"error:{type(exc).__name__}"


def _pptx(path: str) -> tuple[str | None, str]:
    try:
        from pptx import Presentation  # type: ignore
    except ImportError:
        return None, "sin-python-pptx"
    try:
        prs = Presentation(path)
        parts = []
        for slide in prs.slides:
            for shape in slide.shapes:
                if shape.has_text_frame:
                    parts.append(shape.text_frame.text)
        return "\n".join(parts), "python-pptx"
    except Exception as exc:
        return None, f"error:{type(exc).__name__}"


def _eml(path: str) -> tuple[str | None, str]:
    import email
    try:
        with open(path, "rb") as f:
            msg = email.message_from_binary_file(f)
        parts = [str(msg.get(h, "")) for h in ("From", "To", "Subject", "Date")]
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    parts.append(part.get_payload(decode=True).decode("utf-8", "replace"))
                except Exception:
                    pass
        return "\n".join(parts), "email"
    except Exception as exc:
        return None, f"error:{type(exc).__name__}"


def _msg(path: str) -> tuple[str | None, str]:
    try:
        import extract_msg  # type: ignore
    except ImportError:
        return None, "sin-extract-msg"
    try:
        m = extract_msg.Message(path)
        return "\n".join([m.subject or "", m.sender or "", m.to or "", m.body or ""]), "extract-msg"
    except Exception as exc:
        return None, f"error:{type(exc).__name__}"


_DISPATCH = {
    ".pdf": _pdf, ".docx": _docx, ".xlsx": _xlsx, ".xlsm": _xlsx,
    ".pptx": _pptx, ".eml": _eml, ".msg": _msg,
}


def extract_document(path: str, ext: str) -> tuple[str | None, str]:
    handler = _DISPATCH.get(ext)
    if handler is None:
        return None, "sin-extractor"
    return handler(path)
