import io
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from zipfile import BadZipFile, ZipFile

from second_brain.storage import sanitize_filename

DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
UPLOAD_MATRIX = {
    ("txt", "text/plain"): "txt",
    ("md", "text/markdown"): "markdown",
    ("pdf", "application/pdf"): "pdf",
    ("docx", DOCX_MIME): "docx",
}
REQUIRED_DOCX_ENTRIES = {"[Content_Types].xml", "_rels/.rels", "word/document.xml"}


class UploadRejected(ValueError):
    pass


@dataclass(frozen=True)
class ValidatedUpload:
    source_type: str
    mime_type: str
    filename: str
    data: bytes


def normalize_text(data: bytes) -> str:
    if b"\x00" in data:
        raise UploadRejected("text upload contains a forbidden NUL byte")
    try:
        value = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UploadRejected("text upload must be valid UTF-8") from exc
    return re.sub(r"[ \t]+", " ", value.replace("\r\n", "\n").replace("\r", "\n")).strip()


def canonical_text_bytes(data: bytes) -> bytes:
    return normalize_text(data).encode("utf-8")


def validate_upload(
    filename: str | None,
    mime_type: str,
    data: bytes,
    max_upload_bytes: int,
    max_extracted_chars: int,
) -> ValidatedUpload:
    safe_name = sanitize_filename(filename)
    if safe_name is None or "." not in safe_name:
        raise UploadRejected("upload filename extension is required")
    extension = safe_name.rsplit(".", 1)[1].lower()
    source_type = UPLOAD_MATRIX.get((extension, mime_type))
    if source_type is None:
        raise UploadRejected("file extension and MIME type are unsupported or disagree")
    if not data or len(data) > max_upload_bytes:
        raise UploadRejected("upload size is invalid")
    if source_type in {"txt", "markdown"}:
        normalize_text(data)
    elif source_type == "pdf":
        _validate_pdf(data)
    else:
        _validate_docx(data, max_upload_bytes, max_extracted_chars)
    return ValidatedUpload(source_type, mime_type, safe_name, data)


def _validate_pdf(data: bytes) -> None:
    if (
        not data.startswith(b"%PDF-")
        or b"%%EOF" not in data[-1024:]
        or b"startxref" not in data[-4096:]
    ):
        raise UploadRejected("PDF structure is invalid")


def _validate_docx(data: bytes, max_upload_bytes: int, max_extracted_chars: int) -> None:
    if not data.startswith(b"PK\x03\x04"):
        raise UploadRejected("DOCX structure is invalid")
    max_entries = 2_000
    max_entry = max(max_upload_bytes, 1_000_000)
    max_expanded = max(max_upload_bytes * 10, max_extracted_chars * 20, 1_000_000)
    try:
        with ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > max_entries:
                raise UploadRejected("DOCX contains too many entries")
            seen: set[str] = set()
            expanded = 0
            for entry in entries:
                name = entry.filename
                path = PurePosixPath(name)
                if (
                    name in seen
                    or "\\" in name
                    or name.startswith("/")
                    or path.is_absolute()
                    or ".." in path.parts
                    or (path.parts and ":" in path.parts[0])
                ):
                    raise UploadRejected("DOCX contains an unsafe entry name")
                seen.add(name)
                if entry.flag_bits & 0x1:
                    raise UploadRejected("encrypted DOCX entries are unsupported")
                if entry.file_size > max_entry:
                    raise UploadRejected("DOCX entry exceeds the expansion limit")
                expanded += entry.file_size
                if expanded > max_expanded:
                    raise UploadRejected("DOCX exceeds the expansion limit")
                if entry.file_size and entry.file_size / max(entry.compress_size, 1) > 100:
                    raise UploadRejected("DOCX compression ratio is unsafe")
                lowered = name.lower()
                if lowered.endswith("vbaproject.bin") or "macros" in lowered:
                    raise UploadRejected("macro-enabled DOCX content is unsupported")
                if lowered.endswith(".rels"):
                    relationship = archive.read(entry)
                    if re.search(rb"TargetMode\s*=\s*['\"]External['\"]", relationship, re.I):
                        raise UploadRejected("external DOCX relationships are unsupported")
            if not REQUIRED_DOCX_ENTRIES.issubset(seen):
                raise UploadRejected("DOCX is missing required OOXML entries")
            content_types = archive.read("[Content_Types].xml").lower()
            if b"macroenabled" in content_types or b"vbaproject" in content_types:
                raise UploadRejected("macro-enabled DOCX content is unsupported")
    except BadZipFile as exc:
        raise UploadRejected("DOCX structure is invalid") from exc
