import io
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from pypdf import PdfWriter

from second_brain.upload_validation import UploadRejected, normalize_text, validate_upload


def _archive(entries: list[tuple[str, bytes]]) -> bytes:
    output = io.BytesIO()
    with ZipFile(output, "w", ZIP_DEFLATED) as archive:
        for name, value in entries:
            archive.writestr(name, value)
    return output.getvalue()


def test_text_upload_matrix_and_canonical_normalization() -> None:
    accepted = validate_upload("note.md", "text/markdown", b"a\r\nb\rc\t d", 1_000, 1_000)
    assert accepted.source_type == "markdown"
    assert normalize_text(accepted.data) == "a\nb\nc d"
    for name, mime, data in (
        ("note.txt", "text/markdown", b"text"),
        ("note.pdf", "application/pdf", b"plain text"),
        ("note.txt", "text/plain", b"nul\x00value"),
        ("note.txt", "text/plain", b"\xff"),
    ):
        with pytest.raises(UploadRejected):
            validate_upload(name, mime, data, 1_000, 1_000)


def test_structurally_valid_pdf_signature_is_accepted() -> None:
    output = io.BytesIO()
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.write(output)
    accepted = validate_upload(
        "evidence.pdf", "application/pdf", output.getvalue(), 100_000, 100_000
    )
    assert accepted.source_type == "pdf"


@pytest.mark.filterwarnings("ignore:Duplicate name:UserWarning")
def test_docx_rejects_missing_unsafe_or_bomb_like_entries() -> None:
    base = [
        ("[Content_Types].xml", b"<Types/>"),
        ("_rels/.rels", b"<Relationships/>"),
        ("word/document.xml", b"<document/>"),
    ]
    assert (
        validate_upload(
            "safe.docx",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            _archive(base),
            100_000,
            100_000,
        ).source_type
        == "docx"
    )
    for extra in (
        [("../escape", b"x")],
        [("word/vbaProject.bin", b"macro")],
        [("word/_rels/document.xml.rels", b'<Relationship TargetMode="External"/>')],
        [("word/document.xml", b"duplicate")],
    ):
        with pytest.raises(UploadRejected):
            validate_upload(
                "unsafe.docx",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                _archive(base + extra),
                100_000,
                100_000,
            )
