"""Small, state-machine BibTeX parser used at the citation audit boundary.

It intentionally supports the common entry/field grammar without evaluating
BibTeX macros. Unsupported concatenations remain visible and therefore block
verification instead of being guessed.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Dict, Iterable, List


class BibTeXError(ValueError):
    pass


_CITATION_KEY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:+-]*\Z")


def validate_citation_key(value: object) -> str:
    key = str(value or "").strip()
    if not _CITATION_KEY_RE.fullmatch(key):
        raise BibTeXError(
            "citation key must start with an alphanumeric character and contain only "
            "letters, digits, '.', '_', ':', '+', or '-'"
        )
    return key


def _balanced_slice(text: str, start: int, opener: str, closer: str) -> tuple[str, int]:
    depth = 1
    quoted = False
    escaped = False
    index = start
    while index < len(text):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"' and depth == 1:
            quoted = not quoted
        elif not quoted and char == opener:
            depth += 1
        elif not quoted and char == closer:
            depth -= 1
            if depth == 0:
                return text[start:index], index + 1
        index += 1
    raise BibTeXError("unclosed BibTeX entry")


def _split_key_and_fields(body: str) -> tuple[str, str]:
    depth = 0
    quoted = False
    escaped = False
    for index, char in enumerate(body):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"' and depth == 0:
            quoted = not quoted
        elif not quoted and char == "{":
            depth += 1
        elif not quoted and char == "}":
            depth -= 1
        elif not quoted and depth == 0 and char == ",":
            key = body[:index].strip()
            if not key:
                raise BibTeXError("BibTeX entry has no citation key")
            return validate_citation_key(key), body[index + 1 :]
    raise BibTeXError("BibTeX entry has no field list")


def _parse_value(text: str, index: int) -> tuple[str, int]:
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text):
        raise BibTeXError("missing BibTeX field value")
    if text[index] == "{":
        value, end = _balanced_slice(text, index + 1, "{", "}")
        return value, end
    if text[index] == '"':
        out = []
        index += 1
        escaped = False
        while index < len(text):
            char = text[index]
            if escaped:
                out.extend(("\\", char))
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                return "".join(out), index + 1
            else:
                out.append(char)
            index += 1
        raise BibTeXError("unclosed quoted BibTeX value")
    end = index
    while end < len(text) and text[end] not in ",\n\r":
        end += 1
    return text[index:end].strip(), end


def _parse_fields(text: str) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    index = 0
    while index < len(text):
        while index < len(text) and (text[index].isspace() or text[index] == ","):
            index += 1
        if index >= len(text):
            break
        match = re.match(r"[A-Za-z][A-Za-z0-9_:-]*", text[index:])
        if not match:
            raise BibTeXError(f"invalid BibTeX field near {text[index:index + 30]!r}")
        name = match.group(0).lower()
        index += len(match.group(0))
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text) or text[index] != "=":
            raise BibTeXError(f"BibTeX field {name!r} has no '='")
        value, index = _parse_value(text, index + 1)
        if "#" in value:
            raise BibTeXError(f"BibTeX macro concatenation is unsupported in field {name!r}")
        if name in fields:
            raise BibTeXError(f"duplicate BibTeX field {name!r}")
        fields[name] = value.strip()
    return fields


def parse_bibtex(text: str) -> List[dict]:
    entries: List[dict] = []
    keys: set[str] = set()
    outside: list[str] = []
    index = 0
    while True:
        match = re.search(r"@([A-Za-z]+)\s*([({])", text[index:])
        if not match:
            outside.append(text[index:])
            break
        outside.append(text[index : index + match.start()])
        entry_type = match.group(1).lower()
        opener = match.group(2)
        absolute = index + match.end()
        closer = "}" if opener == "{" else ")"
        body, end = _balanced_slice(text, absolute, opener, closer)
        index = end
        if entry_type in {"comment", "preamble", "string"}:
            continue
        key, field_text = _split_key_and_fields(body)
        if key.casefold() in keys:
            raise BibTeXError(f"duplicate BibTeX citation key {key!r}")
        keys.add(key.casefold())
        entries.append({"entry_type": entry_type, "citation_key": key, "fields": _parse_fields(field_text)})
    if not entries:
        raise BibTeXError("no BibTeX entries found")
    residual = re.sub(r"(?m)%.*$", "", "".join(outside)).lstrip("\ufeff").strip()
    if residual:
        raise BibTeXError(f"unexpected text outside BibTeX entries: {residual[:40]!r}")
    return entries


_LATEX_REPLACEMENTS = {
    r"\\&": "&",
    r"\\%": "%",
    r"\\_": "_",
    r"\\-": "",
    "~": " ",
}


def latex_to_text(value: object) -> str:
    text = str(value or "")
    for old, new in _LATEX_REPLACEMENTS.items():
        text = text.replace(old, new)
    text = re.sub(r"\\(?:textit|textbf|emph|mathrm|operatorname)\s*\{([^{}]*)\}", r"\1", text)
    text = re.sub(r"\\['\"`^~=.]\s*\{?([A-Za-z])\}?", r"\1", text)
    text = text.replace("{", "").replace("}", "")
    return unicodedata.normalize("NFKC", re.sub(r"\s+", " ", text)).strip()


def _split_authors(value: str) -> Iterable[str]:
    depth = 0
    start = 0
    index = 0
    while index < len(value):
        char = value[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
        elif depth == 0 and value[index : index + 5].lower() == " and ":
            yield value[start:index]
            index += 4
            start = index + 1
        index += 1
    yield value[start:]


def author_list(value: object) -> List[str]:
    authors = []
    for raw in _split_authors(str(value or "")):
        name = latex_to_text(raw)
        parts = [part.strip() for part in name.split(",")]
        if len(parts) == 2 and all(parts):
            name = f"{parts[1]} {parts[0]}"
        elif len(parts) == 3 and all(parts):
            name = f"{parts[2]} {parts[0]} {parts[1]}"
        name = re.sub(r"\s+", " ", name).strip()
        if name:
            authors.append(name)
    return authors


def entry_to_reference(entry: dict, reference_id: str | None = None) -> dict:
    fields = entry["fields"]
    venue = fields.get("booktitle") or fields.get("journal") or fields.get("publisher") or ""
    year_match = re.search(r"\b(1[5-9]\d{2}|20\d{2}|21\d{2})\b", fields.get("year") or fields.get("date") or "")
    ref = {
        "reference_id": reference_id or entry["citation_key"],
        "citation_key": entry["citation_key"],
        "entry_type": entry["entry_type"],
        "authors": author_list(fields.get("author", "")),
        "title": latex_to_text(fields.get("title", "")),
        "venue": latex_to_text(venue),
        "year": year_match.group(1) if year_match else "",
        "doi": latex_to_text(fields.get("doi", "")),
        "arxiv_id": latex_to_text(fields.get("eprint", "")) if fields.get("archiveprefix", "").lower() == "arxiv" else "",
        "landing_url": latex_to_text(fields.get("url", "")),
        "pdf_url": "",
        "citation_url": "",
        "metadata_url": "",
        "original_bibtex_fields": fields,
    }
    return ref


def quote_bibtex(value: object) -> str:
    text = str(value or "").replace("\\", r"\\").replace("{", r"\{").replace("}", r"\}")
    return "{" + text + "}"


def reference_to_bibtex(ref: dict) -> str:
    key = validate_citation_key(ref.get("citation_key") or ref.get("reference_id") or "reference")
    fields = dict(ref.get("original_bibtex_fields") or {})
    fields["author"] = " and ".join(ref.get("authors") or [])
    fields["title"] = ref.get("title") or ""
    fields["year"] = str(ref.get("year") or "")
    if (ref.get("entry_type") or "article") in {"inproceedings", "conference"}:
        fields["booktitle"] = ref.get("venue") or ""
        fields.pop("journal", None)
    else:
        fields["journal"] = ref.get("venue") or fields.get("journal", "")
    if ref.get("doi"):
        fields["doi"] = ref["doi"]
    order = ["author", "title", "booktitle", "journal", "year", "doi", "url"]
    names = [name for name in order if name in fields] + sorted(set(fields) - set(order))
    rendered = [f"  {name} = {quote_bibtex(fields[name])}" for name in names if str(fields[name]).strip()]
    return f"@{ref.get('entry_type') or 'article'}{{{key},\n" + ",\n".join(rendered) + "\n}"
