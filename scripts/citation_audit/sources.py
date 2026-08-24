"""Source adapters and metadata normalization for citation evidence."""

from __future__ import annotations

import html
import json
import re
import unicodedata
import urllib.parse
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from typing import Dict, List, Protocol

from .bibtex import BibTeXError, author_list, entry_to_reference, latex_to_text, parse_bibtex
from .transport import FetchResult, FetchSpec


FIELDS = ("authors", "title", "year", "venue")


def compact(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def normalize_text(value: object) -> str:
    value = latex_to_text(value)
    value = re.sub(r"[^\w]+", " ", value, flags=re.UNICODE)
    return compact(value).casefold()


_PERSON_TRANSLITERATION = str.maketrans({
    "ł": "l",
    "ø": "o",
    "đ": "d",
    "ð": "d",
    "þ": "th",
    "æ": "ae",
    "œ": "oe",
})


def normalize_person_name(value: object) -> str:
    """Normalize identity spelling without changing author-list order."""
    parsed = author_list(value)
    name = parsed[0] if len(parsed) == 1 else compact(value)
    folded = latex_to_text(name).casefold().translate(_PERSON_TRANSLITERATION)
    folded = "".join(
        char for char in unicodedata.normalize("NFKD", folded)
        if not unicodedata.combining(char)
    )
    return compact(re.sub(r"[^a-z0-9]+", " ", folded))


def normalize_authors(value: object) -> List[str]:
    if isinstance(value, list):
        authors = [compact(item) for item in value]
    else:
        authors = author_list(value)
    return [normalize_person_name(name) for name in authors if compact(name)]


def normalize_field(field: str, value: object):
    if field == "authors":
        return normalize_authors(value)
    if field == "year":
        match = re.search(r"\b(1[5-9]\d{2}|20\d{2}|21\d{2})\b", str(value or ""))
        return match.group(1) if match else ""
    return normalize_text(value)


def observation(source_id: str, source_family: str, values: dict, artifact_ids: list[str], authority: str) -> dict:
    cleaned = {field: values.get(field) for field in FIELDS}
    return {
        "source_id": source_id,
        "source_family": source_family,
        "authority": authority,
        "artifact_ids": artifact_ids,
        "values": cleaned,
        "normalized": {field: normalize_field(field, cleaned.get(field)) for field in FIELDS},
    }


class _CitationMetaParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.meta: Dict[str, List[str]] = {}
        self.title_parts: List[str] = []
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        attr = {str(k).lower(): v for k, v in attrs if k}
        if tag.lower() == "meta":
            key = compact(attr.get("name") or attr.get("property")).lower()
            value = compact(attr.get("content"))
            if key and value:
                self.meta.setdefault(key, []).append(value)
        elif tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data)


def parse_landing_html(body: bytes) -> tuple[dict, dict]:
    parser = _CitationMetaParser()
    parser.feed(body.decode("utf-8", "replace"))
    meta = parser.meta

    def first(*names):
        for name in names:
            values = meta.get(name, [])
            if values:
                return html.unescape(values[0])
        return ""

    authors = [html.unescape(item) for item in meta.get("citation_author", [])]
    values = {
        "authors": authors,
        "title": first("citation_title", "dc.title", "og:title") or compact(" ".join(parser.title_parts)),
        "year": first("citation_publication_date", "citation_date", "dc.date"),
        "venue": first("citation_conference_title", "citation_journal_title", "citation_publisher", "dc.source"),
    }
    discovery = {
        "pdf_url": first("citation_pdf_url"),
        "doi": first("citation_doi", "dc.identifier"),
        "arxiv_id": first("citation_arxiv_id"),
        "raw_meta": {key: list(values) for key, values in sorted(meta.items()) if key.startswith(("citation_", "dc.", "og:"))},
    }
    return values, discovery


def parse_citation_export(body: bytes, reference: dict) -> tuple[dict, dict]:
    text = body.decode("utf-8", "replace")
    entries = parse_bibtex(text)
    if len(entries) != 1:
        raise BibTeXError(
            f"paper-specific citation export must contain exactly one entry, found {len(entries)}"
        )
    selected = None
    wanted_doi = normalize_text(reference.get("doi"))
    wanted_title = normalize_text(reference.get("title"))
    for entry in entries:
        candidate = entry_to_reference(entry)
        if wanted_doi and normalize_text(candidate.get("doi")) == wanted_doi:
            selected = entry
            break
        if wanted_title and normalize_text(candidate.get("title")) == wanted_title:
            selected = entry
            break
    if selected is None:
        selected = entries[0]
    return entry_to_reference(selected), selected


def _crossref_year(message: dict) -> str:
    for key in ("published-print", "published-online", "published", "issued", "created"):
        parts = ((message.get(key) or {}).get("date-parts") or [])
        if parts and parts[0]:
            return str(parts[0][0])
    return ""


def parse_crossref(body: bytes) -> tuple[dict, dict]:
    payload = json.loads(body.decode("utf-8"))
    message = payload.get("message") or payload
    authors = []
    for author in message.get("author") or []:
        name = compact(" ".join(part for part in (author.get("given"), author.get("family")) if part))
        if not name:
            name = compact(author.get("name"))
        if name:
            authors.append(name)
    values = {
        "authors": authors,
        "title": compact((message.get("title") or [""])[0]),
        "year": _crossref_year(message),
        "venue": compact((message.get("container-title") or [""])[0] or message.get("publisher")),
    }
    discovery = {
        "pdf_urls": [
            link.get("URL") for link in message.get("link") or []
            if "pdf" in compact(link.get("content-type")).lower() and link.get("URL")
        ],
        "doi": compact(message.get("DOI")),
        "raw_type": compact(message.get("type")),
    }
    return values, discovery


def parse_semantic_scholar(body: bytes) -> tuple[dict, dict]:
    payload = json.loads(body.decode("utf-8"))
    values = {
        "authors": [compact(author.get("name")) for author in payload.get("authors") or [] if compact(author.get("name"))],
        "title": compact(payload.get("title")),
        "year": compact(payload.get("year") or payload.get("publicationDate")),
        "venue": compact(payload.get("venue")),
    }
    pdf = (payload.get("openAccessPdf") or {}).get("url")
    return values, {"pdf_urls": [pdf] if pdf else [], "external_ids": payload.get("externalIds") or {}}


def parse_arxiv_atom(body: bytes) -> tuple[dict, dict]:
    root = ET.fromstring(body)
    ns = {"atom": "http://www.w3.org/2005/Atom"}
    entry = root.find("atom:entry", ns)
    if entry is None:
        raise ValueError("arXiv response contains no entry")
    values = {
        "authors": [compact(node.findtext("atom:name", default="", namespaces=ns)) for node in entry.findall("atom:author", ns)],
        "title": compact(entry.findtext("atom:title", default="", namespaces=ns)),
        "year": compact(entry.findtext("atom:published", default="", namespaces=ns)),
        "venue": "arXiv",
    }
    return values, {"entry_id": compact(entry.findtext("atom:id", default="", namespaces=ns)), "pdf_urls": []}


def _openreview_value(content: dict, key: str):
    value = content.get(key)
    return value.get("value") if isinstance(value, dict) else value


def openreview_bibtex_export(body: bytes, expected_note_id: str) -> bytes:
    payload = json.loads(body.decode("utf-8"))
    notes = payload.get("notes") or []
    if len(notes) != 1:
        raise ValueError(f"OpenReview metadata expected one note, found {len(notes)}")
    note = notes[0]
    if compact(note.get("id")) != compact(expected_note_id):
        raise ValueError("OpenReview citation export note id does not match the audited forum id")
    bibtex = _openreview_value(note.get("content") or {}, "_bibtex")
    if not isinstance(bibtex, str) or not bibtex.strip():
        raise ValueError("OpenReview note has no official _bibtex citation export")
    encoded = (bibtex.rstrip() + "\n").encode("utf-8")
    if len(parse_bibtex(encoded.decode("utf-8"))) != 1:
        raise ValueError("OpenReview _bibtex citation export must contain exactly one entry")
    return encoded


def parse_openreview(body: bytes) -> tuple[dict, dict]:
    payload = json.loads(body.decode("utf-8"))
    notes = payload.get("notes") or []
    if len(notes) != 1:
        raise ValueError(f"OpenReview metadata expected one note, found {len(notes)}")
    note = notes[0]
    content = note.get("content") or {}
    bibtex = _openreview_value(content, "_bibtex")
    bib_values = {}
    if isinstance(bibtex, str) and bibtex.strip():
        entries = parse_bibtex(bibtex)
        if len(entries) != 1:
            raise ValueError("OpenReview _bibtex citation export must contain exactly one entry")
        bib_values = entry_to_reference(entries[0])
    authors = _openreview_value(content, "authors") or bib_values.get("authors") or []
    if isinstance(authors, str):
        authors = author_list(authors)
    venue = (
        _openreview_value(content, "venue")
        or _openreview_value(content, "venueid")
        or bib_values.get("venue")
        or "OpenReview"
    )
    year = ""
    year_match = re.search(r"\b(20\d{2})\b", compact(venue))
    if year_match:
        year = year_match.group(1)
    if not year:
        year = compact(bib_values.get("year"))
    values = {
        "authors": [compact(name) for name in authors],
        "title": compact(_openreview_value(content, "title") or bib_values.get("title")),
        "year": year,
        "venue": compact(venue),
    }
    pdf_path = compact(_openreview_value(content, "pdf"))
    return values, {
        "note_id": note.get("id"),
        # The collector always uses the identifier-bound /pdf?id=<note> route.
        # This value is retained only as evidence and is never a fetch candidate.
        "declared_pdf_path": pdf_path,
        "pdf_urls": [],
        "has_official_bibtex": bool(isinstance(bibtex, str) and bibtex.strip()),
    }


def parse_generic_metadata(body: bytes) -> tuple[dict, dict]:
    payload = json.loads(body.decode("utf-8"))
    authors = payload.get("authors") or payload.get("author") or []
    if isinstance(authors, str):
        authors = author_list(authors)
    elif authors and isinstance(authors[0], dict):
        authors = [compact(item.get("name") or " ".join(filter(None, (item.get("given"), item.get("family"))))) for item in authors]
    values = {
        "authors": authors,
        "title": compact(payload.get("title")),
        "year": compact(payload.get("year") or payload.get("date")),
        "venue": compact(payload.get("venue") or payload.get("booktitle") or payload.get("journal")),
    }
    pdf = payload.get("pdf_url")
    return values, {"pdf_urls": [pdf] if pdf else []}


class SourceAdapter(Protocol):
    name: str

    def supports(self, reference: dict) -> bool:
        ...

    def requests(self, reference: dict) -> list[FetchSpec]:
        ...


class DOIAdapter:
    name = "doi"

    def supports(self, reference: dict) -> bool:
        return bool(compact(reference.get("doi")))

    def requests(self, reference: dict) -> list[FetchSpec]:
        doi = compact(reference["doi"]).removeprefix("https://doi.org/").removeprefix("http://doi.org/")
        escaped = urllib.parse.quote(doi, safe="")
        specs = [
            FetchSpec("landing_page", "landing_page", f"https://doi.org/{doi}", "text/html,application/xhtml+xml", "html"),
            FetchSpec("citation_export", "citation_export", f"https://doi.org/{doi}", "application/x-bibtex", "citation"),
            FetchSpec("registry_crossref", "registry_metadata", f"https://api.crossref.org/works/{escaped}", "application/json", "metadata"),
        ]
        s2_id = urllib.parse.quote("DOI:" + doi, safe=":")
        fields = "title,authors,year,venue,publicationDate,externalIds,openAccessPdf"
        specs.append(FetchSpec(
            "registry_semantic_scholar", "registry_metadata_secondary",
            f"https://api.semanticscholar.org/graph/v1/paper/{s2_id}?fields={fields}",
            "application/json", "metadata", False,
        ))
        return specs


class ArxivAdapter:
    name = "arxiv"

    def supports(self, reference: dict) -> bool:
        return bool(compact(reference.get("arxiv_id")))

    def requests(self, reference: dict) -> list[FetchSpec]:
        arxiv_id = compact(reference["arxiv_id"]).removeprefix("arXiv:").removeprefix("arxiv:")
        return [
            FetchSpec("landing_page", "landing_page", f"https://arxiv.org/abs/{arxiv_id}", "text/html", "html"),
            FetchSpec("citation_export", "citation_export", f"https://arxiv.org/bibtex/{arxiv_id}", "application/x-bibtex,text/plain", "citation"),
            FetchSpec("registry_arxiv", "registry_metadata", f"https://export.arxiv.org/api/query?id_list={urllib.parse.quote(arxiv_id)}", "application/atom+xml", "metadata"),
            FetchSpec("paper_pdf", "paper_pdf", f"https://arxiv.org/pdf/{arxiv_id}", "application/pdf", "pdf"),
        ]


class OpenReviewAdapter:
    name = "openreview"

    def supports(self, reference: dict) -> bool:
        return bool(compact(reference.get("openreview_id")))

    def requests(self, reference: dict) -> list[FetchSpec]:
        note_id = compact(reference["openreview_id"])
        if not re.fullmatch(r"[A-Za-z0-9_-]+", note_id):
            raise ValueError("OpenReview id contains unsupported characters")
        escaped = urllib.parse.quote(note_id, safe="")
        return [
            FetchSpec("landing_page", "landing_page", f"https://openreview.net/forum?id={escaped}", "text/html", "html"),
            FetchSpec("registry_openreview", "registry_metadata", f"https://api2.openreview.net/notes?id={escaped}", "application/json", "metadata"),
            FetchSpec("paper_pdf", "paper_pdf", f"https://openreview.net/pdf?id={escaped}", "application/pdf", "pdf"),
        ]


class ExplicitAdapter:
    name = "explicit"

    def supports(self, reference: dict) -> bool:
        return all(compact(reference.get(key)) for key in ("landing_url", "citation_url", "metadata_url"))

    def requests(self, reference: dict) -> list[FetchSpec]:
        specs = [
            FetchSpec("landing_page", "landing_page", compact(reference["landing_url"]), "text/html", "html"),
            FetchSpec("citation_export", "citation_export", compact(reference["citation_url"]), "application/x-bibtex,text/plain", "citation"),
            FetchSpec("registry_explicit", "registry_metadata", compact(reference["metadata_url"]), "application/json", "metadata"),
        ]
        if reference.get("pdf_url"):
            specs.append(FetchSpec("paper_pdf", "paper_pdf", compact(reference["pdf_url"]), "application/pdf", "pdf"))
        return specs


ADAPTERS: list[SourceAdapter] = [DOIAdapter(), ArxivAdapter(), OpenReviewAdapter(), ExplicitAdapter()]


def select_adapter(reference: dict) -> SourceAdapter:
    requested = compact(reference.get("source_adapter")).lower()
    if requested:
        for adapter in ADAPTERS:
            if adapter.name == requested:
                if not adapter.supports(reference):
                    raise ValueError(f"source_adapter={requested} is not usable with the supplied identifiers/URLs")
                return adapter
        raise ValueError(f"unknown source_adapter={requested}")
    for adapter in ADAPTERS:
        if adapter.supports(reference):
            return adapter
    raise ValueError("reference needs a DOI, arXiv id, OpenReview id, or explicit landing/citation/metadata URLs")


def parse_registry_result(result: FetchResult) -> tuple[dict, dict]:
    artifact_id = result.spec.artifact_id
    if artifact_id == "registry_crossref":
        return parse_crossref(result.body)
    if artifact_id == "registry_semantic_scholar":
        return parse_semantic_scholar(result.body)
    if artifact_id == "registry_arxiv":
        return parse_arxiv_atom(result.body)
    if artifact_id == "registry_openreview":
        return parse_openreview(result.body)
    return parse_generic_metadata(result.body)
