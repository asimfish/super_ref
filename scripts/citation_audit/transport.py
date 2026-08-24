"""Bounded transports for untrusted bibliographic network inputs."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import ssl
import stat
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass
from typing import Dict, Mapping, Protocol


class FetchError(RuntimeError):
    pass


@dataclass(frozen=True)
class FetchSpec:
    artifact_id: str
    source_family: str
    url: str
    accept: str
    kind: str
    required: bool = True


@dataclass(frozen=True)
class FetchResult:
    spec: FetchSpec
    status: int
    final_url: str
    content_type: str
    body: bytes
    headers: Mapping[str, str]
    redirect_chain: tuple[str, ...] = ()
    peer_ip: str = ""

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()


class Transport(Protocol):
    def fetch(self, spec: FetchSpec) -> FetchResult:
        ...


def _host_is_allowed(host: str, allowed_domains: list[str]) -> bool:
    if not allowed_domains:
        return True
    host = host.lower().rstrip(".")
    return any(host == domain or host.endswith("." + domain) for domain in allowed_domains)


def validate_public_url(
    url: str,
    *,
    allow_http: bool,
    allowed_domains: list[str],
    resolver_mode: str = "strict",
) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ({"https", "http"} if allow_http else {"https"}):
        raise FetchError(f"URL scheme is not allowed: {parsed.scheme or '<missing>'}")
    if not parsed.hostname or parsed.username or parsed.password:
        raise FetchError("URL must have a hostname and no embedded credentials")
    if not _host_is_allowed(parsed.hostname, allowed_domains):
        raise FetchError(f"URL host is outside citation_audit.allowed_domains: {parsed.hostname}")
    try:
        literal_host = ipaddress.ip_address(parsed.hostname.split("%", 1)[0])
    except ValueError:
        literal_host = None
    if literal_host is not None:
        raise FetchError(f"URL IP literals are not allowed: {literal_host}")
    if resolver_mode not in {"strict", "trusted_proxy"}:
        raise FetchError(f"unknown resolver_mode: {resolver_mode}")
    if resolver_mode == "trusted_proxy" and not allowed_domains:
        raise FetchError("resolver_mode=trusted_proxy requires an explicit allowed_domains list")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise FetchError(f"cannot resolve URL host {parsed.hostname}: {exc}") from exc
    if not addresses:
        raise FetchError(f"URL host has no resolved address: {parsed.hostname}")
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        if not ip.is_global and resolver_mode != "trusted_proxy":
            raise FetchError(f"URL resolves to a non-public address: {parsed.hostname} -> {ip}")


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, policy, max_redirects: int) -> None:
        super().__init__()
        self.policy = policy
        self.max_redirects = max_redirects
        self.redirect_chain: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if len(self.redirect_chain) >= self.max_redirects:
            raise FetchError(f"redirect limit exceeded ({self.max_redirects})")
        self.policy(newurl)
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        old_host = (urllib.parse.urlsplit(req.full_url).hostname or "").casefold()
        new_host = (urllib.parse.urlsplit(newurl).hostname or "").casefold()
        if redirected is not None and old_host != new_host:
            for secret_header in ("Authorization", "Cookie", "Proxy-Authorization"):
                redirected.remove_header(secret_header)
                redirected.unredirected_hdrs.pop(secret_header, None)
                redirected.unredirected_hdrs.pop(secret_header.lower(), None)
        self.redirect_chain.append(newurl)
        return redirected


def _response_socket(response):
    candidates = [
        getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None),
        getattr(getattr(response, "fp", None), "_sock", None),
    ]
    return next((item for item in candidates if item is not None), None)


def _decode_gzip_body(body: bytes, limit: int, artifact_id: str) -> bytes:
    """Decode a server-declared gzip body while enforcing the decoded byte cap.

    Some hosts ignore `Accept-Encoding: identity` and compress anyway (observed
    on ojs.aaai.org behind a CDN). Storing compressed bytes silently breaks
    every downstream text check, so the declared encoding is honored here with
    the same per-kind byte limit applied to the decoded output to keep
    decompression-bomb protection intact.
    """
    decoder = zlib.decompressobj(wbits=zlib.MAX_WBITS | 16)
    try:
        output = decoder.decompress(body, limit + 1)
        output += decoder.flush()
    except zlib.error as exc:
        raise FetchError(f"{artifact_id} declared gzip content that failed to decode: {exc}") from exc
    if len(output) > limit or decoder.unconsumed_tail:
        raise FetchError(f"{artifact_id} exceeds byte limit after gzip decoding (> {limit})")
    if not decoder.eof or decoder.unused_data:
        raise FetchError(f"{artifact_id} declared gzip content that is truncated or has trailing data")
    return output


class SafeHTTPTransport:
    """HTTPS transport with redirect revalidation, SSRF checks, and byte caps."""

    transport_type = "safe_http"

    def __init__(self, config: dict) -> None:
        self.timeout = int(config.get("timeout_seconds", 25))
        self.user_agent = str(config.get("user_agent") or "super-rebuttal-citation-audit/1.0")
        self.allow_http = bool(config.get("allow_http", False))
        self.resolver_mode = str(config.get("resolver_mode") or "strict")
        self.allowed_domains = [str(x).lower().rstrip(".") for x in config.get("allowed_domains", [])]
        self.max_redirects = min(max(int(config.get("max_redirects", 5)), 0), 10)
        self.limits = {
            "pdf": int(config.get("max_pdf_bytes", 50 * 1024 * 1024)),
            "html": int(config.get("max_html_bytes", 5 * 1024 * 1024)),
            "citation": int(config.get("max_citation_bytes", 2 * 1024 * 1024)),
            "metadata": int(config.get("max_metadata_bytes", 5 * 1024 * 1024)),
        }
        self.context = ssl.create_default_context()

    def _validate(self, url: str) -> None:
        validate_public_url(
            url,
            allow_http=self.allow_http,
            allowed_domains=self.allowed_domains,
            resolver_mode=self.resolver_mode,
        )

    def fetch(self, spec: FetchSpec) -> FetchResult:
        self._validate(spec.url)
        started = time.monotonic()
        limit = self.limits.get(spec.kind, self.limits["metadata"])
        request = urllib.request.Request(
            spec.url,
            headers={
                "Accept": spec.accept,
                "User-Agent": self.user_agent,
                "Accept-Encoding": "identity",
            },
        )
        redirect_handler = _SafeRedirectHandler(self._validate, self.max_redirects)
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=self.context), redirect_handler
        )
        try:
            with opener.open(request, timeout=self.timeout) as response:
                final_url = response.geturl()
                self._validate(final_url)
                peer_socket = _response_socket(response)
                peer_ip = ""
                if peer_socket is not None:
                    peer_ip = str(peer_socket.getpeername()[0]).split("%", 1)[0]
                if self.resolver_mode == "strict":
                    if not peer_ip:
                        raise FetchError("could not attest the actual network peer IP")
                    if not ipaddress.ip_address(peer_ip).is_global:
                        raise FetchError(f"actual network peer is not public: {peer_ip}")
                length = response.headers.get("Content-Length")
                if length and int(length) > limit:
                    raise FetchError(f"{spec.artifact_id} exceeds byte limit ({length} > {limit})")
                chunks = []
                total = 0
                while total <= limit:
                    remaining_time = self.timeout - (time.monotonic() - started)
                    if remaining_time <= 0:
                        raise FetchError(f"{spec.artifact_id} exceeded total wall-clock limit ({self.timeout}s)")
                    if peer_socket is not None and peer_socket.fileno() >= 0:
                        peer_socket.settimeout(max(0.1, remaining_time))
                    chunk = response.read(min(64 * 1024, limit + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                body = b"".join(chunks)
                if len(body) > limit:
                    raise FetchError(f"{spec.artifact_id} exceeds byte limit ({len(body)} > {limit})")
                headers = {str(k).lower(): str(v) for k, v in response.headers.items()}
                declared_encoding = headers.get("content-encoding", "").strip().lower()
                if declared_encoding in {"gzip", "x-gzip"}:
                    body = _decode_gzip_body(body, limit, spec.artifact_id)
                    headers["x-citation-audit-content-decoded"] = declared_encoding
                elif declared_encoding not in {"", "identity"}:
                    raise FetchError(
                        f"{spec.artifact_id} used an unsupported content encoding: {declared_encoding}"
                    )
                elif body[:3] == b"\x1f\x8b\x08":
                    # Some origins (observed: ojs.aaai.org) send gzip bytes without
                    # declaring Content-Encoding even for `Accept-Encoding: identity`.
                    # A raw gzip blob is never valid text or PDF evidence, so decode
                    # it under the same byte cap; a non-gzip body that merely starts
                    # with these bytes fails the decode and blocks fail-closed.
                    body = _decode_gzip_body(body, limit, spec.artifact_id)
                    headers["x-citation-audit-content-decoded"] = "gzip-undeclared"
                return FetchResult(
                    spec=spec,
                    status=int(getattr(response, "status", 200)),
                    final_url=final_url,
                    content_type=headers.get("content-type", "").split(";", 1)[0].strip().lower(),
                    body=body,
                    headers=headers,
                    redirect_chain=tuple(redirect_handler.redirect_chain),
                    peer_ip=peer_ip,
                )
        except FetchError:
            raise
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as exc:
            raise FetchError(f"failed to fetch {spec.artifact_id} from {spec.url}: {exc}") from exc


class FixtureTransport:
    """Explicit offline transport. It never falls through to the network."""

    transport_type = "fixture"

    def __init__(self, fixture_dir: str) -> None:
        self.root = os.path.realpath(fixture_dir)
        manifest_path = os.path.join(self.root, "responses.json")
        try:
            with open(manifest_path, encoding="utf-8") as handle:
                manifest = json.load(handle)
        except (OSError, ValueError) as exc:
            raise FetchError(f"invalid fixture transport manifest {manifest_path}: {exc}") from exc
        self.responses = manifest.get("responses") or []

    def _body(self, item: dict) -> bytes:
        if "body" in item:
            return str(item["body"]).encode("utf-8")
        relative = item.get("body_file")
        if not relative:
            raise FetchError("fixture response has neither body nor body_file")
        path = os.path.realpath(os.path.join(self.root, relative))
        if os.path.commonpath([self.root, path]) != self.root:
            raise FetchError(f"fixture body escapes fixture root: {relative}")
        with open(path, "rb") as handle:
            return handle.read()

    def fetch(self, spec: FetchSpec) -> FetchResult:
        matches = [
            item for item in self.responses
            if item.get("url") == spec.url and item.get("accept", spec.accept) == spec.accept
        ]
        if len(matches) != 1:
            raise FetchError(
                f"fixture transport expected exactly one response for {spec.url} [{spec.accept}], found {len(matches)}"
            )
        item = matches[0]
        status = int(item.get("status", 200))
        if status < 200 or status >= 300:
            raise FetchError(f"fixture response for {spec.artifact_id} has HTTP {status}")
        content_type = str(item.get("content_type") or "application/octet-stream").split(";", 1)[0].lower()
        return FetchResult(
            spec=spec,
            status=status,
            final_url=str(item.get("final_url") or spec.url),
            content_type=content_type,
            body=self._body(item),
            headers={"content-type": content_type},
        )


def looks_like_html(body: bytes) -> bool:
    head = body[:4096].lstrip().lower()
    return head.startswith((b"<!doctype html", b"<html", b"<head", b"<body")) or b"<html" in head


def challenge_markers(body: bytes) -> list[str]:
    text = body[:100000].decode("utf-8", "ignore").lower()
    markers = {
        "cloudflare": "cloudflare",
        "captcha": "captcha",
        "sign-in": "sign in",
        "login": "log in",
        "access-denied": "access denied",
        "javascript-challenge": "enable javascript",
    }
    return sorted(name for name, needle in markers.items() if needle in text)


def validate_result(result: FetchResult, config: dict) -> None:
    body = result.body
    kind = result.spec.kind
    if not body:
        raise FetchError(f"{result.spec.artifact_id} returned an empty body")
    if kind == "pdf":
        if looks_like_html(body):
            raise FetchError(f"{result.spec.artifact_id} returned HTML instead of a PDF")
        if not body.startswith(b"%PDF-"):
            raise FetchError(f"{result.spec.artifact_id} has no PDF magic header")
        minimum = int(config.get("min_pdf_bytes", 1024))
        if len(body) < minimum:
            raise FetchError(f"{result.spec.artifact_id} is implausibly small ({len(body)} < {minimum} bytes)")
    elif kind == "html":
        if result.content_type not in {"text/html", "application/xhtml+xml", ""} and not looks_like_html(body):
            raise FetchError(f"{result.spec.artifact_id} is not HTML ({result.content_type or 'unknown type'})")
        markers = challenge_markers(body)
        lower = body[:500000].lower()
        has_scholarly_meta = b"citation_title" in lower and b"citation_author" in lower
        if markers and not has_scholarly_meta:
            raise FetchError(f"{result.spec.artifact_id} looks like a login/challenge page: {', '.join(markers)}")
    elif kind == "citation":
        if looks_like_html(body):
            markers = challenge_markers(body)
            detail = f": {', '.join(markers)}" if markers else ""
            raise FetchError(f"{result.spec.artifact_id} returned HTML instead of a citation export{detail}")
        if b"@" not in body[:4096]:
            raise FetchError(f"{result.spec.artifact_id} is not a recognizable BibTeX export")


def write_fetch_artifact(directory: str, result: FetchResult, filename: str) -> dict:
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, filename)
    if os.path.lexists(path) and not stat.S_ISREG(os.lstat(path).st_mode):
        raise FetchError(f"refusing to replace non-regular artifact path: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=".citation-download-", dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(result.body)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {
        "artifact_id": result.spec.artifact_id,
        "source_family": result.spec.source_family,
        "kind": result.spec.kind,
        "request_url": result.spec.url,
        "final_url": result.final_url,
        "redirect_chain": list(result.redirect_chain),
        "peer_ip": result.peer_ip,
        "accept": result.spec.accept,
        "status": result.status,
        "content_type": result.content_type,
        "bytes": len(result.body),
        "sha256": result.sha256,
        "path": filename,
    }
