#!/usr/bin/env python3
"""Fetch RFC 9474 Appendix A test vectors and emit the Deterministic JSON.

Downloads the canonical RFC 9474 text and extracts the
RSABSSA-SHA384-PSS-Deterministic test vector (Appendix A.3: empty
``msg_prefix``, 48-byte salt) into ``tests/vectors/rfc9474_deterministic.json``.

The script is committed for reproducibility; the produced JSON is committed
so the conformance tests never need network access. If the download fails,
the script exits non-zero WITHOUT writing anything -- vectors are never
fabricated or hand-computed.

Usage:
    python scripts/fetch_rfc9474_vectors.py
"""
from __future__ import annotations

import json
import re
import ssl
import sys
import urllib.request
from pathlib import Path

RFC_URL = "https://www.rfc-editor.org/rfc/rfc9474.txt"
SECTION_HEADER = "A.3.  RSABSSA-SHA384-PSS-Deterministic Test Vector"
NEXT_SECTION = "A.4."

# Fields we extract, mapped to the JSON keys the test suite expects.
# The RFC labels are on the left; the JSON keys on the right.
FIELD_MAP = {
    "p": "p",
    "q": "q",
    "n": "n",
    "e": "e",
    "d": "d",
    "msg": "msg",
    "salt": "salt",
    "encoded_msg": "encoded_msg",
    "inv": "inv",
    "blinded_msg": "blinded_msg",
    "blind_sig": "blind_sig",
    "sig": "sig",
}


def _ssl_context() -> ssl.SSLContext:
    """Build an SSL context, preferring certifi's CA bundle when available.

    The system Python on macOS often lacks a usable CA store; certifi (a
    dependency of the project) provides a portable bundle so the download
    works reproducibly across machines.
    """
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:  # noqa: BLE001
        return ssl.create_default_context()


def fetch_rfc_text(url: str = RFC_URL) -> str:
    ctx = _ssl_context()
    with urllib.request.urlopen(url, timeout=60, context=ctx) as resp:  # noqa: S310
        return resp.read().decode("utf-8")


def extract_section(text: str) -> str:
    # Section headers sit at column 0; the table-of-contents entries for the
    # same titles are indented, so anchor to line start to skip the TOC.
    start_m = re.search("^" + re.escape(SECTION_HEADER), text, re.MULTILINE)
    if start_m is None:
        raise SystemExit(f"BLOCKED: section header not found: {SECTION_HEADER!r}")
    start = start_m.start()
    end_m = re.search("^" + re.escape(NEXT_SECTION), text[start + len(SECTION_HEADER):], re.MULTILINE)
    end = (start + len(SECTION_HEADER) + end_m.start()) if end_m else len(text)
    return text[start:end]


def parse_fields(section: str) -> dict[str, str]:
    """Parse ``name = hexblob`` entries, joining lines wrapped across the RFC.

    RFC blobs wrap across lines with leading indentation and page-break
    artifacts. We tokenize by finding each ``<label> = `` assignment and
    collecting all hex characters until the next assignment.
    """
    # Strip RFC page headers/footers (form feeds and running headers).
    lines = []
    for line in section.splitlines():
        stripped = line.strip()
        # Skip page-break furniture that could appear inside a section.
        if stripped.startswith("RFC 9474") or "Blind RSA Signatures" in stripped:
            continue
        if re.match(r"^\[Page \d+\]", stripped):
            continue
        lines.append(line)
    joined = "\n".join(lines)

    # Find every "label =" assignment and its span.
    assign_re = re.compile(r"^\s*([A-Za-z_]+)\s*=", re.MULTILINE)
    matches = list(assign_re.finditer(joined))
    fields: dict[str, str] = {}
    for i, m in enumerate(matches):
        label = m.group(1)
        value_start = m.end()
        value_end = matches[i + 1].start() if i + 1 < len(matches) else len(joined)
        raw = joined[value_start:value_end]
        # Keep only hex characters -- drops whitespace, newlines, indentation.
        hex_value = re.sub(r"[^0-9a-fA-F]", "", raw)
        fields[label] = hex_value
    return fields


def build_vector(fields: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for rfc_label, json_key in FIELD_MAP.items():
        if rfc_label not in fields:
            raise SystemExit(f"BLOCKED: RFC field '{rfc_label}' not found in section")
        value = fields[rfc_label]
        if not value:
            raise SystemExit(f"BLOCKED: RFC field '{rfc_label}' is empty")
        out[json_key] = value.lower()
    return out


def validate(vector: dict[str, str]) -> None:
    # RFC 9474 Appendix A uses a 4096-bit modulus (two 2048-bit primes) for
    # every test vector. This is a property of the published vectors, not a
    # tunable -- we assert it so any silent extraction corruption is caught.
    n = int(vector["n"], 16)
    n_bits = n.bit_length()
    if n_bits != 4096:
        raise SystemExit(f"BLOCKED: modulus n is {n_bits}-bit, expected 4096")
    p = int(vector["p"], 16)
    q = int(vector["q"], 16)
    if p * q != n:
        raise SystemExit("BLOCKED: p * q != n (extraction corrupted)")
    if len(vector["salt"]) != 96:  # 48-byte salt for the -PSS- variant
        raise SystemExit("BLOCKED: salt is not 48 bytes")
    for key, val in vector.items():
        if len(val) % 2 != 0:
            raise SystemExit(f"BLOCKED: field '{key}' has odd-length hex")
        int(val, 16)  # raises ValueError if not hex


def main() -> int:
    try:
        text = fetch_rfc_text()
    except Exception as exc:  # noqa: BLE001
        print(f"BLOCKED: could not fetch RFC 9474: {exc}", file=sys.stderr)
        return 1

    section = extract_section(text)
    fields = parse_fields(section)
    vector = build_vector(fields)
    validate(vector)

    out_path = Path(__file__).resolve().parents[1] / "tests" / "vectors" / "rfc9474_deterministic.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(vector, indent=2, sort_keys=True) + "\n")
    print(f"Wrote {out_path} ({int(vector['n'], 16).bit_length()}-bit n, {len(vector)} fields)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
