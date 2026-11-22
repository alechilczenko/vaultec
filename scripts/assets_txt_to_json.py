#!/usr/bin/env python3
"""Convert a plain-text asset list into JSON for POST /assets/import (or UI Import).

Input (assets.txt): one target per line. Blank lines and # comments are ignored.
Optional trailing note after #. Optional type prefix (IP|Host|URL).

Examples:
  10.0.4.50
  admin-panel.corp.internal:8443
  https://api.corp.internal/v1/auth
  IP 192.168.1.10
  URL https://app.example.com  # primary
  Host mail.internal  # MX

Output shape (AssetBulkImport / UI import):
  {"assets": [{"name": "...", "type": "IP"|"Host"|"URL", "notes": "..."}]}
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path

ASSET_NAME_MAX = 255
NOTES_MAX = 2000
IMPORT_BATCH_MAX = 100

TYPE_ALIASES = {
    "ip": "IP",
    "host": "Host",
    "hostname": "Host",
    "url": "URL",
    "webapp": "URL",
    "web": "URL",
}

PREFIX_RE = re.compile(
    r"^(?P<type>ip|host|hostname|url|webapp|web)\s*[:\-]\s*(?P<rest>.+)$",
    re.IGNORECASE,
)
PREFIX_SPACE_RE = re.compile(
    r"^(?P<type>ip|host|hostname|url|webapp|web)\s+(?P<rest>\S.*)$",
    re.IGNORECASE,
)


def infer_type(identifier: str, explicit: str | None = None) -> str:
    if explicit:
        key = explicit.strip().lower()
        if key in TYPE_ALIASES:
            return TYPE_ALIASES[key]
        raise ValueError(f"unknown type '{explicit}' (use IP, Host, or URL)")

    value = identifier.strip()
    lower = value.lower()
    if lower.startswith("http://") or lower.startswith("https://"):
        return "URL"
    try:
        addr = ipaddress.ip_address(value.split("%", 1)[0])
        if isinstance(addr, ipaddress.IPv4Address):
            return "IP"
    except ValueError:
        pass
    # Match UI: dotted IPv4 without validating octets strictly via regex fallback
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", value):
        return "IP"
    return "Host"


def split_note(line: str) -> tuple[str, str | None]:
    """Split 'target # note' while keeping # inside URLs (fragment)."""
    if "#" not in line:
        return line.strip(), None
    # URL with scheme: treat # as fragment unless preceded by whitespace
    if re.match(r"https?://", line, re.IGNORECASE):
        m = re.search(r"\s+#\s*(.*)$", line)
        if not m:
            return line.strip(), None
        note = m.group(1).strip() or None
        name = line[: m.start()].strip()
        return name, note
    name, _, note = line.partition("#")
    name = name.strip()
    note = note.strip() or None
    return name, note


def parse_line(line: str, line_no: int) -> dict | None:
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None

    body, note = split_note(raw)
    if not body:
        return None

    explicit = None
    m = PREFIX_RE.match(body) or PREFIX_SPACE_RE.match(body)
    if m:
        explicit = m.group("type")
        body = m.group("rest").strip()

    name = body.strip()
    if not name:
        raise ValueError(f"line {line_no}: missing name")
    if len(name) > ASSET_NAME_MAX:
        raise ValueError(
            f"line {line_no}: name exceeds {ASSET_NAME_MAX} characters"
        )
    if note and len(note) > NOTES_MAX:
        raise ValueError(f"line {line_no}: notes exceed {NOTES_MAX} characters")

    return {
        "name": name,
        "type": infer_type(name, explicit),
        "notes": note,
    }


def parse_assets(text: str) -> list[dict]:
    assets: list[dict] = []
    seen: set[str] = set()
    for i, line in enumerate(text.splitlines(), start=1):
        item = parse_line(line, i)
        if item is None:
            continue
        key = item["name"].casefold()
        if key in seen:
            print(f"warning: line {i}: duplicate '{item['name']}' skipped", file=sys.stderr)
            continue
        seen.add(key)
        assets.append(item)
    return assets


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Convert assets.txt (IPs / hosts / URLs) to import JSON."
    )
    p.add_argument(
        "-i",
        "--input",
        type=Path,
        default=Path("assets.txt"),
        help="plain-text asset list (default: assets.txt)",
    )
    p.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("assets.json"),
        help="JSON output path (default: assets.json; '-' for stdout)",
    )
    p.add_argument(
        "--array",
        action="store_true",
        help="emit a bare JSON array instead of {\"assets\": [...]}",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.input.is_file():
        print(f"error: input not found: {args.input}", file=sys.stderr)
        return 1

    assets = parse_assets(args.input.read_text(encoding="utf-8"))
    if not assets:
        print("error: no assets parsed", file=sys.stderr)
        return 1

    if len(assets) > IMPORT_BATCH_MAX:
        print(
            f"warning: {len(assets)} assets > API batch max ({IMPORT_BATCH_MAX}); "
            "UI import splits automatically, API callers should chunk.",
            file=sys.stderr,
        )

    payload = assets if args.array else {"assets": assets}
    text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"

    if str(args.output) == "-":
        sys.stdout.write(text)
    else:
        args.output.write_text(text, encoding="utf-8")
        print(f"wrote {len(assets)} asset(s) → {args.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
