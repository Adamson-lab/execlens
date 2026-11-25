"""Render the dashboard HTML (static snapshot with embedded data, or live shell)."""
from __future__ import annotations

import json
from pathlib import Path

TEMPLATE = Path(__file__).parent / "web" / "dashboard.html"


def render(payload: dict | None) -> str:
    html = TEMPLATE.read_text(encoding="utf-8")
    data = "null" if payload is None else json.dumps(payload).replace("</", "<\\/")
    return html.replace("__DATA__", data)
