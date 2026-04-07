#!/usr/bin/env python3
"""Lightweight local evidence viewer for Ancilis demos.

Serves evidence data from a DuckDB evidence store over HTTP.
No external dependencies beyond ancilis[mcp] and standard library.

Usage:
    python examples/demo/local_server.py --db-path ~/.ancilis/demo/evidence.duckdb
    python examples/demo/local_server.py --db-path ... --port 8100

Endpoints:
    GET /         → dashboard.html (static)
    GET /health   → {"status": "ok"}
    GET /v1/evidence         → list of evidence records (limit 500)
    GET /v1/evidence/summary → summary stats (decisions, control pass rates, chain)
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.WARNING)

STATIC_DIR = Path(__file__).parent / "static"
DASHBOARD_HTML = STATIC_DIR / "dashboard.html"
DEFAULT_PORT = 8100


def _load_store(db_path: str) -> Any:
    """Return an EvidenceStore pointed at an existing DuckDB file."""
    from ancilis.config import load_config
    from ancilis.evidence.store import EvidenceStore

    config_path = Path(__file__).with_name("ancilis.yaml")
    config = load_config(path=config_path)
    return EvidenceStore(config, db_path=db_path, in_memory=False)


def _record_to_dict(record: Any) -> dict[str, Any]:
    """Convert an EvidenceRecord dataclass to a JSON-serialisable dict."""
    if dataclasses.is_dataclass(record):
        return dataclasses.asdict(record)
    return dict(record)


class EvidenceHandler(BaseHTTPRequestHandler):
    """Simple JSON + static-file request handler."""

    store: Any  # set on class by main()

    def log_message(self, fmt: str, *args: Any) -> None:  # silence access log
        pass

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, path: Path) -> None:
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?")[0]
        try:
            if path == "/":
                if DASHBOARD_HTML.exists():
                    self._send_html(DASHBOARD_HTML)
                else:
                    self._send_json({"error": "dashboard.html not found"}, 404)
            elif path == "/health":
                self._send_json({"status": "ok"})
            elif path == "/v1/evidence/summary":
                summary = self.store.get_summary()
                self._send_json(summary)
            elif path == "/v1/evidence":
                records = self.store.get_records(limit=500)
                self._send_json([_record_to_dict(r) for r in records])
            else:
                self._send_json({"error": "not found"}, 404)
        except Exception as exc:  # noqa: BLE001
            self._send_json({"error": str(exc)}, 500)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.end_headers()


def main() -> None:
    parser = argparse.ArgumentParser(description="Ancilis local evidence viewer")
    parser.add_argument("--db-path", required=True, help="Path to DuckDB evidence file")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to bind (default: 8100)")
    args = parser.parse_args()

    db_path = os.path.abspath(args.db_path)
    if not Path(db_path).exists():
        print(f"Error: evidence DB not found at {db_path}", file=sys.stderr)
        sys.exit(1)

    EvidenceHandler.store = _load_store(db_path)

    server = HTTPServer(("127.0.0.1", args.port), EvidenceHandler)
    print(f"Evidence viewer: http://127.0.0.1:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
