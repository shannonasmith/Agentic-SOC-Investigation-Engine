#!/usr/bin/env python3
"""
pipeline/ingest_logs.py

Production-style ingestion entrypoint for normalized alert generation.

Supports:
- Splunk
- Zeek

Examples:
    python -m pipeline.ingest_logs --source splunk --path data/splunk/alerts.json
    python -m pipeline.ingest_logs --source zeek --path data/zeek/
"""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path
from typing import Any, Callable

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "output"

DEFAULT_OUTPUTS = {
    "splunk": OUTPUT_DIR / "normalized_alerts.json",
    "zeek": OUTPUT_DIR / "normalized_zeek_alerts.json",
}

ADAPTER_MODULES = {
    "splunk": "app.services.splunk_adapter",
    "zeek": "app.services.zeek_adapter",
}

ADAPTER_FUNCTION_CANDIDATES = {
    "splunk": [
        "normalize_splunk_alerts",
        "process_splunk_alerts",
        "parse_splunk_alerts",
        "run_splunk_adapter",
        "ingest_splunk_logs",
        "load_and_normalize",
        "main",
    ],
    "zeek": [
        "load_zeek_alerts_from_path",
        "normalize_zeek_logs",
        "process_zeek_logs",
        "parse_zeek_logs",
        "run_zeek_adapter",
        "ingest_zeek_logs",
        "load_and_normalize",
        "main",
    ],
}


class IngestError(Exception):
    pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ingest logs into normalized alert JSON")
    parser.add_argument(
        "--source",
        required=True,
        choices=["splunk", "zeek"],
        help="Ingestion source",
    )
    parser.add_argument(
        "--path",
        required=True,
        help="Path to input file or directory",
    )
    parser.add_argument(
        "--output",
        required=False,
        help="Optional output JSON path",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    return parser.parse_args()


def ensure_project_root_on_path() -> None:
    root = str(PROJECT_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


def import_adapter(source: str) -> Any:
    module_name = ADAPTER_MODULES[source]
    try:
        return importlib.import_module(module_name)
    except Exception as exc:
        raise IngestError(f"Failed to import adapter module '{module_name}': {exc}") from exc


def resolve_entrypoint(source: str, module: Any) -> Callable[..., Any]:
    for fn_name in ADAPTER_FUNCTION_CANDIDATES[source]:
        fn = getattr(module, fn_name, None)
        if callable(fn):
            return fn

    available = [name for name in dir(module) if callable(getattr(module, name, None))]
    raise IngestError(
        f"No supported adapter function found for source '{source}'. "
        f"Tried {ADAPTER_FUNCTION_CANDIDATES[source]}. "
        f"Available callables: {available}"
    )


def call_adapter(fn: Callable[..., Any], input_path: Path) -> Any:
    attempts = [
        lambda: fn(str(input_path)),
        lambda: fn(input_path),
        lambda: fn(path=str(input_path)),
        lambda: fn(input_path=str(input_path)),
        lambda: fn(log_path=str(input_path)),
        lambda: fn(source_path=str(input_path)),
        lambda: fn(),
    ]

    last_type_error = None

    for attempt in attempts:
        try:
            return attempt()
        except TypeError as exc:
            last_type_error = exc
            continue
        except Exception as exc:
            raise IngestError(f"Adapter execution failed: {exc}") from exc

    raise IngestError(
        f"Could not call adapter function '{fn.__name__}' with supported signatures. "
        f"Last TypeError: {last_type_error}"
    )


def load_json_file(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        raise IngestError(f"Failed to load JSON file '{path}': {exc}") from exc


def normalize_adapter_result(result: Any) -> list[dict]:
    if result is None:
        raise IngestError(
            "Adapter returned None. It must return a list of normalized alerts, "
            "a dict containing alerts, or a JSON file path."
        )

    if isinstance(result, list):
        if not all(isinstance(item, dict) for item in result):
            raise IngestError("Adapter returned a list, but not all items are dicts.")
        return result

    if isinstance(result, dict):
        for key in ("alerts", "normalized_alerts", "records", "events", "data"):
            value = result.get(key)
            if isinstance(value, list) and all(isinstance(item, dict) for item in value):
                return value
        raise IngestError(
            "Adapter returned a dict, but no supported list key was found. "
            "Expected one of: alerts, normalized_alerts, records, events, data."
        )

    if isinstance(result, (str, Path)):
        json_path = Path(result)
        if not json_path.exists():
            raise IngestError(f"Adapter returned path '{json_path}', but file does not exist.")
        data = load_json_file(json_path)
        return normalize_adapter_result(data)

    raise IngestError(f"Unsupported adapter return type: {type(result).__name__}")


def write_output(records: list[dict], output_path: Path, pretty: bool) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output_path.open("w", encoding="utf-8") as f:
            if pretty:
                json.dump(records, f, indent=2, ensure_ascii=False)
            else:
                json.dump(records, f, ensure_ascii=False)
    except Exception as exc:
        raise IngestError(f"Failed to write output file '{output_path}': {exc}") from exc


def validate_input(source: str, input_path: Path) -> None:
    if not input_path.exists():
        raise IngestError(f"Input path does not exist: {input_path}")

    if source == "zeek" and not input_path.is_dir():
        raise IngestError(f"Zeek expects a directory path, got: {input_path}")


def main() -> int:
    ensure_project_root_on_path()
    args = parse_args()

    source = args.source
    input_path = Path(args.path).resolve()
    output_path = Path(args.output).resolve() if args.output else DEFAULT_OUTPUTS[source]

    try:
        validate_input(source, input_path)

        module = import_adapter(source)
        entrypoint = resolve_entrypoint(source, module)
        result = call_adapter(entrypoint, input_path)
        records = normalize_adapter_result(result)
        write_output(records, output_path, args.pretty)

        print("=" * 80)
        print("INGESTION COMPLETE")
        print("=" * 80)
        print(f"Source      : {source}")
        print(f"Input path  : {input_path}")
        print(f"Output path : {output_path}")
        print(f"Record count: {len(records)}")
        if records:
            print(f"Sample keys : {sorted(records[0].keys())}")
        print("=" * 80)
        return 0

    except IngestError as exc:
        print("=" * 80, file=sys.stderr)
        print("INGESTION FAILED", file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        print(str(exc), file=sys.stderr)
        print("=" * 80, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
