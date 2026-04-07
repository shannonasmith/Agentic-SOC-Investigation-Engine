"""
app/services/zeek_adapter.py

Production-style Zeek adapter for AI-Assisted SOC + MITRE ATT&CK Mapping Engine.

Purpose:
    Ingest Zeek network telemetry and convert conn.log / http.log records into
    normalized ATT&CK-ready alerts that can be consumed by the mapper.

Supported inputs:
    - Zeek ASCII logs with #separator / #fields headers
    - JSON line Zeek logs (compatibility path)

Supported log types:
    - conn.log
    - http.log
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


# =============================================================================
# CONFIG / CONSTANTS
# =============================================================================

ZEEK_UNSET = "-"
ZEEK_EMPTY = "(empty)"
DEFAULT_SOURCE = "zeek"
DEFAULT_PROVIDER = "zeek"
SUPPORTED_LOGS = {"conn.log", "http.log"}


# =============================================================================
# HELPERS
# =============================================================================

def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value in (None, "", ZEEK_UNSET, ZEEK_EMPTY):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, "", ZEEK_UNSET, ZEEK_EMPTY):
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _safe_str(value: Any, default: str = "") -> str:
    if value in (None, ZEEK_UNSET, ZEEK_EMPTY):
        return default
    return str(value).strip()


def _split_zeek_set(value: Any) -> List[str]:
    s = _safe_str(value)
    if not s:
        return []
    return [item.strip() for item in s.split(",") if item.strip()]


def _epoch_to_iso(ts: Any) -> str:
    try:
        epoch = float(ts)
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    except (TypeError, ValueError):
        return ""


def _normalize_path(path: Any) -> str:
    p = _safe_str(path)
    if not p:
        return "/"
    return p if p.startswith("/") else f"/{p}"


def _build_alert_id(source_type: str, uid: str, ts: str, src_ip: str, dst_ip: str) -> str:
    uid_part = uid or "no-uid"
    ts_part = ts or "no-ts"
    src_part = src_ip or "no-src"
    dst_part = dst_ip or "no-dst"
    return f"{source_type}:{uid_part}:{ts_part}:{src_part}:{dst_part}"


def _coalesce(*values: Any) -> str:
    for value in values:
        s = _safe_str(value)
        if s:
            return s
    return ""


# =============================================================================
# HEURISTIC / ENRICHMENT LOGIC
# =============================================================================

def _severity_from_conn(record: Dict[str, Any]) -> str:
    service = _safe_str(record.get("service")).lower()
    conn_state = _safe_str(record.get("conn_state")).upper()
    history = _safe_str(record.get("history")).upper()
    orig_bytes = _safe_int(record.get("orig_bytes"))
    resp_bytes = _safe_int(record.get("resp_bytes"))
    missed_bytes = _safe_int(record.get("missed_bytes"))
    duration = _safe_float(record.get("duration"))

    if missed_bytes > 0:
        return "medium"

    if conn_state in {"REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "SHR"}:
        return "medium"

    if service in {"ssh", "rdp", "smb", "winrm"} and duration > 0 and (orig_bytes + resp_bytes) > 0:
        return "medium"

    if "S" in history and "H" not in history and duration == 0:
        return "low"

    return "informational"


def _severity_from_http(record: Dict[str, Any]) -> str:
    method = _safe_str(record.get("method")).upper()
    status_code = _safe_int(record.get("status_code"))
    user_agent = _safe_str(record.get("user_agent")).lower()
    uri = _normalize_path(record.get("uri"))
    resp_mime_types = _split_zeek_set(record.get("resp_mime_types"))

    suspicious_exts = (".exe", ".dll", ".ps1", ".hta", ".js", ".vbs", ".bat", ".zip", ".iso")
    suspicious_paths = (
        "/admin",
        "/login",
        "/wp-admin",
        "/xmlrpc.php",
        "/shell",
        "/upload",
        "/api/token",
        "/powershell",
    )

    if any(uri.lower().endswith(ext) for ext in suspicious_exts):
        return "high"

    if any(token in uri.lower() for token in suspicious_paths):
        return "medium"

    if method in {"POST", "PUT"} and status_code in {200, 201, 204}:
        return "medium"

    if any(mt in {"application/x-dosexec", "application/x-msdownload"} for mt in resp_mime_types):
        return "high"

    if "python-requests" in user_agent or "curl" in user_agent or "wget" in user_agent:
        return "medium"

    return "informational"


def _conn_tags(record: Dict[str, Any]) -> List[str]:
    tags = ["network", "zeek", "conn"]

    proto = _safe_str(record.get("proto")).lower()
    service = _safe_str(record.get("service")).lower()
    conn_state = _safe_str(record.get("conn_state")).upper()

    if proto:
        tags.append(f"proto:{proto}")
    if service:
        tags.append(f"service:{service}")
    if conn_state:
        tags.append(f"conn_state:{conn_state}")

    if service in {"ssh", "rdp", "smb", "winrm"}:
        tags.append("remote-access")

    if conn_state in {"REJ", "RSTO", "RSTR", "RSTOS0", "S0"}:
        tags.append("failed-connection")

    return sorted(set(tags))


def _http_tags(record: Dict[str, Any]) -> List[str]:
    tags = ["network", "zeek", "http", "web"]

    method = _safe_str(record.get("method")).upper()
    uri = _normalize_path(record.get("uri")).lower()
    status_code = _safe_int(record.get("status_code"))

    if method:
        tags.append(f"http_method:{method}")
    if status_code:
        tags.append(f"http_status:{status_code}")

    if method == "POST":
        tags.append("http-post")

    if any(keyword in uri for keyword in ("login", "auth", "token", "admin", "upload", "shell", "cmd")):
        tags.append("suspicious-uri")

    if any(uri.endswith(ext) for ext in (".exe", ".dll", ".ps1", ".hta", ".js", ".vbs", ".zip", ".iso")):
        tags.append("payload-delivery")

    return sorted(set(tags))


def _build_conn_description(record: Dict[str, Any]) -> str:
    src_ip = _safe_str(record.get("id.orig_h"))
    src_port = _safe_str(record.get("id.orig_p"))
    dst_ip = _safe_str(record.get("id.resp_h"))
    dst_port = _safe_str(record.get("id.resp_p"))
    proto = _safe_str(record.get("proto"))
    service = _safe_str(record.get("service"))
    conn_state = _safe_str(record.get("conn_state"))
    duration = _safe_str(record.get("duration"))
    orig_bytes = _safe_str(record.get("orig_bytes"))
    resp_bytes = _safe_str(record.get("resp_bytes"))
    history = _safe_str(record.get("history"))

    parts = [
        "Zeek network connection event detected.",
        f"Source {src_ip}:{src_port} connected to destination {dst_ip}:{dst_port}.",
        f"Protocol={proto or 'unknown'}",
        f"service={service or 'unknown'}",
        f"conn_state={conn_state or 'unknown'}",
        f"duration={duration or '0'}",
        f"orig_bytes={orig_bytes or '0'}",
        f"resp_bytes={resp_bytes or '0'}",
        f"history={history or 'unknown'}.",
    ]

    if service in {"ssh", "rdp", "smb", "winrm"}:
        parts.append(
            "This reflects remote service communication and may indicate administrative access or lateral movement depending on context."
        )

    if conn_state in {"REJ", "RSTO", "RSTR", "RSTOS0", "S0"}:
        parts.append(
            "This reflects failed or reset connection behavior and may indicate blocked access, unsuccessful remote access, or scanning."
        )

    if proto.lower() == "tcp" and _safe_int(record.get("orig_bytes")) == 0 and _safe_int(record.get("resp_bytes")) == 0:
        parts.append(
            "Zero-byte TCP behavior may indicate incomplete handshakes, scanning, or connectivity testing."
        )

    return " ".join(parts)


def _build_http_description(record: Dict[str, Any]) -> str:
    src_ip = _safe_str(record.get("id.orig_h"))
    src_port = _safe_str(record.get("id.orig_p"))
    dst_ip = _safe_str(record.get("id.resp_h"))
    dst_port = _safe_str(record.get("id.resp_p"))
    method = _safe_str(record.get("method"))
    host = _safe_str(record.get("host"))
    uri = _normalize_path(record.get("uri"))
    referrer = _safe_str(record.get("referrer"))
    user_agent = _safe_str(record.get("user_agent"))
    status_code = _safe_str(record.get("status_code"))
    status_msg = _safe_str(record.get("status_msg"))
    mime_types = ", ".join(_split_zeek_set(record.get("resp_mime_types"))) or "unknown"

    fqdn_or_ip = host or dst_ip

    parts = [
        "Zeek HTTP transaction detected.",
        f"Client {src_ip}:{src_port} sent {method or 'UNKNOWN'} request to {fqdn_or_ip}:{dst_port}{uri}.",
        f"Server destination IP={dst_ip}.",
        f"HTTP status={status_code or 'unknown'} {status_msg or ''}".strip(),
        f"mime_types={mime_types}.",
    ]

    if referrer:
        parts.append(f"Referrer={referrer}.")

    if user_agent:
        parts.append(f"User-Agent={user_agent}.")

    parts.append(
        "This activity represents HTTP communication between a client and server and may include browsing, API interaction, or file transfer depending on context."
    )

    return " ".join(parts)


def _build_conn_title(record: Dict[str, Any]) -> str:
    service = _safe_str(record.get("service"))
    dst_ip = _safe_str(record.get("id.resp_h"))
    dst_port = _safe_str(record.get("id.resp_p"))
    if service:
        return f"Zeek connection event to {service} on {dst_ip}:{dst_port}"
    return f"Zeek connection event to {dst_ip}:{dst_port}"


def _build_http_title(record: Dict[str, Any]) -> str:
    method = _safe_str(record.get("method")) or "HTTP"
    host = _coalesce(record.get("host"), record.get("id.resp_h"), "unknown-host")
    uri = _normalize_path(record.get("uri"))
    return f"Zeek HTTP {method} request to {host}{uri}"


# =============================================================================
# ZEEK ASCII PARSER
# =============================================================================

@dataclass
class ZeekHeader:
    separator: str = "\t"
    set_separator: str = ","
    empty_field: str = ZEEK_EMPTY
    unset_field: str = ZEEK_UNSET
    path: str = ""
    open_time: str = ""
    fields: List[str] | None = None
    types: List[str] | None = None

    def __post_init__(self) -> None:
        if self.fields is None:
            self.fields = []
        if self.types is None:
            self.types = []


class ZeekAsciiParser:
    """
    Parses native Zeek ASCII logs with #fields / #types headers.
    """

    def parse_file(self, filepath: str | Path) -> List[Dict[str, Any]]:
        filepath = str(filepath)
        header = ZeekHeader()
        rows: List[Dict[str, Any]] = []

        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                line = raw_line.rstrip("\n")

                if not line:
                    continue

                if line.startswith("#"):
                    self._handle_header_line(header, line)
                    continue

                if not header.fields:
                    raise ValueError(
                        f"Zeek ASCII parse error: no #fields header found before data rows in {filepath}"
                    )

                values = line.split(header.separator)
                if len(values) != len(header.fields):
                    raise ValueError(
                        f"Zeek ASCII parse error: field count mismatch in {filepath}. "
                        f"Expected {len(header.fields)} fields, got {len(values)}."
                    )

                row = dict(zip(header.fields, values))
                rows.append(row)

        return rows

    def _handle_header_line(self, header: ZeekHeader, line: str) -> None:
        if line.startswith("#separator"):
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                raise ValueError(f"Malformed Zeek header line: {line}")
            raw_sep = parts[1].strip()
            header.separator = bytes(raw_sep, "utf-8").decode("unicode_escape")

        elif line.startswith("#set_separator"):
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                raise ValueError(f"Malformed Zeek header line: {line}")
            header.set_separator = parts[1].strip()

        elif line.startswith("#empty_field"):
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                raise ValueError(f"Malformed Zeek header line: {line}")
            header.empty_field = parts[1].strip()

        elif line.startswith("#unset_field"):
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                raise ValueError(f"Malformed Zeek header line: {line}")
            header.unset_field = parts[1].strip()

        elif line.startswith("#path"):
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                raise ValueError(f"Malformed Zeek header line: {line}")
            header.path = parts[1].strip()

        elif line.startswith("#open"):
            parts = line.split(maxsplit=1)
            if len(parts) != 2:
                raise ValueError(f"Malformed Zeek header line: {line}")
            header.open_time = parts[1].strip()

        elif line.startswith("#fields"):
            parts = line.split("\t")
            if len(parts) < 2:
                raise ValueError(f"Malformed Zeek #fields line: {line}")
            header.fields = parts[1:]

        elif line.startswith("#types"):
            parts = line.split("\t")
            if len(parts) < 2:
                raise ValueError(f"Malformed Zeek #types line: {line}")
            header.types = parts[1:]


# =============================================================================
# ADAPTER
# =============================================================================

class ZeekAdapter:
    """
    Converts Zeek records to normalized ATT&CK-ready alerts.
    """

    def __init__(self, provider: str = DEFAULT_PROVIDER, source: str = DEFAULT_SOURCE) -> None:
        self.provider = provider
        self.source = source
        self.ascii_parser = ZeekAsciiParser()

    def parse_zeek_file(self, filepath: str | Path) -> List[Dict[str, Any]]:
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"Zeek log file not found: {filepath}")

        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            first_nonempty = ""
            for line in f:
                if line.strip():
                    first_nonempty = line.strip()
                    break

        if not first_nonempty:
            return []

        if first_nonempty.startswith("#"):
            return self.ascii_parser.parse_file(filepath)

        rows = []
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.strip():
                    rows.append(json.loads(line))
        return rows

    def adapt_file(self, filepath: str | Path) -> List[Dict[str, Any]]:
        filepath = Path(filepath)
        filename = filepath.name

        if filename not in SUPPORTED_LOGS:
            raise ValueError(
                f"Unsupported Zeek log type: {filename}. Supported: {sorted(SUPPORTED_LOGS)}"
            )

        records = self.parse_zeek_file(filepath)

        if filename == "conn.log":
            return [self._convert_conn_record(r, filepath=str(filepath)) for r in records]

        if filename == "http.log":
            return [self._convert_http_record(r, filepath=str(filepath)) for r in records]

        return []

    def adapt_directory(self, log_dir: str | Path) -> List[Dict[str, Any]]:
        log_dir = Path(log_dir)
        if not log_dir.exists():
            raise FileNotFoundError(f"Zeek log directory not found: {log_dir}")

        alerts: List[Dict[str, Any]] = []

        for filename in ("conn.log", "http.log"):
            candidate = log_dir / filename
            if candidate.exists():
                alerts.extend(self.adapt_file(candidate))

        return alerts

    def _convert_conn_record(self, record: Dict[str, Any], filepath: str) -> Dict[str, Any]:
        event_time = _epoch_to_iso(record.get("ts"))
        src_ip = _safe_str(record.get("id.orig_h"))
        src_port = _safe_int(record.get("id.orig_p"))
        dst_ip = _safe_str(record.get("id.resp_h"))
        dst_port = _safe_int(record.get("id.resp_p"))
        uid = _safe_str(record.get("uid"))
        proto = _safe_str(record.get("proto")).lower()
        service = _safe_str(record.get("service")).lower()
        conn_state = _safe_str(record.get("conn_state")).upper()
        duration = _safe_float(record.get("duration"))
        orig_bytes = _safe_int(record.get("orig_bytes"))
        resp_bytes = _safe_int(record.get("resp_bytes"))
        history = _safe_str(record.get("history"))

        title = _build_conn_title(record)
        description = _build_conn_description(record)
        severity = _severity_from_conn(record)
        tags = _conn_tags(record)

        normalized = {
            "alert_id": _build_alert_id("zeek-conn", uid, event_time, src_ip, dst_ip),
            "source": self.source,
            "provider": self.provider,
            "log_type": "conn.log",
            "event_type": "network_connection",
            "event_category": "network",
            "title": title,
            "summary": description,
            "description": description,
            "severity": severity,
            "confidence": "medium",
            "status": "new",
            "timestamp": event_time,
            "ingest_source_path": filepath,
            "raw_message": json.dumps(record, ensure_ascii=False),
            "text_for_mapping": " ".join(
                [
                    title,
                    description,
                    f"src_ip={src_ip}",
                    f"src_port={src_port}",
                    f"dst_ip={dst_ip}",
                    f"dst_port={dst_port}",
                    f"proto={proto}",
                    f"service={service}",
                    f"conn_state={conn_state}",
                    f"history={history}",
                ]
            ),
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "transport": proto,
            "service": service,
            "network_direction": "unknown",
            "protocol_details": {
                "conn_state": conn_state,
                "history": history,
                "duration": duration,
                "orig_bytes": orig_bytes,
                "resp_bytes": resp_bytes,
                "orig_pkts": _safe_int(record.get("orig_pkts")),
                "resp_pkts": _safe_int(record.get("resp_pkts")),
                "local_orig": _safe_str(record.get("local_orig")),
                "local_resp": _safe_str(record.get("local_resp")),
                "missed_bytes": _safe_int(record.get("missed_bytes")),
            },
            "http": {},
            "dns": {},
            "file": {},
            "process": {},
            "host": {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
            },
            "user": {},
            "tags": tags,
            "data_source": {
                "product": "Zeek",
                "component": "conn.log",
                "category": "network_telemetry",
            },
            "evidence": {
                "uid": uid,
                "zeek_path": "conn",
            },
            "attack_hints": {
                "telemetry_family": "network",
                "possible_behaviors": self._conn_behavior_hints(record),
            },
            "raw_record": record,
        }

        return normalized

    def _convert_http_record(self, record: Dict[str, Any], filepath: str) -> Dict[str, Any]:
        event_time = _epoch_to_iso(record.get("ts"))
        src_ip = _safe_str(record.get("id.orig_h"))
        src_port = _safe_int(record.get("id.orig_p"))
        dst_ip = _safe_str(record.get("id.resp_h"))
        dst_port = _safe_int(record.get("id.resp_p"))
        uid = _safe_str(record.get("uid"))

        method = _safe_str(record.get("method")).upper()
        host = _safe_str(record.get("host"))
        uri = _normalize_path(record.get("uri"))
        user_agent = _safe_str(record.get("user_agent"))
        status_code = _safe_int(record.get("status_code"))
        status_msg = _safe_str(record.get("status_msg"))

        title = _build_http_title(record)
        description = _build_http_description(record)
        severity = _severity_from_http(record)
        tags = _http_tags(record)

        normalized = {
            "alert_id": _build_alert_id("zeek-http", uid, event_time, src_ip, dst_ip),
            "source": self.source,
            "provider": self.provider,
            "log_type": "http.log",
            "event_type": "http_request",
            "event_category": "network",
            "title": title,
            "summary": description,
            "description": description,
            "severity": severity,
            "confidence": "medium",
            "status": "new",
            "timestamp": event_time,
            "ingest_source_path": filepath,
            "raw_message": json.dumps(record, ensure_ascii=False),
            "text_for_mapping": " ".join(
                [
                    title,
                    description,
                    f"src_ip={src_ip}",
                    f"src_port={src_port}",
                    f"dst_ip={dst_ip}",
                    f"dst_port={dst_port}",
                    f"http_method={method}",
                    f"http_host={host}",
                    f"http_uri={uri}",
                    f"status_code={status_code}",
                    f"user_agent={user_agent}",
                ]
            ),
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "transport": "tcp",
            "service": "http",
            "network_direction": "unknown",
            "protocol_details": {},
            "http": {
                "method": method,
                "host": host,
                "uri": uri,
                "referrer": _safe_str(record.get("referrer")),
                "version": _safe_str(record.get("version")),
                "user_agent": user_agent,
                "request_body_len": _safe_int(record.get("request_body_len")),
                "response_body_len": _safe_int(record.get("response_body_len")),
                "status_code": status_code,
                "status_msg": status_msg,
                "info_code": _safe_int(record.get("info_code")),
                "info_msg": _safe_str(record.get("info_msg")),
                "username": _safe_str(record.get("username")),
                "password": _safe_str(record.get("password")),
                "proxied": _split_zeek_set(record.get("proxied")),
                "orig_fuids": _split_zeek_set(record.get("orig_fuids")),
                "orig_filenames": _split_zeek_set(record.get("orig_filenames")),
                "orig_mime_types": _split_zeek_set(record.get("orig_mime_types")),
                "resp_fuids": _split_zeek_set(record.get("resp_fuids")),
                "resp_filenames": _split_zeek_set(record.get("resp_filenames")),
                "resp_mime_types": _split_zeek_set(record.get("resp_mime_types")),
            },
            "dns": {},
            "file": {
                "resp_filenames": _split_zeek_set(record.get("resp_filenames")),
                "resp_mime_types": _split_zeek_set(record.get("resp_mime_types")),
            },
            "process": {},
            "host": {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
            },
            "user": {
                "username": _safe_str(record.get("username")),
            },
            "tags": tags,
            "data_source": {
                "product": "Zeek",
                "component": "http.log",
                "category": "network_telemetry",
            },
            "evidence": {
                "uid": uid,
                "zeek_path": "http",
            },
            "attack_hints": {
                "telemetry_family": "network",
                "possible_behaviors": self._http_behavior_hints(record),
            },
            "raw_record": record,
        }

        return normalized

    def _conn_behavior_hints(self, record: Dict[str, Any]) -> List[str]:
        hints: List[str] = []

        service = _safe_str(record.get("service")).lower()
        conn_state = _safe_str(record.get("conn_state")).upper()
        dst_port = _safe_int(record.get("id.resp_p"))

        if service in {"ssh", "rdp", "smb", "winrm"} or dst_port in {22, 3389, 445, 5985, 5986}:
            hints.append("remote service interaction")
            hints.append("possible lateral movement or remote administration")

        if conn_state in {"S0", "REJ", "RSTO", "RSTR", "RSTOS0"}:
            hints.append("failed connection attempts")
            hints.append("possible scanning, discovery, or blocked access")

        if dst_port in {80, 443, 8080, 8443}:
            hints.append("web communication")

        if dst_port in {53}:
            hints.append("dns-related traffic")

        return hints

    def _http_behavior_hints(self, record: Dict[str, Any]) -> List[str]:
        hints: List[str] = []

        method = _safe_str(record.get("method")).upper()
        uri = _normalize_path(record.get("uri")).lower()
        user_agent = _safe_str(record.get("user_agent")).lower()
        filenames = _split_zeek_set(record.get("resp_filenames"))

        if method == "POST":
            hints.append("possible upload or command dispatch")

        if any(keyword in uri for keyword in ("login", "auth", "token")):
            hints.append("authentication-related web request")

        if any(keyword in uri for keyword in ("upload", "shell", "cmd", "powershell")):
            hints.append("administrative or upload-oriented web request")

        if any(uri.endswith(ext) for ext in (".exe", ".dll", ".ps1", ".hta", ".zip", ".iso", ".js", ".vbs")):
            hints.append("possible payload or file transfer")

        if filenames:
            hints.append("file transfer observed")

        if "curl" in user_agent or "wget" in user_agent or "python-requests" in user_agent:
            hints.append("scripted http activity")

        return hints


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def load_zeek_alerts_from_path(path: str | Path) -> List[Dict[str, Any]]:
    adapter = ZeekAdapter()
    path = Path(path)

    if path.is_dir():
        return adapter.adapt_directory(path)

    return adapter.adapt_file(path)


# =============================================================================
# CLI / MANUAL TESTING
# =============================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Adapt Zeek logs into normalized ATT&CK-ready alerts.")
    parser.add_argument("path", help="Path to conn.log, http.log, or a directory containing them.")
    parser.add_argument("--output", help="Optional output JSON file path.")
    args = parser.parse_args()

    alerts = load_zeek_alerts_from_path(args.path)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=2, ensure_ascii=False)
        print(f"[+] Wrote {len(alerts)} normalized Zeek alerts to {out_path}")
    else:
        print(json.dumps(alerts[:3], indent=2, ensure_ascii=False))
        print(f"[+] Parsed {len(alerts)} total normalized alerts")
