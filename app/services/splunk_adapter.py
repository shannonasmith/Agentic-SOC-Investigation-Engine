import json
from typing import List, Dict


class SplunkAdapter:
    def __init__(self):
        pass

    def _infer_event_type(self, record: Dict) -> str:
        search_name = (record.get("search_name") or "").lower()
        signature = (record.get("signature") or "").lower()
        process_name = (record.get("process_name") or "").lower()
        command_line = (record.get("command_line") or "").lower()

        text = " ".join([search_name, signature, process_name, command_line])

        if "failed login" in text or "authentication" in text or "brute force" in text:
            return "authentication_failure"

        if "powershell" in text or "encodedcommand" in text or "encoded command" in text:
            return "process_execution"

        if "psexec" in text or "remote service" in text:
            return "remote_execution"

        if "mimikatz" in text or "lsass" in text or "credential dump" in text:
            return "credential_access"

        if "run key" in text or "registry" in text or "persistence" in text:
            return "persistence"

        return "generic_alert"

    def normalize_record(self, record: Dict, index: int) -> Dict:
        event_type = self._infer_event_type(record)

        details_parts = []
        if record.get("signature"):
            details_parts.append(record["signature"])
        if record.get("search_name"):
            details_parts.append(f"Splunk detection: {record['search_name']}")

        details = " | ".join(details_parts) if details_parts else "Splunk alert"

        normalized = {
            "alert_id": record.get("alert_id", f"splunk-{index}"),
            "event_type": event_type,
            "log_source": "splunk",
            "source_ip": record.get("src_ip", ""),
            "destination_ip": record.get("dest_ip", ""),
            "username": record.get("user", ""),
            "process_name": record.get("process_name", ""),
            "command_line": record.get("command_line", ""),
            "details": details,
            "severity": (record.get("severity", "medium") or "medium").lower(),
            "raw_time": record.get("_time", "")
        }

        return normalized

    def load_and_normalize(self, input_file: str) -> List[Dict]:
        with open(input_file, "r", encoding="utf-8") as f:
            records = json.load(f)

        normalized_alerts = []
        for i, record in enumerate(records, start=1):
            normalized_alerts.append(self.normalize_record(record, i))

        return normalized_alerts
