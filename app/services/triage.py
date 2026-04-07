def build_alert_text(alert):
    parts = []

    for key in [
        "event_type",
        "log_source",
        "details",
        "command_line",
        "process_name",
        "parent_process",
        "username",
        "target_user",
        "source_ip",
        "destination_ip",
        "notes",
    ]:
        if alert.get(key):
            parts.append(f"{key} {alert[key]}")

    return " ".join(parts).lower()


def triage_alert(alert):
    text = build_alert_text(alert)
    score = 0

    if alert.get("severity", "").lower() in {"high", "critical"}:
        score += 30

    if "failed login" in text or "brute force" in text:
        score += 20

    if "powershell" in text or "encodedcommand" in text or "encoded command" in text:
        score += 25

    if "lsass" in text or "credential dump" in text:
        score += 30

    if "lateral movement" in text or "psexec" in text or "wmic" in text:
        score += 25

    if score >= 70:
        severity = "critical"
    elif score >= 45:
        severity = "high"
    elif score >= 20:
        severity = "medium"
    else:
        severity = "low"

    return {
        "triage_score": score,
        "severity": severity
    }
