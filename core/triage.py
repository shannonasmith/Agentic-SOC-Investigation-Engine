def build_alert_text(alert):
    parts = []

    for key in [
        "event_type",
        "details",
        "process_name",
        "command_line",
        "username",
        "target_user",
        "source_ip",
        "destination_ip",
    ]:
        if alert.get(key):
            parts.append(f"{key} {alert[key]}")

    return " ".join(parts).lower()


def triage_alert(alert):
    text = build_alert_text(alert)
    score = 0

    if "failed login" in text or "authentication_failure" in text:
        score += 25

    if "brute force" in text:
        score += 20

    if "powershell" in text:
        score += 20

    if "encodedcommand" in text or "encoded command" in text:
        score += 25

    if "psexec" in text or "wmic" in text:
        score += 30

    if "admin" in text or "administrator" in text:
        score += 10

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
