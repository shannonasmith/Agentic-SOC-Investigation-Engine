import ipaddress


KNOWN_SUSPICIOUS_IPS = {
    "198.51.100.22": "known_malicious_test_feed",
    "203.0.113.99": "suspicious_external_source",
}


def classify_ip(ip):
    try:
        parsed = ipaddress.ip_address(ip)

        if parsed.is_private:
            return "internal"
        elif parsed.is_global:
            return "external"
        else:
            return "unknown"

    except Exception:
        return "unknown"


def enrich_iocs(alert):
    src_ip = alert.get("source_ip", "")
    dst_ip = alert.get("destination_ip", "")

    src_class = classify_ip(src_ip) if src_ip else "unknown"
    dst_class = classify_ip(dst_ip) if dst_ip else "unknown"

    findings = []

    if src_ip in KNOWN_SUSPICIOUS_IPS:
        findings.append(f"source_ip_match:{KNOWN_SUSPICIOUS_IPS[src_ip]}")

    if dst_ip in KNOWN_SUSPICIOUS_IPS:
        findings.append(f"destination_ip_match:{KNOWN_SUSPICIOUS_IPS[dst_ip]}")

    if src_class == "external":
        findings.append("external_source_ip")

    if dst_class == "external":
        findings.append("external_destination_ip")

    return {
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "source_ip_class": src_class,
        "destination_ip_class": dst_class,
        "ioc_findings": findings,
    }
