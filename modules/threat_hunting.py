from collections import Counter, defaultdict
from typing import Any, Dict, List


HIGH_RISK_TECHNIQUES = {
    "T1078",
    "T1021",
    "T1059",
    "T1105",
    "T1003",
    "T1505.003",
}


def hunt_anomalies(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []

    technique_counter = Counter()
    ip_counter = Counter()

    for event in events:
        alert = event.get("alert", {})
        matches = event.get("matches", [])
        agent = event.get("agent_decision", {})

        src_ip = alert.get("src_ip") or alert.get("source_ip") or "unknown"
        ip_counter[src_ip] += 1

        if matches:
            top = matches[0]
            technique_id = top.get("technique_id")
            confidence = top.get("confidence", 0) / 100

            technique_counter[technique_id] += 1

            # 🔥 High confidence detection
            if confidence >= 0.9:
                findings.append({
                    "type": "high_confidence_detection",
                    "severity": "high",
                    "reason": f"{technique_id} detected with {confidence:.2f} confidence",
                    "technique_id": technique_id,
                })

            # 🔥 High-risk techniques
            if technique_id in HIGH_RISK_TECHNIQUES:
                findings.append({
                    "type": "high_risk_technique",
                    "severity": "high",
                    "reason": f"{technique_id} is a high-risk technique",
                })

        # 🔥 Vulnerability context
        vuln = agent.get("vulnerability_context")
        if isinstance(vuln, dict):
            if vuln.get("priority") == "critical":
                findings.append({
                    "type": "critical_vulnerability_exposure",
                    "severity": "high",
                    "reason": f"{vuln.get('top_cve')} on {vuln.get('asset')}",
                })

    # 🔥 Repeated IP activity
    for ip, count in ip_counter.items():
        if ip != "unknown" and count >= 2:
            findings.append({
                "type": "repeated_ip_activity",
                "severity": "medium",
                "reason": f"{ip} appeared in {count} alerts",
            })

    # 🔥 Repeated technique patterns
    for tech, count in technique_counter.items():
        if tech and count >= 2:
            findings.append({
                "type": "repeated_technique_pattern",
                "severity": "medium",
                "reason": f"{tech} appeared {count} times",
            })

    return findings
