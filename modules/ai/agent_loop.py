from modules.ai.ioc_enrichment import enrich_iocs
from modules.vuln.risk_engine import load_vulnerabilities, find_vulns_for_asset


def summarize_top_match(matches):
    if not matches:
        return {
            "technique_id": "unknown",
            "technique_name": "unknown",
            "confidence": 0.0,
            "tactics": [],
        }

    top = matches[0]
    return {
        "technique_id": top.get("technique_id", "unknown"),
        "technique_name": top.get("name", "unknown"),
        "confidence": float(top.get("confidence", 0.0)),
        "tactics": top.get("tactics", []),
    }


def correlate_alerts(current_alert, all_alerts):
    src_ip = current_alert.get("source_ip")
    dst_ip = current_alert.get("destination_ip")
    username = current_alert.get("username")
    alert_id = current_alert.get("alert_id")

    related_by_src = []
    related_by_dst = []
    related_by_user = []

    for alert in all_alerts:
        if alert.get("alert_id") == alert_id:
            continue

        if src_ip and alert.get("source_ip") == src_ip:
            related_by_src.append(alert.get("alert_id"))

        if dst_ip and alert.get("destination_ip") == dst_ip:
            related_by_dst.append(alert.get("alert_id"))

        if username and alert.get("username") == username:
            related_by_user.append(alert.get("alert_id"))

    return {
        "related_by_source_ip": related_by_src,
        "related_by_destination_ip": related_by_dst,
        "related_by_username": related_by_user,
    }


def determine_agent_decision(alert, matches, triage, soar_result, all_alerts=None):
    top = summarize_top_match(matches)

    incident_type = soar_result.get("incident_type", "unknown")
    urgency = soar_result.get("urgency", "low")
    confidence = top["confidence"]
    tactics = top["tactics"]

    decisions = []
    enrichment_steps = []
    enrichment_results = {}
    recommended_next_steps = list(soar_result.get("recommended_actions", []))

    if confidence >= 90:
        decisions.append("high_confidence_detection")
    elif confidence >= 70:
        decisions.append("moderate_confidence_detection")
        enrichment_steps.append("correlate by source_ip")
        enrichment_steps.append("correlate by username")
    else:
        decisions.append("low_confidence_detection")
        enrichment_steps.append("expand investigation scope before containment")
        enrichment_steps.append("collect additional telemetry")
        enrichment_steps.append("review top 3 ATT&CK matches before action")

    if incident_type == "lateral_movement":
        decisions.append("potential_host_spread")
        enrichment_steps.append("correlate destination hosts for same user")
        enrichment_steps.append("review east-west movement patterns")

    if incident_type == "credential_access":
        decisions.append("credential_risk")
        enrichment_steps.append("review authentication success after failures")
        enrichment_steps.append("check account reuse across hosts")

    if incident_type == "defense_evasion":
        decisions.append("stealth_behavior")
        enrichment_steps.append("review tampering or logging impairment indicators")
        enrichment_steps.append("collect process lineage and script execution context")

    if "discovery" in tactics or incident_type == "reconnaissance":
        decisions.append("pre_attack_recon")
        enrichment_steps.append("look for follow-on auth, execution, or lateral activity")

    if "collection" in tactics or incident_type == "collection":
        decisions.append("possible_staging")
        enrichment_steps.append("review archive creation and outbound transfer attempts")

    if triage.get("severity") == "critical" and "escalate_to_ir" not in recommended_next_steps:
        recommended_next_steps.append("escalate_to_ir")

    if all_alerts is not None:
        enrichment_results = correlate_alerts(alert, all_alerts)

        if enrichment_results["related_by_username"]:
            decisions.append("user_activity_correlation_found")
        if enrichment_results["related_by_source_ip"]:
            decisions.append("source_ip_correlation_found")
        if enrichment_results["related_by_destination_ip"]:
            decisions.append("destination_ip_correlation_found")

    ioc_enrichment = enrich_iocs(alert)

    if ioc_enrichment["ioc_findings"]:
        decisions.append("ioc_enrichment_hit")

        if "external_source_ip" in ioc_enrichment["ioc_findings"]:
            decisions.append("external_threat_detected")
            recommended_next_steps.append("block_external_source_ip")

        if any("match" in f for f in ioc_enrichment["ioc_findings"]):
            decisions.append("known_threat_indicator")
            recommended_next_steps.append("escalate_to_ir")

    vuln_context = None
    try:
        destination_ip = alert.get("destination_ip")
        if destination_ip:
            vulns = load_vulnerabilities()
            asset_vulns = find_vulns_for_asset(destination_ip, vulns)

            if asset_vulns:
                top_vuln = asset_vulns[0]
                vuln_context = {
                    "asset": destination_ip,
                    "top_cve": top_vuln.get("cve"),
                    "title": top_vuln.get("title"),
                    "risk_score": top_vuln.get("risk_score", 0),
                    "priority": (
                        "critical" if top_vuln.get("risk_score", 0) >= 14
                        else "high" if top_vuln.get("risk_score", 0) >= 11
                        else "medium" if top_vuln.get("risk_score", 0) >= 8
                        else "low"
                    ),
                }

                if top_vuln.get("risk_score", 0) >= 14:
                    decisions.append("critical_asset_at_risk")
                    recommended_next_steps.append("prioritize_patch_and_isolation")
                elif top_vuln.get("risk_score", 0) >= 11:
                    decisions.append("high_risk_asset_at_risk")
                    recommended_next_steps.append("expedite_patch_window")
            else:
                vuln_context = {
                    "asset": destination_ip,
                    "top_cve": None,
                    "title": None,
                    "risk_score": 0,
                    "priority": "none",
                }
    except Exception as exc:
        vuln_context = {
            "asset": alert.get("destination_ip"),
            "error": str(exc),
        }

    return {
        "agent_state": "completed_assessment",
        "top_technique": top,
        "decisions": decisions,
        "enrichment_steps": enrichment_steps,
        "enrichment_results": enrichment_results,
        "ioc_enrichment": ioc_enrichment,
        "recommended_next_steps": recommended_next_steps,
        "vulnerability_context": vuln_context,
        "final_disposition": {
            "incident_type": incident_type,
            "urgency": urgency,
            "confidence": confidence,
        },
    }
