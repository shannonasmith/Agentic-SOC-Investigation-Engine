import json


def generate_ai_analysis(alert, matches, soar_result):
    """
    Simulated AI SOC analyst reasoning layer.
    (LLM-ready structure, but currently rule-based for portability)
    """

    top_match = matches[0] if matches else {}
    technique = top_match.get("name", "unknown")
    tactics = top_match.get("tactics", [])
    confidence = top_match.get("confidence", 0)

    event_type = alert.get("event_type", "unknown")
    user = alert.get("username", "unknown")
    src_ip = alert.get("source_ip", "unknown")
    dst_ip = alert.get("destination_ip", "unknown")

    # 🧠 WHY THIS MATTERS
    if "credential" in event_type:
        why = "This alert indicates potential credential access activity, which could allow an attacker to gain unauthorized access to systems."
    elif "execution" in event_type:
        why = "This alert indicates suspicious execution behavior, which may allow attackers to run arbitrary code on the system."
    elif "remote" in event_type:
        why = "This alert suggests lateral movement, where an attacker may be spreading across systems."
    else:
        why = "This alert indicates potentially suspicious behavior that should be investigated."

    # ⚠️ RISK SUMMARY
    risk = f"Technique: {technique} | Tactics: {', '.join(tactics)} | Confidence: {confidence}%"

    # 🧭 NEXT STEPS
    next_steps = soar_result.get("recommended_actions", [])

    # 🔗 CONTEXT SUMMARY
    context = f"User: {user} | Source IP: {src_ip} | Destination IP: {dst_ip}"

    return {
        "why_it_matters": why,
        "risk_summary": risk,
        "recommended_next_steps": next_steps,
        "context": context,
    }
