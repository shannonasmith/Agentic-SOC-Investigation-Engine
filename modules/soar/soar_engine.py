from modules.soar.playbook_engine import execute_playbook
from modules.soar.action_mapper import simulate_action

def classify_incident(mapped_techniques):
    tactic_priority = {
        "lateral-movement": 5,
        "credential-access": 5,
        "privilege-escalation": 5,
        "execution": 4,
        "persistence": 3,
        "defense-evasion": 3,
        "discovery": 2,
        "collection": 2,
        "exfiltration": 4,
    }

    tactic_scores = {}

    for technique in mapped_techniques:
        tactics = technique.get("tactics", [])
        confidence = technique.get("confidence", 0)

        for t in tactics:
            score = tactic_priority.get(t, 1) * (confidence / 100)
            tactic_scores[t] = tactic_scores.get(t, 0) + score

    if not tactic_scores:
        return "unknown"

    best_tactic = max(tactic_scores, key=tactic_scores.get)

    tactic_map = {
        "lateral-movement": "lateral_movement",
        "credential-access": "credential_access",
        "privilege-escalation": "privilege_escalation",
        "execution": "execution",
        "persistence": "persistence",
        "defense-evasion": "defense_evasion",
        "discovery": "reconnaissance",
        "collection": "collection",
        "exfiltration": "exfiltration",
    }

    return tactic_map.get(best_tactic, "unknown")

def determine_urgency(severity, confidence):
    if severity == "high" and confidence > 0.8:
        return "critical"
    elif severity == "high":
        return "high"
    elif severity == "medium":
        return "medium"
    return "low"

def generate_soar_output(alert, mapped_techniques, severity, confidence):
    incident_type = classify_incident(mapped_techniques)
    urgency = determine_urgency(severity, confidence)
    playbook_name = f"{incident_type}_response"
    raw_actions = execute_playbook(playbook_name, alert)
    actions = [simulate_action(a, alert) for a in raw_actions]

    return {
        "incident_type": incident_type,
        "urgency": urgency,
        "recommended_actions": actions,
        "playbook": playbook_name,
    }
