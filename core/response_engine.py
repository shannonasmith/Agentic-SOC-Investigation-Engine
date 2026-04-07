TACTIC_ACTIONS = {
    "credential-access": [
        "Review authentication logs for brute-force or password-spray behavior",
        "Check for successful logins after repeated failures",
        "Reset or rotate impacted credentials if malicious activity is confirmed"
    ],
    "execution": [
        "Review process execution telemetry and parent-child relationships",
        "Collect command-line evidence from the endpoint",
        "Check PowerShell or script execution logs for follow-on activity"
    ],
    "discovery": [
        "Review host and account enumeration activity",
        "Determine whether the behavior aligns with expected admin activity"
    ],
    "persistence": [
        "Inspect startup locations, autoruns, and login item changes",
        "Check whether new persistence mechanisms were created"
    ],
    "privilege-escalation": [
        "Investigate whether the user gained elevated rights unexpectedly",
        "Review process injection or token abuse telemetry"
    ],
    "reconnaissance": [
        "Review source IP behavior and scanning scope",
        "Determine whether external probing is broad or targeted"
    ]
}


def recommend_actions(matches):
    actions = []
    seen = set()

    for match in matches:
        for tactic in match.get("tactics", []):
            if tactic in TACTIC_ACTIONS:
                for action in TACTIC_ACTIONS[tactic]:
                    if action not in seen:
                        seen.add(action)
                        actions.append(action)

    if not actions:
        actions.append("Collect additional telemetry and validate whether the activity is benign or malicious")

    return actions[:8]
