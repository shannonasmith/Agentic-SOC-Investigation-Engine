TACTIC_ACTIONS = {
    "initial-access": [
        "Validate source IP reputation and geolocation",
        "Review authentication logs for spray or brute-force patterns",
        "Enforce MFA and reset affected credentials if warranted",
    ],
    "credential-access": [
        "Review account lockouts and authentication telemetry",
        "Reset or rotate impacted credentials",
        "Check for suspicious authentication success after repeated failures",
    ],
    "execution": [
        "Isolate affected host if malicious execution is confirmed",
        "Collect process tree, command-line, and parent-child telemetry",
        "Review script block logs, PowerShell logs, or EDR execution traces",
    ],
    "lateral-movement": [
        "Check remote service creation, SMB, WinRM, RDP, WMI, and PsExec activity",
        "Review east-west traffic and admin share access",
        "Scope additional hosts touched by the same account or source system",
    ],
    "persistence": [
        "Review scheduled tasks, services, autoruns, and startup locations",
        "Hunt for newly created accounts or remote management changes",
    ],
    "discovery": [
        "Review host and account enumeration activity",
        "Determine whether the behavior aligns with expected admin activity",
    ],
}


def recommend_actions(matches):
    actions = []
    seen = set()

    for match in matches:
        for tactic in match.get("tactics", []):
            for action in TACTIC_ACTIONS.get(tactic, []):
                if action not in seen:
                    seen.add(action)
                    actions.append(action)

    if not actions:
        actions.append(
            "Collect additional telemetry and validate whether the activity is benign or malicious"
        )

    return actions[:8]
