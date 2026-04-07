import json


def criticality_score(level):
    mapping = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    return mapping.get(str(level).lower(), 1)


def compute_vuln_risk(vuln):
    cvss = float(vuln.get("cvss", 0))
    exploit_available = 2 if vuln.get("exploit_available") else 0
    internet_exposed = 2 if vuln.get("internet_exposed") else 0
    asset_crit = criticality_score(vuln.get("asset_criticality"))

    return round(cvss + exploit_available + internet_exposed + asset_crit, 2)


def load_vulnerabilities(path="data/vulnerabilities.json"):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def find_vulns_for_asset(destination_ip, vulns):
    matches = []
    for vuln in vulns:
        if vuln.get("hostname") == destination_ip:
            item = dict(vuln)
            item["risk_score"] = compute_vuln_risk(vuln)
            matches.append(item)

    matches.sort(key=lambda x: x["risk_score"], reverse=True)
    return matches
