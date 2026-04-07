import json
from modules.vuln.risk_engine import compute_vuln_risk


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


if __name__ == "__main__":
    vulns = load_json("data/vulnerabilities.json")

    print("\n===== VULNERABILITY PRIORITIZATION =====")

    for v in vulns:
        score = compute_vuln_risk(v)

        print(
            f"{v['hostname']} | {v['cve']} | {v['title']} | Risk: {score}"
        )
