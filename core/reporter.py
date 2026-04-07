from collections import Counter, defaultdict
import json


def build_coverage_summary(results):
    technique_counts = Counter()
    tactic_counts = Counter()

    for alert in results:
        for match in alert["matches"]:
            technique_counts[match["technique_id"]] += 1

            for tactic in match.get("tactics", []):
                tactic_counts[tactic] += 1

    return {
        "total_alerts": len(results),
        "technique_frequency": dict(technique_counts.most_common()),
        "tactic_frequency": dict(tactic_counts.most_common())
    }


def build_attack_navigator_layer(results):
    technique_scores = defaultdict(float)

    for alert in results:
        for match in alert["matches"]:
            tid = match["technique_id"]
            score = match["confidence"]

            technique_scores[tid] = max(technique_scores[tid], score)

    techniques = []

    for tid, score in technique_scores.items():
        techniques.append({
            "techniqueID": tid,
            "score": round(score, 2),
            "comment": "Observed in SOC mapping pipeline"
        })

    return {
        "name": "SOC Mapping Coverage",
        "domain": "enterprise-attack",
        "version": "4.5",
        "techniques": techniques
    }
