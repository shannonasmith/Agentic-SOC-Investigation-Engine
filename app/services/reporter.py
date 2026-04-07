from collections import Counter, defaultdict


def build_coverage_summary(results):
    technique_counter = Counter()
    tactic_counter = Counter()

    for result in results:
        for match in result.get("matches", []):
            technique_counter[match["technique_id"]] += 1
            for tactic in match.get("tactics", []):
                tactic_counter[tactic] += 1

    return {
        "total_alerts": len(results),
        "technique_frequency": dict(technique_counter.most_common()),
        "tactic_frequency": dict(tactic_counter.most_common()),
    }


def build_attack_navigator_layer(results, name="SOC Mapping Coverage"):
    score_by_technique = defaultdict(float)

    for result in results:
        for match in result.get("matches", []):
            score_by_technique[match["technique_id"]] = max(
                score_by_technique[match["technique_id"]],
                match["confidence"]
            )

    techniques = []
    for technique_id, score in score_by_technique.items():
        techniques.append({
            "techniqueID": technique_id,
            "score": round(score, 2),
            "comment": "Observed in SOC mapping pipeline",
        })

    return {
        "name": name,
        "version": "4.6",
        "domain": "enterprise-attack",
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#66b1ff", "#0056b3"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Mapped by alert pipeline", "color": "#66b1ff"}
        ],
    }
