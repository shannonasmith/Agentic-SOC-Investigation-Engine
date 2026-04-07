import json

from app.services.retrieval_index import TfidfAttackIndex
from app.services.embedder import AttackEmbedder
from app.services.mapper import AttackMapper
from app.config import (
    TFIDF_VECTORIZER_FILE,
    TFIDF_MATRIX_FILE,
    TFIDF_TECHNIQUES_FILE,
    EMBEDDINGS_FILE,
)


def load_dataset(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def expand_expected(expected_set):
    """
    Expand ATT&CK expectations to include parent/sub-technique relationships.

    Examples:
      T1003      -> also consider T1003.xxx family related
      T1003.001  -> also consider parent T1003
    """
    expanded = set(expected_set)

    for t in list(expected_set):
        if "." in t:
            parent = t.split(".")[0]
            expanded.add(parent)

    return expanded


def match_family(predicted, expected_set):
    """
    Return True if predicted technique matches an expected technique
    directly or via ATT&CK family hierarchy.

    Examples:
      predicted=T1003.001 matches expected=T1003
      predicted=T1003 matches expected=T1003.001
    """
    for expected in expected_set:
        if predicted == expected:
            return True

        if predicted.startswith(expected + "."):
            return True

        if expected.startswith(predicted + "."):
            return True

    return False


def evaluate(dataset):
    tfidf = TfidfAttackIndex()
    tfidf.load(
        TFIDF_VECTORIZER_FILE,
        TFIDF_MATRIX_FILE,
        TFIDF_TECHNIQUES_FILE,
    )

    embedder = AttackEmbedder()
    embedder.load(tfidf.techniques, EMBEDDINGS_FILE)

    mapper = AttackMapper(tfidf, embedder)

    total = len(dataset)
    top1_hits = 0
    top3_hits = 0
    top5_hits = 0

    detailed_results = []

    for item in dataset:
        alert = item["alert"]
        expected = set(item["expected_techniques"])
        expected = expand_expected(expected)

        result = mapper.map_alert(alert, top_k_tfidf=15, top_k_final=5)

        predicted = [m["technique_id"] for m in result["matches"]]

        top1 = predicted[:1]
        top3 = predicted[:3]
        top5 = predicted[:5]

        hit_top1 = any(match_family(t, expected) for t in top1)
        hit_top3 = any(match_family(t, expected) for t in top3)
        hit_top5 = any(match_family(t, expected) for t in top5)

        if hit_top1:
            top1_hits += 1
        if hit_top3:
            top3_hits += 1
        if hit_top5:
            top5_hits += 1

        detailed_results.append({
            "alert_id": item["alert_id"],
            "expected": sorted(list(expected)),
            "predicted": predicted,
            "top1_hit": hit_top1,
            "top3_hit": hit_top3,
            "top5_hit": hit_top5
        })

    summary = {
        "total_alerts": total,
        "top1_accuracy": round(top1_hits / total, 3),
        "top3_accuracy": round(top3_hits / total, 3),
        "top5_accuracy": round(top5_hits / total, 3),
    }

    return summary, detailed_results


def main():
    dataset = load_dataset("data/evaluation_set.json")

    summary, details = evaluate(dataset)

    print("\n=== EVALUATION RESULTS ===")
    print(f"Total Alerts: {summary['total_alerts']}")
    print(f"Top-1 Accuracy: {summary['top1_accuracy']}")
    print(f"Top-3 Accuracy: {summary['top3_accuracy']}")
    print(f"Top-5 Accuracy: {summary['top5_accuracy']}")

    with open("output/evaluation_report.json", "w", encoding="utf-8") as f:
        json.dump(
            {
                "summary": summary,
                "details": details
            },
            f,
            indent=2
        )

    print("\n[+] Evaluation report saved to output/evaluation_report.json")


if __name__ == "__main__":
    main()
