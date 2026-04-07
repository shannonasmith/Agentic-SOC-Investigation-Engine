import json


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def evaluate(mapped_results, eval_set):
    results_by_id = {r["alert_id"]: r for r in mapped_results}

    total = 0
    top1_correct = 0
    top3_correct = 0

    for item in eval_set:
        alert_id = item["alert_id"]
        expected = set(item["expected_techniques"])

        if alert_id not in results_by_id:
            continue

        total += 1

        matches = results_by_id[alert_id]["matches"]

        top1 = matches[0]["technique_id"] if matches else None
        top3 = [m["technique_id"] for m in matches[:3]]

        if top1 in expected:
            top1_correct += 1

        if any(t in expected for t in top3):
            top3_correct += 1

    print("\n===== EVALUATION RESULTS =====")
    print(f"Total Alerts: {total}")

    if total > 0:
        print(f"Top-1 Accuracy: {top1_correct / total:.2f}")
        print(f"Top-3 Accuracy: {top3_correct / total:.2f}")
    else:
        print("No matching alerts found.")


if __name__ == "__main__":
    mapped = load_json("output/mapped_alerts.json")
    eval_set = load_json("data/eval_set.json")

    evaluate(mapped, eval_set)
