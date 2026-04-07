import argparse
import json
import os

from modules.ai.investigation_agent import run_investigation_loop
from modules.asset_context import load_assets, get_asset_context
from modules.threat_hunting import hunt_anomalies
from modules.ai.agent_loop import determine_agent_decision
from modules.ai.analyst_agent import generate_ai_analysis
from modules.soar.soar_engine import generate_soar_output
from app.services.retrieval_index import TfidfAttackIndex
from app.services.embedder import AttackEmbedder
from app.services.mapper import AttackMapper
from app.services.triage import triage_alert
from app.services.response_engine import recommend_actions
from app.services.reporter import build_coverage_summary, build_attack_navigator_layer
from app.config import (
    INPUT_ALERTS_FILE,
    MAPPED_OUTPUT_FILE,
    COVERAGE_OUTPUT_FILE,
    NAVIGATOR_OUTPUT_FILE,
    TFIDF_VECTORIZER_FILE,
    TFIDF_MATRIX_FILE,
    TFIDF_TECHNIQUES_FILE,
    EMBEDDINGS_FILE,
)


def load_alerts(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def analyze_alerts(alerts):
    tfidf_index = TfidfAttackIndex()
    tfidf_index.load(
        TFIDF_VECTORIZER_FILE,
        TFIDF_MATRIX_FILE,
        TFIDF_TECHNIQUES_FILE,
    )

    embedder = AttackEmbedder(model_name="all-MiniLM-L6-v2")
    embedder.load(tfidf_index.techniques, EMBEDDINGS_FILE)

    asset_db = load_assets()

    mapper = AttackMapper(tfidf_index, embedder)

    all_results = []

    for i, alert in enumerate(alerts, start=1):
        triage = triage_alert(alert)
        mapping = mapper.map_alert(alert)
        result_matches = mapping["matches"]
        actions = recommend_actions(result_matches)

        confidence = (
            result_matches[0].get("confidence", 0) / 100
            if result_matches
            else 0
        )

        soar_result = generate_soar_output(
            alert=alert,
            mapped_techniques=result_matches,
            severity=triage["severity"],
            confidence=confidence,
        )

        ai_analysis = generate_ai_analysis(alert, result_matches, soar_result)

        agent_decision = determine_agent_decision(
            alert=alert,
            matches=result_matches,
            triage=triage,
            soar_result=soar_result,
            all_alerts=alerts,
        )

        destination_ip = alert.get("dest_ip") or alert.get("destination_ip")
        asset_context = get_asset_context(destination_ip, asset_db)
        if asset_context["criticality"] >= 8:
            agent_decision["decisions"].append("high_value_asset_targeted")

        investigation_state = run_investigation_loop(
            alert=alert,
            triage=triage,
            result_matches=result_matches,
            soar_result=soar_result,
            agent_decision=agent_decision,
            asset_context=asset_context,
        )

        result = {
            "alert_id": alert.get("alert_id", f"alert-{i}"),
            "alert": alert,
            "triage": triage,
            "query_used": mapping["query_used"],
            "matches": result_matches,
            "recommended_actions": actions,
            "soar": soar_result,
            "ai_analysis": ai_analysis,
            "agent_decision": agent_decision,
            "asset_context": asset_context,
            "investigation_state": investigation_state,
        }

        all_results.append(result)

        print("\n" + "=" * 70)
        print(f"ALERT ID: {result['alert_id']}")
        print(f"SEVERITY: {triage['severity']}")
        print(f"TRIAGE SCORE: {triage['triage_score']}")
        print(f"QUERY USED: {result['query_used']}")

        print("\nTOP MATCHES:")
        for m in result["matches"]:
            print(f"  {m['technique_id']} - {m['name']}")
            print(f"    TF-IDF Score: {m.get('tfidf_score', 0):.4f}")
            print(f"    Embedding Score: {m.get('embedding_score', 0):.4f}")
            print(f"    Rule Score: {m.get('rule_score', 0):.4f}")
            print(f"    Field Match Score: {m.get('field_match_score', 0):.4f}")
            print(f"    Final Score: {m.get('final_score', 0):.4f}")
            print(f"    Confidence: {m.get('confidence', 0)}%")
            print(f"    Tactics: {m.get('tactics', [])}")
            print(f"    Explanation: {' | '.join(m.get('explanation', []))}")

        print("\nRECOMMENDED ACTIONS:")
        for action in actions:
            print(f"  - {action}")

        print("\nSOAR OUTPUT:")
        print(f"  Incident Type: {soar_result['incident_type']}")
        print(f"  Urgency: {soar_result['urgency']}")
        print(f"  Playbook: {soar_result['playbook']}")
        print("  Actions:")
        for action in soar_result["recommended_actions"]:
            print(f"    - {action}")

        print("\nAI ANALYST OUTPUT:")
        print(f"  Why it matters: {ai_analysis['why_it_matters']}")
        print(f"  Risk: {ai_analysis['risk_summary']}")
        print("  Next Steps:")
        for step in ai_analysis["recommended_next_steps"]:
            print(f"    - {step}")
        print(f"  Context: {ai_analysis['context']}")

        print("\nAGENT LOOP OUTPUT:")
        print(f"  Agent State: {agent_decision['agent_state']}")
        print(
            f"  Top Technique: "
            f"{agent_decision['top_technique']['technique_id']} - "
            f"{agent_decision['top_technique']['technique_name']}"
        )
        print(
            f"  Final Disposition: "
            f"{agent_decision['final_disposition']['incident_type']} | "
            f"Urgency: {agent_decision['final_disposition']['urgency']} | "
            f"Confidence: {agent_decision['final_disposition']['confidence']}%"
        )

        print("  Decisions:")
        for decision in agent_decision["decisions"]:
            print(f"    - {decision}")

        print("  Enrichment Steps:")
        for step in agent_decision["enrichment_steps"]:
            print(f"    - {step}")

        print("  Enrichment Results:")
        enrichment_results = agent_decision.get("enrichment_results", {})
        for key, value in enrichment_results.items():
            print(f"    - {key}: {value}")

        print("  IOC Enrichment:")
        ioc = agent_decision.get("ioc_enrichment", {})
        print(f"    - source_ip_class: {ioc.get('source_ip_class', 'unknown')}")
        print(f"    - destination_ip_class: {ioc.get('destination_ip_class', 'unknown')}")
        print(f"    - ioc_findings: {ioc.get('ioc_findings', [])}")

        print("  Final Next Steps:")
        for step in agent_decision["recommended_next_steps"]:
            print(f"    - {step}")

        print("  Vulnerability Context:")
        print(f"    - {agent_decision.get('vulnerability_context')}")

        print("  Asset Context:")
        print(f"    - Asset Name: {asset_context['name']}")
        print(f"    - Criticality: {asset_context['criticality']}")
        print("\nINVESTIGATION AGENT OUTPUT:")
        print(f"  Final Severity: {investigation_state['severity']}")
        print(f"  Final Confidence: {investigation_state['confidence']:.2f}")
        print(f"  Stop Reason: {investigation_state['stop_reason']}")

        print("  Enrichments Run:")
        for step in investigation_state["enrichments_run"]:
            print(f"    - {step}")

        print("  Decisions:")
        for decision in investigation_state["decisions"]:
            print(f"    - {decision}")

        print("  Recommended Next Steps:")
        for step in investigation_state["recommended_next_steps"]:
            print(f"    - {step}")

        print("  Investigation Log:")
        for log in investigation_state["investigation_log"]:
            print(f"    - {log}")

    os.makedirs("output", exist_ok=True)

    with open(MAPPED_OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)

    coverage = build_coverage_summary(all_results)
    with open(COVERAGE_OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(coverage, f, indent=2)

    navigator = build_attack_navigator_layer(all_results)
    with open(NAVIGATOR_OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(navigator, f, indent=2)

    print("\n" + "=" * 70)
    print(f"[+] Results written to: {MAPPED_OUTPUT_FILE}")
    print(f"[+] Coverage summary written to: {COVERAGE_OUTPUT_FILE}")
    print(f"[+] ATT&CK Navigator layer written to: {NAVIGATOR_OUTPUT_FILE}")

    # =========================
    # THREAT HUNTING MODULE
    # =========================
    hunt_findings = hunt_anomalies(all_results)

    print("\n" + "=" * 70)
    print("THREAT HUNTING FINDINGS")

    if not hunt_findings:
        print("No hunt findings identified.")
    else:
        for i, finding in enumerate(hunt_findings, 1):
            print(f"{i}. [{finding['severity'].upper()}] {finding['type']}")
            print(f"   Reason: {finding['reason']}")

    # Save hunt results
    with open("output/threat_hunt_findings.json", "w") as f:
        json.dump(hunt_findings, f, indent=2)

    return all_results


def main():
    parser = argparse.ArgumentParser(
        description="Analyze normalized alerts and map them to MITRE ATT&CK techniques."
    )
    parser.add_argument(
        "--input",
        default=INPUT_ALERTS_FILE,
        help=f"Path to normalized alerts JSON file (default: {INPUT_ALERTS_FILE})",
    )
    args = parser.parse_args()

    alerts = load_alerts(args.input)

    print(f"[DEBUG] Loaded {len(alerts)} alerts from {args.input}")
    if alerts:
        print(f"[DEBUG] First alert ID: {alerts[0].get('alert_id', 'missing-alert-id')}")

    analyze_alerts(alerts)


if __name__ == "__main__":
    main()
