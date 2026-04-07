from copy import deepcopy


MAX_STEPS = 5


def initialize_case_state(alert, triage, result_matches, soar_result):
    top_match = result_matches[0] if result_matches else {}

    return {
        "alert_id": alert.get("alert_id", "unknown"),
        "alert": deepcopy(alert),
        "severity": triage.get("severity", "low"),
        "triage_score": triage.get("triage_score", 0),
        "confidence": top_match.get("confidence", 0) / 100 if top_match else 0.0,
        "top_technique": {
            "technique_id": top_match.get("technique_id"),
            "technique_name": top_match.get("name"),
        },
        "incident_type": soar_result.get("incident_type", "unknown"),
        "playbook": soar_result.get("playbook", "unknown"),
        "evidence": [],
        "decisions": [],
        "actions_taken": [],
        "recommended_next_steps": [],
        "investigation_log": [],
        "enrichments_run": [],
        "stop_reason": None,
    }

def choose_next_action(state):

    # 🔥 PRIORITIZE RESPONSE IF CONFIDENT
    if state["confidence"] >= 0.90 and "recommend_response" not in state["actions_taken"]:
        return "recommend_response"

    if state["confidence"] >= 0.90 and "recommend_response" in state["actions_taken"]:
        return "stop"

    if "check_ioc" not in state["enrichments_run"]:
        return "check_ioc"

    if "check_vulnerability" not in state["enrichments_run"]:
        return "check_vulnerability"

    if "check_asset_criticality" not in state["enrichments_run"]:
        return "check_asset_criticality"

    if "correlate_entities" not in state["enrichments_run"]:
        return "correlate_entities"

    if "recommend_response" not in state["actions_taken"]:
        return "recommend_response"

    return "stop"


def run_ioc_check(state, agent_decision):
    ioc = agent_decision.get("ioc_enrichment", {})
    findings = ioc.get("ioc_findings", [])

    state["enrichments_run"].append("check_ioc")
    state["evidence"].append({"type": "ioc", "data": ioc})

    before = state["confidence"]

    if findings:
        state["confidence"] = min(1.0, state["confidence"] + 0.15)
        state["severity"] = "high" if state["severity"] in ["low", "medium"] else state["severity"]
        state["decisions"].append("ioc_enrichment_hit")

    state["investigation_log"].append({
        "step": "check_ioc",
        "before_confidence": before,
        "after_confidence": state["confidence"],
        "result": findings,
    })

    return state


def run_vulnerability_check(state, agent_decision):
    vuln = agent_decision.get("vulnerability_context", {})

    state["enrichments_run"].append("check_vulnerability")
    state["evidence"].append({"type": "vulnerability", "data": vuln})

    before = state["confidence"]

    if isinstance(vuln, dict) and vuln.get("priority") == "critical":
        state["confidence"] = min(1.0, state["confidence"] + 0.10)
        state["severity"] = "critical"
        state["decisions"].append("critical_vulnerability_exposure")

    elif isinstance(vuln, dict) and vuln.get("priority") == "high":
        state["confidence"] = min(1.0, state["confidence"] + 0.05)
        if state["severity"] == "medium":
            state["severity"] = "high"
        state["decisions"].append("high_vulnerability_exposure")

    state["investigation_log"].append({
        "step": "check_vulnerability",
        "before_confidence": before,
        "after_confidence": state["confidence"],
        "result": vuln,
    })

    return state


def run_asset_check(state, asset_context):
    state["enrichments_run"].append("check_asset_criticality")
    state["evidence"].append({"type": "asset_context", "data": asset_context})

    before = state["confidence"]

    if asset_context.get("criticality", 1) >= 8:
        state["confidence"] = min(1.0, state["confidence"] + 0.05)
        if state["severity"] != "critical":
            state["severity"] = "high"
        state["decisions"].append("high_value_asset_targeted")

    state["investigation_log"].append({
        "step": "check_asset_criticality",
        "before_confidence": before,
        "after_confidence": state["confidence"],
        "result": asset_context,
    })

    return state


def run_entity_correlation(state, agent_decision):
    enrichment = agent_decision.get("enrichment_results", {})
    related = []

    for value in enrichment.values():
        if isinstance(value, list):
            related.extend(value)

    state["enrichments_run"].append("correlate_entities")
    state["evidence"].append({"type": "correlation", "data": enrichment})

    before = state["confidence"]

    if related:
        state["confidence"] = min(1.0, state["confidence"] + 0.05)
        state["decisions"].append("entity_correlation_found")

    state["investigation_log"].append({
        "step": "correlate_entities",
        "before_confidence": before,
        "after_confidence": state["confidence"],
        "result_count": len(related),
    })

    return state

def run_response_recommendation(state, agent_decision):

    # 🔥 ADD THIS LINE RIGHT HERE
    print("DEBUG agent_decision keys:", agent_decision.keys())

    # Pull BOTH possible fields
    next_steps = (
        agent_decision.get("recommended_next_steps")
        or agent_decision.get("final_next_steps")
        or []
    )

    state["actions_taken"].append("recommend_response")
    state["recommended_next_steps"] = next_steps

    if next_steps:
        state["decisions"].append("response_recommended")

    state["investigation_log"].append({
        "step": "recommend_response",
        "before_confidence": state["confidence"],
        "after_confidence": state["confidence"],
        "result": next_steps,
    })

    return state


def finalize_case_state(state):
    if state["confidence"] >= 0.90:
        state["stop_reason"] = "confidence_threshold_met"
    elif len(state["enrichments_run"]) >= MAX_STEPS:
        state["stop_reason"] = "max_steps_reached"
    else:
        state["stop_reason"] = "workflow_completed"

    return state


def run_investigation_loop(alert, triage, result_matches, soar_result, agent_decision, asset_context):
    state = initialize_case_state(alert, triage, result_matches, soar_result)

    for _ in range(MAX_STEPS):
        action = choose_next_action(state)

        if action == "stop":
            break

        if action == "check_ioc":
            state = run_ioc_check(state, agent_decision)

        elif action == "check_vulnerability":
            state = run_vulnerability_check(state, agent_decision)

        elif action == "check_asset_criticality":
            state = run_asset_check(state, asset_context)

        elif action == "correlate_entities":
            state = run_entity_correlation(state, agent_decision)

        elif action == "recommend_response":
            state = run_response_recommendation(state, agent_decision)

        else:
            state["stop_reason"] = f"unknown_action:{action}"
            break

    state = finalize_case_state(state)
    return state
