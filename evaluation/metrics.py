# evaluation/metrics.py
import config  # LangSmith tracing — must be first
from evaluation.labeled_alerts import LABELED_ALERTS
from agents.triage import run_triage
from agents.analysis import run_analysis
from alerts.schemas import AlertSchema
from datetime import datetime, timezone


def run_eval():
    total = len(LABELED_ALERTS)
    severity_correct = 0
    attack_type_correct = 0

    wrong_cases = []
    confidence_on_wrong = []
    confidence_on_right = []

    for case in LABELED_ALERTS:
        alert = AlertSchema(
            timestamp=datetime.now(timezone.utc),
            source_ip=case["source_ip"],       # ← was hardcoded "10.0.0.1", now matches raw_log
            destination_ip="192.168.1.10",       # internal target — fine to keep generic
            hostname="eval-host",
            event_type=case["event_type"],
            severity=case["true_severity"],
            port=443,
            protocol="TCP",
            raw_log=case["raw_log"],
        )

        # Replicates LangGraph's automatic state-merging behavior manually,
        # since this script calls agents directly without a graph running.
        state = {"alert": alert.model_dump(mode="json"), "errors": []}

        triage_result = run_triage(state)
        state.update(triage_result)

        if state.get("triage_escalate"):
            analysis_result = run_analysis(state)
            state.update(analysis_result)

        predicted_severity = state.get("triage_severity")
        predicted_confidence = state.get("triage_confidence", 0.0)
        predicted_attack_type = state.get("attack_type", "N/A")

        is_severity_right = predicted_severity == case["true_severity"]
        is_attack_type_right = (
            case["true_attack_type"].split()[0].lower() in predicted_attack_type.lower()
        )

        if is_severity_right:
            severity_correct += 1
            confidence_on_right.append(predicted_confidence)
        else:
            confidence_on_wrong.append(predicted_confidence)
            wrong_cases.append({
                "id": case["id"],
                "log": case["raw_log"][:60],
                "expected": case["true_severity"],
                "got": predicted_severity,
                "confidence": predicted_confidence,
                "notes": case["notes"],
            })

        if is_attack_type_right:
            attack_type_correct += 1

    print(f"\n{'='*60}")
    print(f"SEVERITY accuracy:    {severity_correct}/{total} ({severity_correct/total*100:.1f}%)")
    print(f"ATTACK TYPE accuracy: {attack_type_correct}/{total} ({attack_type_correct/total*100:.1f}%)")

    if confidence_on_right:
        avg_right = sum(confidence_on_right) / len(confidence_on_right)
        print(f"\nAvg confidence when CORRECT: {avg_right:.2f}")
    if confidence_on_wrong:
        avg_wrong = sum(confidence_on_wrong) / len(confidence_on_wrong)
        print(f"Avg confidence when WRONG:   {avg_wrong:.2f}")
        print("^ If this is close to or higher than the 'correct' number,")
        print("  confidence_score isn't a reliable signal for HITL routing yet.")

    if wrong_cases:
        print(f"\n{'='*60}\nWRONG CASES:")
        for w in wrong_cases:
            print(f"  [{w['id']}] expected={w['expected']} got={w['got']} "
                  f"conf={w['confidence']:.2f}\n    log: {w['log']}...\n    note: {w['notes']}")


if __name__ == "__main__":
    run_eval()