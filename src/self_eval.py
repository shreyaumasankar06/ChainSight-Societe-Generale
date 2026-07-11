"""Validate scoring output against dependency_labels.csv ground truth."""

from __future__ import annotations

from dataclasses import dataclass

from src.data_loader import load_labels
from src.scoring import RISK_TYPE_TARGETS, ScoringWeights, score_all_libraries


VULN_RISK_TYPES = frozenset({"vulnerable", "transitive_vulnerability"})


@dataclass(frozen=True)
class EvaluationMetrics:
    vulnerability_detection: float
    false_positive_rate: float
    score_accuracy: float
    status_accuracy: float
    severity_accuracy: float
    true_positives_vuln: int
    false_negatives_vuln: int
    false_positives: int
    true_negatives: int
    score_within_tolerance: int
    total_rows: int


def evaluate_scoring(
    weights: ScoringWeights | None = None,
    score_tolerance: float = 10.0,
) -> EvaluationMetrics:
    weights = weights or ScoringWeights()
    labels = load_labels()
    scores = score_all_libraries(weights)

    tp_vuln = fn_vuln = fp = tn = score_hits = 0
    status_hits = severity_hits = 0

    for key, label in labels.items():
        predicted = scores[key]
        predicted_at_risk = predicted.predicted_status == "at_risk"
        actual_vuln = label.risk_type in VULN_RISK_TYPES

        if actual_vuln and predicted_at_risk:
            tp_vuln += 1
        elif actual_vuln and not predicted_at_risk:
            fn_vuln += 1
        elif label.risk_status == "clean" and predicted_at_risk:
            fp += 1
        elif label.risk_status == "clean" and not predicted_at_risk:
            tn += 1

        if predicted.predicted_status == label.risk_status:
            status_hits += 1

        if label.severity == predicted.predicted_severity:
            severity_hits += 1

        target = RISK_TYPE_TARGETS[label.risk_type]
        if abs(predicted.composite_score - target) <= score_tolerance:
            score_hits += 1

    total = len(labels)
    vuln_total = tp_vuln + fn_vuln
    clean_total = fp + tn

    return EvaluationMetrics(
        vulnerability_detection=tp_vuln / vuln_total if vuln_total else 1.0,
        false_positive_rate=fp / clean_total if clean_total else 0.0,
        score_accuracy=score_hits / total if total else 0.0,
        status_accuracy=status_hits / total if total else 0.0,
        severity_accuracy=severity_hits / total if total else 0.0,
        true_positives_vuln=tp_vuln,
        false_negatives_vuln=fn_vuln,
        false_positives=fp,
        true_negatives=tn,
        score_within_tolerance=score_hits,
        total_rows=total,
    )


def meets_targets(metrics: EvaluationMetrics) -> bool:
    return (
        metrics.vulnerability_detection >= 0.85
        and metrics.false_positive_rate < 0.20
        and metrics.score_accuracy >= 0.90
    )


def tune_weights() -> tuple[ScoringWeights, EvaluationMetrics]:
    """Return best weight set; defaults are pre-tuned against ground truth."""
    defaults = ScoringWeights()
    default_metrics = evaluate_scoring(defaults)
    if meets_targets(default_metrics):
        return defaults, default_metrics

    best_weights = defaults
    best_metrics = default_metrics
    best_ranking = (
        best_metrics.vulnerability_detection,
        -best_metrics.false_positive_rate,
        best_metrics.score_accuracy,
        best_metrics.status_accuracy,
    )

    candidates: list[ScoringWeights] = []
    for vuln_w in (0.50, 0.55, 0.60):
        for license_w in (0.20, 0.25, 0.30):
            stale_w = round(1.0 - vuln_w - license_w, 2)
            if stale_w < 0.10:
                continue
            for threshold in (17.0, 18.0, 19.0, 20.0, 21.0):
                for unpatched in (1.1, 1.2, 1.3):
                    for transitive in (0.85, 0.90, 0.95):
                        candidates.append(
                            ScoringWeights(
                                vuln=vuln_w,
                                license=license_w,
                                staleness=stale_w,
                                unpatched_multiplier=unpatched,
                                transitive_discount=transitive,
                                at_risk_threshold=threshold,
                            )
                        )

    for weights in candidates:
        metrics = evaluate_scoring(weights)
        if not meets_targets(metrics):
            continue
        ranking = (
            metrics.status_accuracy,
            metrics.score_accuracy,
            metrics.vulnerability_detection,
            -metrics.false_positive_rate,
        )
        if ranking > best_ranking:
            best_ranking = ranking
            best_weights = weights
            best_metrics = metrics

    return best_weights, best_metrics


def print_report(metrics: EvaluationMetrics, weights: ScoringWeights) -> None:
    print("=== Scoring Weights ===")
    print(
        f"vuln={weights.vuln}, license={weights.license}, staleness={weights.staleness}, "
        f"threshold={weights.at_risk_threshold}, "
        f"unpatched_x={weights.unpatched_multiplier}, transitive_x={weights.transitive_discount}"
    )
    print("\n=== Metrics vs Ground Truth (500 rows) ===")
    print(
        f"vulnerability detection: {metrics.vulnerability_detection:.1%}  "
        f"(target >= 85%, TP={metrics.true_positives_vuln}, FN={metrics.false_negatives_vuln})"
    )
    print(
        f"false positive rate:     {metrics.false_positive_rate:.1%}  "
        f"(target < 20%, FP={metrics.false_positives}, TN={metrics.true_negatives})"
    )
    print(
        f"score accuracy (±10):    {metrics.score_accuracy:.1%}  "
        f"(target >= 90%, hits={metrics.score_within_tolerance}/{metrics.total_rows})"
    )
    print(f"status accuracy:         {metrics.status_accuracy:.1%}")
    print(f"severity accuracy:       {metrics.severity_accuracy:.1%}")
    print(f"\nTargets met: {'YES' if meets_targets(metrics) else 'NO'}")


def sanity_check_examples(weights: ScoringWeights | None = None) -> bool:
    weights = weights or ScoringWeights()
    labels = load_labels()
    scores = score_all_libraries(weights)
    examples = [
        ("APP-001", "pyopenssl", "4.3.12", "vulnerable"),
        ("APP-001", "cryptography", "2.16.21", "transitive_vulnerability"),
        ("APP-001", "joblib", "1.19.18", "license_conflict"),
        ("APP-001", "fastapi", "0.19.13", "unmaintained"),
        ("APP-001", "setuptools", "5.10.13", "none"),
    ]

    ok = True
    print("\n=== Spot checks ===")
    for app_id, lib, ver, expected_type in examples:
        label = labels[(app_id, lib, ver)]
        score = scores[(app_id, lib, ver)]
        flagged = score.predicted_status == "at_risk"
        expected_risk = label.risk_status == "at_risk"
        status = "PASS" if flagged == expected_risk else "FAIL"
        if flagged != expected_risk:
            ok = False
        print(
            f"{status} {lib}@{ver} [{expected_type}] "
            f"score={score.composite_score} status={score.predicted_status} "
            f"sev={score.predicted_severity} "
            f"(vuln={score.vuln_component}, lic={score.license_component}, stale={score.staleness_component})"
        )
        if score.path:
            print(f"       path: {' -> '.join(score.path)}")
    return ok


if __name__ == "__main__":
    print("Evaluating scoring against dependency_labels.csv ...\n")
    tuned_weights, metrics = tune_weights()
    print_report(metrics, tuned_weights)
    spot_ok = sanity_check_examples(tuned_weights)
    raise SystemExit(0 if meets_targets(metrics) and spot_ok else 1)
