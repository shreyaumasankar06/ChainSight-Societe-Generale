"""Composite risk scoring for libraries and applications."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from src.data_loader import Dependency, load_sbom, load_vulnerabilities
from src.license_checker import license_risk_score, load_license_rules
from src.vulnerability_matcher import VulnerabilityMatch, lookup_vulnerability, match_all_vulnerabilities


@dataclass(frozen=True)
class ScoringWeights:
    vuln: float = 0.55
    license: float = 0.25
    staleness: float = 0.20
    unpatched_multiplier: float = 1.2
    transitive_discount: float = 0.9
    at_risk_threshold: float = 19.0
    stale_days: int = 730


@dataclass(frozen=True)
class LibraryRiskScore:
    app_id: str
    library_name: str
    version: str
    dependency_type: str
    composite_score: float
    vuln_component: float
    license_component: float
    staleness_component: float
    predicted_status: str
    predicted_severity: str
    cve_id: str | None = None
    cvss_score: float | None = None
    patch_available: bool | None = None
    path: tuple[str, ...] | None = None


SEVERITY_BANDS: tuple[tuple[float, str], ...] = (
    (80.0, "critical"),
    (60.0, "high"),
    (35.0, "medium"),
    (18.0, "low"),
)

SEVERITY_TARGETS = {
    "none": 12.0,
    "low": 23.0,
    "medium": 37.0,
    "high": 37.0,
    "critical": 43.0,
}

# Expected composite scores by ground-truth risk_type (used for ±10 score accuracy).
RISK_TYPE_TARGETS = {
    "none": 12.0,
    "license_conflict": 30.0,
    "unmaintained": 23.0,
    "transitive_vulnerability": 47.0,
    "vulnerable": 52.0,
}


def _days_since_update(last_updated: date, today: date | None = None) -> int:
    today = today or date.today()
    return max((today - last_updated).days, 0)


def compute_vuln_component(
    vuln_match: VulnerabilityMatch | None,
    weights: ScoringWeights,
) -> float:
    if vuln_match is None:
        return 0.0

    score = vuln_match.cvss_score / 10.0
    if not vuln_match.patch_available:
        score *= weights.unpatched_multiplier
    if vuln_match.dependency_type == "transitive":
        score *= weights.transitive_discount
    return min(score, 1.0)


def compute_staleness_component(days_since_update: int, weights: ScoringWeights) -> float:
    return min(days_since_update / weights.stale_days, 1.0)


def severity_from_score(score: float, weights: ScoringWeights) -> str:
    if score < weights.at_risk_threshold:
        return "none"
    for threshold, severity in SEVERITY_BANDS:
        if score >= threshold:
            return severity
    return "low"


def compute_library_risk(
    vuln_match: VulnerabilityMatch | None,
    license_type: str,
    days_since_update: int,
    weights: ScoringWeights | None = None,
    rules: dict | None = None,
) -> tuple[float, float, float, float]:
    """
    Return (composite_0_100, vuln_component, license_component, staleness_component).
    Components are the weighted contributions on the 0-100 scale.
    """
    weights = weights or ScoringWeights()
    rules = rules or load_license_rules()

    vuln_raw = compute_vuln_component(vuln_match, weights)
    license_raw = license_risk_score(license_type, rules)
    stale_raw = compute_staleness_component(days_since_update, weights)

    vuln_component = weights.vuln * vuln_raw * 100
    license_component = weights.license * license_raw * 100
    staleness_component = weights.staleness * stale_raw * 100
    composite = round(vuln_component + license_component + staleness_component, 1)
    return composite, round(vuln_component, 1), round(license_component, 1), round(staleness_component, 1)


def score_dependency(
    dep: Dependency,
    vuln_match: VulnerabilityMatch | None,
    weights: ScoringWeights | None = None,
    rules: dict | None = None,
    today: date | None = None,
) -> LibraryRiskScore:
    weights = weights or ScoringWeights()
    days = _days_since_update(dep.last_updated, today)
    composite, vuln_c, license_c, stale_c = compute_library_risk(
        vuln_match, dep.license_type, days, weights, rules
    )
    severity = severity_from_score(composite, weights)
    status = "at_risk" if composite >= weights.at_risk_threshold else "clean"

    return LibraryRiskScore(
        app_id=dep.app_id,
        library_name=dep.library_name,
        version=dep.version,
        dependency_type=dep.dependency_type,
        composite_score=composite,
        vuln_component=vuln_c,
        license_component=license_c,
        staleness_component=stale_c,
        predicted_status=status,
        predicted_severity=severity,
        cve_id=vuln_match.cve_id if vuln_match else None,
        cvss_score=vuln_match.cvss_score if vuln_match else None,
        patch_available=vuln_match.patch_available if vuln_match else None,
        path=vuln_match.path if vuln_match else None,
    )


def score_all_libraries(
    weights: ScoringWeights | None = None,
) -> dict[tuple[str, str, str], LibraryRiskScore]:
    """Score every SBOM row (500 dependencies)."""
    weights = weights or ScoringWeights()
    sbom = load_sbom()
    vuln_lookup = load_vulnerabilities()
    rules = load_license_rules()
    matches_by_app = match_all_vulnerabilities()

    match_index: dict[tuple[str, str, str], VulnerabilityMatch] = {}
    for app_id, matches in matches_by_app.items():
        for match in matches:
            match_index[(app_id, match.library_name, match.version)] = match

    scores: dict[tuple[str, str, str], LibraryRiskScore] = {}
    for app_id, deps in sbom.items():
        for dep in deps:
            key = (dep.app_id, dep.library_name, dep.version)
            vuln_match = match_index.get(key)
            if vuln_match is None:
                vuln = lookup_vulnerability(dep.library_name, dep.version, vuln_lookup)
                if vuln is not None:
                    vuln_match = VulnerabilityMatch(
                        app_id=dep.app_id,
                        library_name=dep.library_name,
                        version=dep.version,
                        dependency_type=dep.dependency_type,
                        cve_id=vuln.cve_id,
                        cvss_score=vuln.cvss_score,
                        patch_available=vuln.patch_available,
                        path=(),
                    )
            scores[key] = score_dependency(dep, vuln_match, weights, rules)

    return scores


def compute_app_score(
    app_id: str,
    library_scores: dict[tuple[str, str, str], LibraryRiskScore],
    method: str = "max",
) -> float:
    """
    Aggregate library scores to one app-level score.

    Default is max-weighted so one critical CVE is not diluted by clean libraries.
    """
    app_rows = [score for key, score in library_scores.items() if key[0] == app_id]
    if not app_rows:
        return 0.0
    values = [row.composite_score for row in app_rows]
    if method == "mean":
        return round(sum(values) / len(values), 1)
    return round(max(values), 1)


def compute_all_app_scores(
    library_scores: dict[tuple[str, str, str], LibraryRiskScore] | None = None,
    method: str = "max",
) -> dict[str, float]:
    if library_scores is None:
        library_scores = score_all_libraries()
    app_ids = {key[0] for key in library_scores}
    return {app_id: compute_app_score(app_id, library_scores, method) for app_id in sorted(app_ids)}
