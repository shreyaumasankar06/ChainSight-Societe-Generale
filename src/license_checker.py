"""License risk lookup against license_rules.json."""

from __future__ import annotations

import json
from pathlib import Path

from src.data_loader import DEFAULT_DATA_DIR, LicenseRule, load_license_rules

LICENSE_SCORES = {
    "low": 0.1,
    "medium": 0.4,
    "high": 0.8,
    "critical": 1.0,
}


def load_policy_baseline(data_dir: Path | str | None = None) -> frozenset[str]:
    path = (Path(data_dir) if data_dir is not None else DEFAULT_DATA_DIR) / "license_rules.json"
    with open(path, encoding="utf-8") as f:
        payload = json.load(f)
    return frozenset(payload["policy_baseline"])


def get_license_risk_level(
    license_type: str,
    rules: dict[str, LicenseRule] | None = None,
) -> str:
    if rules is None:
        rules = load_license_rules()
    rule = rules.get(license_type)
    if rule is None:
        return "critical"
    return rule.risk_level


def license_risk_score(
    license_type: str,
    rules: dict[str, LicenseRule] | None = None,
) -> float:
    return LICENSE_SCORES.get(get_license_risk_level(license_type, rules), 0.0)


def is_license_conflict(
    license_type: str,
    policy_baseline: frozenset[str] | None = None,
) -> bool:
    if policy_baseline is None:
        policy_baseline = load_policy_baseline()
    return license_type not in policy_baseline
