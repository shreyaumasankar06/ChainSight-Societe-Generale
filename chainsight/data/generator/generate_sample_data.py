#!/usr/bin/env python3
"""
Generate internally consistent ChainSight sample data.

Labels in dependency_labels.csv are derived from the same vulnerability,
license, and maintenance signals used to build the other files — not patched
in afterward.
"""

from __future__ import annotations

import csv
import json
import random
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

SEED = 42
NUM_APPS = 10
DEPS_PER_APP = 50
NUM_CVES = 200

# Target ground-truth distribution (500 rows total)
TARGET_COUNTS = {
    "vulnerable": 90,                  # ~18%
    "license_conflict": 60,            # ~12%
    "unmaintained": 75,                # ~15%
    "transitive_vulnerability": 50,    # ~10%
    "clean": 225,                      # ~45%
}

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "sample_data"

LICENSE_TYPES = [
    {"id": "MIT", "name": "MIT License", "risk_level": "low",
     "compatible_with": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unlicense", "LGPL-2.1", "LGPL-3.0", "MPL-2.0"]},
    {"id": "Apache-2.0", "name": "Apache License 2.0", "risk_level": "low",
     "compatible_with": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unlicense", "LGPL-2.1", "LGPL-3.0", "MPL-2.0"]},
    {"id": "BSD-3-Clause", "name": "BSD 3-Clause", "risk_level": "low",
     "compatible_with": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unlicense", "LGPL-2.1", "LGPL-3.0", "MPL-2.0"]},
    {"id": "ISC", "name": "ISC License", "risk_level": "low",
     "compatible_with": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unlicense", "LGPL-2.1", "LGPL-3.0", "MPL-2.0"]},
    {"id": "Unlicense", "name": "The Unlicense", "risk_level": "low",
     "compatible_with": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unlicense", "LGPL-2.1", "LGPL-3.0", "MPL-2.0"]},
    {"id": "MPL-2.0", "name": "Mozilla Public License 2.0", "risk_level": "medium",
     "compatible_with": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unlicense", "MPL-2.0", "LGPL-2.1", "LGPL-3.0"]},
    {"id": "LGPL-2.1", "name": "GNU LGPL v2.1", "risk_level": "medium",
     "compatible_with": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unlicense", "MPL-2.0", "LGPL-2.1", "LGPL-3.0"]},
    {"id": "LGPL-3.0", "name": "GNU LGPL v3.0", "risk_level": "medium",
     "compatible_with": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unlicense", "MPL-2.0", "LGPL-2.1", "LGPL-3.0"]},
    {"id": "EPL-1.0", "name": "Eclipse Public License 1.0", "risk_level": "medium",
     "compatible_with": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unlicense", "MPL-2.0", "EPL-1.0", "CDDL-1.0"]},
    {"id": "CDDL-1.0", "name": "CDDL 1.0", "risk_level": "medium",
     "compatible_with": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unlicense", "MPL-2.0", "EPL-1.0", "CDDL-1.0"]},
    {"id": "GPL-2.0", "name": "GNU GPL v2.0", "risk_level": "high",
     "compatible_with": ["GPL-2.0", "LGPL-2.1"]},
    {"id": "GPL-3.0", "name": "GNU GPL v3.0", "risk_level": "high",
     "compatible_with": ["GPL-3.0", "LGPL-3.0"]},
    {"id": "AGPL-3.0", "name": "GNU AGPL v3.0", "risk_level": "critical",
     "compatible_with": ["AGPL-3.0"]},
    {"id": "Proprietary", "name": "Proprietary / Commercial", "risk_level": "high",
     "compatible_with": ["Proprietary", "MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]},
    {"id": "Custom", "name": "Custom / Unknown License", "risk_level": "critical",
     "compatible_with": ["Custom"]},
]

# App policy: permissive baseline; GPL/AGPL/Custom flagged as conflicts for all apps.
POLICY_BASELINE = {"MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unlicense", "MPL-2.0",
                   "LGPL-2.1", "LGPL-3.0", "EPL-1.0", "CDDL-1.0", "Proprietary"}

LIBRARY_POOL = [
    "requests", "urllib3", "flask", "django", "fastapi", "sqlalchemy", "psycopg2",
    "redis-py", "celery", "boto3", "cryptography", "pyjwt", "numpy", "pandas",
    "scikit-learn", "tensorflow", "torch", "pillow", "lxml", "pyyaml", "jinja2",
    "werkzeug", "gunicorn", "uvicorn", "httpx", "aiohttp", "paramiko", "bcrypt",
    "passlib", "marshmallow", "pydantic", "click", "attrs", "certifi", "idna",
    "charset-normalizer", "six", "python-dateutil", "pytz", "markupsafe", "itsdangerous",
    "greenlet", "typing-extensions", "packaging", "setuptools", "wheel", "pip",
    "loguru", "structlog", "prometheus-client", "opentelemetry-api", "grpcio",
    "protobuf", "kafka-python", "confluent-kafka", "pika", "stripe", "twilio",
    "sendgrid", "authlib", "oauthlib", "defusedxml", "bleach", "tinycss2",
    "cssselect", "beautifulsoup4", "feedparser", "chardet", "toml", "tomli",
    "orjson", "ujson", "msgpack", "lz4", "zstandard", "cffi", "pycparser",
    "pyopenssl", "service-identity", "pyasn1", "rsa", "ecdsa", "dnspython",
    "netaddr", "ipaddress", "psutil", "watchdog", "filelock", "portalocker",
    "tenacity", "backoff", "ratelimit", "limits", "cachetools", "diskcache",
    "joblib", "dask", "xarray", "h5py", "openpyxl", "xlrd", "tabulate", "rich",
]

APP_TEMPLATES = [
    ("APP-001", "TradeFlow Core", "critical", "platform-trading@sg.com"),
    ("APP-002", "RiskEngine Pro", "critical", "risk-analytics@sg.com"),
    ("APP-003", "ClientPortal Web", "high", "digital-channels@sg.com"),
    ("APP-004", "Payments Gateway", "critical", "payments@sg.com"),
    ("APP-005", "Compliance Reporter", "high", "regulatory-tech@sg.com"),
    ("APP-006", "Market Data Hub", "high", "market-data@sg.com"),
    ("APP-007", "Internal Admin Console", "medium", "internal-tools@sg.com"),
    ("APP-008", "Document Archiver", "medium", "document-services@sg.com"),
    ("APP-009", "DevSandbox API", "low", "developer-experience@sg.com"),
    ("APP-010", "Legacy Batch Runner", "medium", "batch-ops@sg.com"),
]


@dataclass
class Dependency:
    app_id: str
    library_name: str
    version: str
    license_type: str
    dependency_type: str  # direct | transitive
    last_updated: date
    label_category: str  # planned ground-truth bucket


def _version_tuple(version: str) -> tuple[int, ...]:
    parts = []
    for segment in version.split("."):
        digits = "".join(ch for ch in segment if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _is_version_affected(version: str, affected_versions: list[str]) -> bool:
    if version in affected_versions:
        return True
    for spec in affected_versions:
        if spec.startswith("<="):
            return _version_tuple(version) <= _version_tuple(spec[2:])
        if spec.startswith("<"):
            return _version_tuple(version) < _version_tuple(spec[1:])
        if spec.startswith(">="):
            return _version_tuple(version) >= _version_tuple(spec[2:])
        if spec.startswith(">"):
            return _version_tuple(version) > _version_tuple(spec[1:])
        if spec.startswith("="):
            return version == spec[1:]
    return False


def _license_conflicts(policy: set[str], license_type: str) -> bool:
    return license_type not in policy


def _severity_from_cvss(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def _pick_version(rng: random.Random) -> str:
    return f"{rng.randint(0, 5)}.{rng.randint(0, 20)}.{rng.randint(0, 30)}"


def _recent_date(rng: random.Random) -> date:
    days_ago = rng.randint(30, 540)
    return date.today() - timedelta(days=days_ago)


def _stale_date(rng: random.Random) -> date:
    days_ago = rng.randint(900, 2200)
    return date.today() - timedelta(days=days_ago)


def build_license_rules() -> dict:
    return {
        "policy_baseline": sorted(POLICY_BASELINE),
        "licenses": LICENSE_TYPES,
        "compatibility_matrix": {
            lic["id"]: lic["compatible_with"] for lic in LICENSE_TYPES
        },
    }


def build_applications() -> list[dict]:
    return [
        {
            "id": app_id,
            "name": name,
            "business_criticality": criticality,
            "owner": owner,
        }
        for app_id, name, criticality, owner in APP_TEMPLATES
    ]


def allocate_label_slots(rng: random.Random) -> list[str]:
    slots: list[str] = []
    for category, count in TARGET_COUNTS.items():
        slots.extend([category] * count)
    rng.shuffle(slots)
    return slots


def _unique_library_versions(rng: random.Random, count: int) -> list[tuple[str, str]]:
    """Generate globally unique (library_name, version) pairs across the SBOM."""
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    while len(pairs) < count:
        library_name = rng.choice(LIBRARY_POOL)
        version = _pick_version(rng)
        key = (library_name, version)
        if key in seen:
            continue
        seen.add(key)
        pairs.append(key)
    return pairs


def build_dependencies(rng: random.Random, label_slots: list[str]) -> list[Dependency]:
    """Assign each dependency a planned label bucket, then set fields to match."""
    conflict_licenses = ["GPL-2.0", "GPL-3.0", "AGPL-3.0", "Custom"]
    safe_licenses = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Unlicense", "MPL-2.0"]
    deps: list[Dependency] = []
    slot_idx = 0
    unique_pairs = _unique_library_versions(rng, NUM_APPS * DEPS_PER_APP)
    pair_idx = 0

    for app_id, _, _, _ in APP_TEMPLATES:
        for i in range(DEPS_PER_APP):
            dependency_type = "direct" if i < 15 else "transitive"
            category = label_slots[slot_idx]
            slot_idx += 1

            library_name, version = unique_pairs[pair_idx]
            pair_idx += 1

            license_type = rng.choice(safe_licenses)
            last_updated = _recent_date(rng)

            if category == "vulnerable":
                dependency_type = "direct"
                license_type = rng.choice(safe_licenses)
                last_updated = _recent_date(rng)
            elif category == "transitive_vulnerability":
                dependency_type = "transitive"
                license_type = rng.choice(safe_licenses)
                last_updated = _recent_date(rng)
            elif category == "license_conflict":
                license_type = rng.choice(conflict_licenses)
                last_updated = _recent_date(rng)
            elif category == "unmaintained":
                license_type = rng.choice(safe_licenses)
                last_updated = _stale_date(rng)
            else:  # clean
                license_type = rng.choice(safe_licenses)
                last_updated = _recent_date(rng)

            deps.append(
                Dependency(
                    app_id=app_id,
                    library_name=library_name,
                    version=version,
                    license_type=license_type,
                    dependency_type=dependency_type,
                    last_updated=last_updated,
                    label_category=category,
                )
            )

    return deps


def build_vulnerability_db(rng: random.Random, deps: list[Dependency]) -> list[dict]:
    """Create CVEs for vulnerable + transitive-vulnerability deps; fill rest of catalog."""
    vuln_targets = [
        d for d in deps if d.label_category in ("vulnerable", "transitive_vulnerability")
    ]
    cves: list[dict] = []

    for idx, dep in enumerate(vuln_targets, start=1):
        # Exact version only — avoids range matches bleeding into other SBOM rows.
        affected_versions = [dep.version]
        cves.append({
            "cve_id": f"CVE-2024-{idx:05d}",
            "affected_library": dep.library_name,
            "affected_versions": affected_versions,
            "cvss_score": round(rng.uniform(4.0, 10.0), 1),
            "patch_available": rng.choice([True, True, True, False]),
        })

    # Decoy CVEs use fictional libraries so they never collide with SBOM rows.
    cve_num = len(cves) + 1
    while len(cves) < NUM_CVES:
        library = f"legacy-module-{cve_num}"
        version = _pick_version(rng)
        cves.append({
            "cve_id": f"CVE-2024-{cve_num:05d}",
            "affected_library": library,
            "affected_versions": [version, f"<={version}"],
            "cvss_score": round(rng.uniform(2.0, 9.8), 1),
            "patch_available": rng.choice([True, False]),
        })
        cve_num += 1

    return cves


def derive_label(
    dep: Dependency,
    cves: list[dict],
    stale_threshold_days: int = 730,
) -> dict:
    """Compute ground-truth label from generated fields and CVE catalog."""
    matching_cves = [
        cve for cve in cves
        if cve["affected_library"] == dep.library_name
        and _is_version_affected(dep.version, cve["affected_versions"])
    ]
    has_cve = len(matching_cves) > 0
    license_conflict = _license_conflicts(POLICY_BASELINE, dep.license_type)
    days_since_update = (date.today() - dep.last_updated).days
    unmaintained = days_since_update >= stale_threshold_days

    if has_cve and dep.dependency_type == "direct":
        top = max(matching_cves, key=lambda c: c["cvss_score"])
        severity = _severity_from_cvss(top["cvss_score"])
        patch_note = "Patch available." if top["patch_available"] else "No patch available yet."
        return {
            "app_id": dep.app_id,
            "library_name": dep.library_name,
            "version": dep.version,
            "risk_status": "at_risk",
            "risk_type": "vulnerable",
            "severity": severity,
            "explanation": (
                f"Direct dependency matches {top['cve_id']} (CVSS {top['cvss_score']}). {patch_note}"
            ),
        }

    if has_cve and dep.dependency_type == "transitive":
        top = max(matching_cves, key=lambda c: c["cvss_score"])
        severity = _severity_from_cvss(top["cvss_score"])
        return {
            "app_id": dep.app_id,
            "library_name": dep.library_name,
            "version": dep.version,
            "risk_status": "at_risk",
            "risk_type": "transitive_vulnerability",
            "severity": severity,
            "explanation": (
                f"Transitive dependency matches {top['cve_id']} (CVSS {top['cvss_score']}). "
                "Exposure inherited through dependency chain."
            ),
        }

    if license_conflict:
        return {
            "app_id": dep.app_id,
            "library_name": dep.library_name,
            "version": dep.version,
            "risk_status": "at_risk",
            "risk_type": "license_conflict",
            "severity": "high" if dep.license_type in ("GPL-2.0", "GPL-3.0", "Proprietary") else "critical",
            "explanation": (
                f"License '{dep.license_type}' is outside the organizational policy baseline "
                f"({', '.join(sorted(POLICY_BASELINE))})."
            ),
        }

    if unmaintained:
        return {
            "app_id": dep.app_id,
            "library_name": dep.library_name,
            "version": dep.version,
            "risk_status": "at_risk",
            "risk_type": "unmaintained",
            "severity": "medium" if days_since_update < 1500 else "high",
            "explanation": (
                f"No release activity in {days_since_update} days (last updated {dep.last_updated.isoformat()})."
            ),
        }

    return {
        "app_id": dep.app_id,
        "library_name": dep.library_name,
        "version": dep.version,
        "risk_status": "clean",
        "risk_type": "none",
        "severity": "none",
        "explanation": "No known vulnerability, license conflict, or maintenance concern.",
    }


def write_outputs(
    applications: list[dict],
    deps: list[Dependency],
    cves: list[dict],
    license_rules: dict,
    labels: list[dict],
) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_DIR / "applications.json", "w", encoding="utf-8") as f:
        json.dump(applications, f, indent=2)
        f.write("\n")

    with open(OUTPUT_DIR / "vulnerability_db.json", "w", encoding="utf-8") as f:
        json.dump(cves, f, indent=2)
        f.write("\n")

    with open(OUTPUT_DIR / "license_rules.json", "w", encoding="utf-8") as f:
        json.dump(license_rules, f, indent=2)
        f.write("\n")

    sbom_fields = [
        "app_id", "library_name", "version", "license_type",
        "dependency_type", "last_updated",
    ]
    with open(OUTPUT_DIR / "sbom_dependencies.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=sbom_fields)
        writer.writeheader()
        for dep in deps:
            writer.writerow({
                "app_id": dep.app_id,
                "library_name": dep.library_name,
                "version": dep.version,
                "license_type": dep.license_type,
                "dependency_type": dep.dependency_type,
                "last_updated": dep.last_updated.isoformat(),
            })

    label_fields = [
        "app_id", "library_name", "version",
        "risk_status", "risk_type", "severity", "explanation",
    ]
    with open(OUTPUT_DIR / "dependency_labels.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=label_fields)
        writer.writeheader()
        writer.writerows(labels)


def print_summary(labels: list[dict], deps: list[Dependency]) -> None:
    from collections import Counter

    planned = Counter(d.label_category for d in deps)
    actual = Counter(
        lbl["risk_type"] if lbl["risk_type"] != "none" else "clean"
        for lbl in labels
    )

    print("Generated sample data in:", OUTPUT_DIR)
    print("\nPlanned label buckets:")
    for key in TARGET_COUNTS:
        print(f"  {key}: {planned[key]} (target {TARGET_COUNTS[key]})")

    print("\nDerived label distribution:")
    for key in TARGET_COUNTS:
        print(f"  {key}: {actual[key]} (target {TARGET_COUNTS[key]})")

    mismatches = sum(1 for d, lbl in zip(deps, labels)
                     if (d.label_category if d.label_category != "clean" else "clean")
                     != (lbl["risk_type"] if lbl["risk_type"] != "none" else "clean"))
    print(f"\nPlanned vs derived mismatches: {mismatches}")
    print(f"Applications: {len(APP_TEMPLATES)}")
    print(f"SBOM rows: {len(deps)}")
    print(f"CVEs: {NUM_CVES}")


def main() -> None:
    rng = random.Random(SEED)

    license_rules = build_license_rules()
    applications = build_applications()
    label_slots = allocate_label_slots(rng)
    deps = build_dependencies(rng, label_slots)
    cves = build_vulnerability_db(rng, deps)
    labels = [derive_label(dep, cves) for dep in deps]

    write_outputs(applications, deps, cves, license_rules, labels)
    print_summary(labels, deps)


if __name__ == "__main__":
    main()
