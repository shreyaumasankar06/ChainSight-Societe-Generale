"""Load ChainSight sample data into typed in-memory structures."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path

DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / "chainsight" / "data" / "sample_data"


@dataclass(frozen=True)
class Application:
    id: str
    name: str
    business_criticality: str
    owner: str


@dataclass(frozen=True)
class Dependency:
    app_id: str
    library_name: str
    version: str
    license_type: str
    dependency_type: str
    parent_library: str
    last_updated: date


def is_app_direct_parent(parent_library: str, app_id: str) -> bool:
    """True when parent_library means the dependency hangs off the app root."""
    return not parent_library or parent_library.strip() == "" or parent_library == app_id


@dataclass(frozen=True)
class Vulnerability:
    cve_id: str
    affected_library: str
    affected_versions: tuple[str, ...]
    cvss_score: float
    patch_available: bool


@dataclass(frozen=True)
class LicenseRule:
    id: str
    name: str
    risk_level: str
    compatible_with: tuple[str, ...]


@dataclass(frozen=True)
class DependencyLabel:
    app_id: str
    library_name: str
    version: str
    risk_status: str
    risk_type: str
    severity: str
    explanation: str


def _resolve_data_dir(data_dir: Path | str | None) -> Path:
    return Path(data_dir) if data_dir is not None else DEFAULT_DATA_DIR


def load_applications(data_dir: Path | str | None = None) -> dict[str, Application]:
    path = _resolve_data_dir(data_dir) / "applications.json"
    with open(path, encoding="utf-8") as f:
        records = json.load(f)

    return {
        record["id"]: Application(
            id=record["id"],
            name=record["name"],
            business_criticality=record["business_criticality"],
            owner=record["owner"],
        )
        for record in records
    }


def load_sbom(data_dir: Path | str | None = None) -> dict[str, list[Dependency]]:
    path = _resolve_data_dir(data_dir) / "sbom_dependencies.csv"
    grouped: dict[str, list[Dependency]] = {}

    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            dep = Dependency(
                app_id=row["app_id"],
                library_name=row["library_name"],
                version=row["version"],
                license_type=row["license_type"],
                dependency_type=row["dependency_type"],
                parent_library=row.get("parent_library", "").strip(),
                last_updated=date.fromisoformat(row["last_updated"]),
            )
            grouped.setdefault(dep.app_id, []).append(dep)

    return grouped


def load_vulnerabilities(
    data_dir: Path | str | None = None,
) -> dict[tuple[str, tuple[str, ...]], Vulnerability]:
    path = _resolve_data_dir(data_dir) / "vulnerability_db.json"
    with open(path, encoding="utf-8") as f:
        records = json.load(f)

    lookup: dict[tuple[str, tuple[str, ...]], Vulnerability] = {}
    for record in records:
        affected_versions = tuple(record["affected_versions"])
        vuln = Vulnerability(
            cve_id=record["cve_id"],
            affected_library=record["affected_library"],
            affected_versions=affected_versions,
            cvss_score=float(record["cvss_score"]),
            patch_available=bool(record["patch_available"]),
        )
        lookup[(vuln.affected_library, affected_versions)] = vuln

    return lookup


def load_license_rules(data_dir: Path | str | None = None) -> dict[str, LicenseRule]:
    path = _resolve_data_dir(data_dir) / "license_rules.json"
    with open(path, encoding="utf-8") as f:
        payload = json.load(f)

    return {
        record["id"]: LicenseRule(
            id=record["id"],
            name=record["name"],
            risk_level=record["risk_level"],
            compatible_with=tuple(record["compatible_with"]),
        )
        for record in payload["licenses"]
    }


def load_labels(
    data_dir: Path | str | None = None,
) -> dict[tuple[str, str, str], DependencyLabel]:
    path = _resolve_data_dir(data_dir) / "dependency_labels.csv"
    lookup: dict[tuple[str, str, str], DependencyLabel] = {}

    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            label = DependencyLabel(
                app_id=row["app_id"],
                library_name=row["library_name"],
                version=row["version"],
                risk_status=row["risk_status"],
                risk_type=row["risk_type"],
                severity=row["severity"],
                explanation=row["explanation"],
            )
            lookup[(label.app_id, label.library_name, label.version)] = label

    return lookup
