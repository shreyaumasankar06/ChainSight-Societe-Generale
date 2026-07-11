"""
Dashboard view-model builder.

Hand-off entry points for the UI layer (do not reimplement scoring here):
  - score_all_libraries()   -> per-(app, library, version) LibraryRiskScore
  - compute_all_app_scores() -> one float per app_id (max-weighted)

Graph explainability: use LibraryRiskScore.path (from VulnerabilityMatch.path)
for risk-colored graph edges and report chain text — not composite_score alone.

License checker swap (when her license_checker.py is ready):
  In src/scoring.py, change:
    from src.license_checker import license_risk_score
  to her module's equivalent. No other scoring changes required.
"""

from __future__ import annotations

from datetime import date

from src.data_loader import load_applications, load_sbom
from src.graph_builder import build_all_graphs
from src.scoring import LibraryRiskScore, compute_all_app_scores, score_all_libraries


def _severity_to_status(score: LibraryRiskScore) -> str:
    if score.cve_id:
        if score.dependency_type == "transitive":
            return "Transitive Vulnerability"
        return "Vulnerable"
    if score.license_component >= score.vuln_component and score.license_component >= score.staleness_component:
        return "License Conflict"
    if score.staleness_component >= score.vuln_component and score.staleness_component >= score.license_component:
        return "Unmaintained"
    return "At Risk"


def _remediation(score: LibraryRiskScore) -> str:
    if score.cve_id:
        patch = "Apply vendor patch." if score.patch_available else "No patch available — isolate or replace."
        chain = f" Chain: {' → '.join(score.path)}." if score.path else ""
        return f"{patch}{chain}"
    if score.license_component >= 20:
        return "Replace or relicense — dependency license is outside organizational policy."
    if score.staleness_component >= 15:
        return "Upgrade to a maintained release; no recent security or bugfix activity."
    return "Review dependency usage and apply recommended upgrades."


def _finding_from_score(score: LibraryRiskScore, license_type: str) -> dict:
    path_display = " → ".join(score.path) if score.path else None
    return {
        "library": score.library_name,
        "version": score.version,
        "license": license_type,
        "cve": score.cve_id or "None",
        "cvss": score.cvss_score or 0.0,
        "severity": score.predicted_severity.upper() if score.predicted_severity != "none" else "LOW",
        "status": _severity_to_status(score),
        "remediation": _remediation(score),
        "path": path_display,
        "path_steps": list(score.path) if score.path else [],
        "composite_score": score.composite_score,
        "dependency_type": score.dependency_type,
    }


def _graph_payload(
    app_id: str,
    graph,
    library_scores: dict[tuple[str, str, str], LibraryRiskScore],
) -> dict:
    """Serialize graph for risk-colored visualization (Step 5)."""
    nodes: list[dict] = []
    edges: list[dict] = []

    for node in graph.nodes:
        if isinstance(node, str):
            nodes.append({
                "id": node,
                "label": node,
                "kind": "app",
                "risk_score": 0,
                "severity": "none",
                "path": [],
            })
            continue

        attrs = graph.nodes[node]
        key = (app_id, attrs["library_name"], attrs["version"])
        score = library_scores.get(key)
        nodes.append({
            "id": f"{attrs['library_name']}@{attrs['version']}",
            "label": attrs["library_name"],
            "version": attrs["version"],
            "kind": attrs["dependency_type"],
            "risk_score": score.composite_score if score else 0,
            "severity": score.predicted_severity if score else "none",
            "path": list(score.path) if score and score.path else [],
        })

    for source, target in graph.edges:
        def _node_ref(n):
            if isinstance(n, str):
                return n
            a = graph.nodes[n]
            return f"{a['library_name']}@{a['version']}"

        edges.append({"from": _node_ref(source), "to": _node_ref(target)})

    return {"nodes": nodes, "edges": edges}


def build_dashboard_data() -> dict:
    applications = load_applications()
    sbom = load_sbom()
    library_scores = score_all_libraries()
    app_scores = compute_all_app_scores(library_scores, method="max")
    graphs = build_all_graphs(sbom)

    license_by_key: dict[tuple[str, str, str], str] = {}
    for app_id, deps in sbom.items():
        for dep in deps:
            license_by_key[(dep.app_id, dep.library_name, dep.version)] = dep.license_type

    apps: dict[str, dict] = {}
    for app_id, application in applications.items():
        deps = sbom.get(app_id, [])
        app_lib_scores = [
            library_scores[(app_id, d.library_name, d.version)]
            for d in deps
            if (app_id, d.library_name, d.version) in library_scores
        ]

        vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        license_issues = 0
        findings: list[dict] = []

        for score in app_lib_scores:
            key = (score.app_id, score.library_name, score.version)
            if score.predicted_status != "at_risk":
                continue
            findings.append(_finding_from_score(score, license_by_key[key]))

            if score.cve_id:
                bucket = score.predicted_severity if score.predicted_severity in vuln_counts else "low"
                vuln_counts[bucket] += 1
            if score.license_component >= 20:
                license_issues += 1

        findings.sort(key=lambda f: (-f["composite_score"], f["library"]))

        apps[app_id] = {
            "id": app_id,
            "name": application.name,
            "version": application.business_criticality.title(),
            "department": application.owner,
            "language": f"Criticality: {application.business_criticality}",
            "risk_score": app_scores[app_id],
            "vulnerabilities": vuln_counts,
            "license_issues": license_issues,
            "dependencies_count": len(deps),
            "last_scanned": date.today().isoformat(),
            "description": f"SBOM risk report for {application.name}.",
            "findings": findings,
            "graph": _graph_payload(app_id, graphs[app_id], library_scores),
        }

    libraries = _build_library_index(applications, sbom, library_scores)

    all_scores = list(library_scores.values())
    stats = {
        "total_apps": len(apps),
        "avg_risk_score": round(
            sum(app_scores.values()) / len(app_scores) if app_scores else 0, 1
        ),
        "critical_findings": sum(
            1 for s in all_scores if s.predicted_severity == "critical" and s.predicted_status == "at_risk"
        ),
    }

    return {"apps": apps, "libraries": libraries, "stats": stats}


def _build_library_index(applications, sbom, library_scores) -> dict[str, dict]:
    index: dict[str, dict] = {}

    for app_id, deps in sbom.items():
        app_name = applications[app_id].name
        for dep in deps:
            name = dep.library_name
            key = (app_id, dep.library_name, dep.version)
            score = library_scores[key]

            if name not in index:
                index[name] = {
                    "name": name,
                    "latest_version": dep.version,
                    "license": dep.license_type,
                    "cves": [],
                    "affected_apps": [],
                }

            entry = index[name]
            if dep.version > entry["latest_version"]:
                entry["latest_version"] = dep.version

            app_ref = {"id": app_id, "name": app_name, "version_used": dep.version}
            if app_ref not in entry["affected_apps"]:
                entry["affected_apps"].append(app_ref)

            if score.cve_id:
                cve_entry = {
                    "id": score.cve_id,
                    "cvss": score.cvss_score or 0.0,
                    "severity": score.predicted_severity.upper(),
                    "path": list(score.path) if score.path else [],
                }
                if not any(c["id"] == cve_entry["id"] for c in entry["cves"]):
                    entry["cves"].append(cve_entry)

    return index


_CACHE: dict | None = None


def get_dashboard_data() -> dict:
    global _CACHE
    if _CACHE is None:
        _CACHE = build_dashboard_data()
    return _CACHE
