import networkx as nx
from src.data_loader import load_applications, load_sbom
from src.graph_builder import build_all_graphs
from src.scoring import score_all_libraries

def lookup_library_apps(query: str, sbom=None, applications=None, library_scores=None) -> list[dict]:
    """
    Given a library name query, return every library and the apps that depend on it
    using nx.ancestors() on the app dependency graphs.
    Supports partial and case-insensitive matches.
    """
    query = query.strip().lower()
    if not query:
        return []

    if sbom is None:
        sbom = load_sbom()
    if applications is None:
        applications = load_applications()
    if library_scores is None:
        library_scores = score_all_libraries()

    graphs = build_all_graphs(sbom)
    results_map = {}

    for app_id, graph in graphs.items():
        app_name = applications[app_id].name if app_id in applications else app_id

        for node in graph.nodes:
            if not isinstance(node, tuple):
                # This is the root app_id string node
                continue

            # node is (app_id, lib_name, version)
            _, lib_name, version = node

            if query in lib_name.lower():
                # Use nx.ancestors to check if this app_id is an ancestor of the library node
                ancestors = nx.ancestors(graph, node)
                if app_id in ancestors:
                    # Retrieve node attributes
                    attrs = graph.nodes[node]
                    license_type = attrs.get("license_type", "Unknown")

                    if lib_name not in results_map:
                        results_map[lib_name] = {
                            "name": lib_name,
                            "latest_version": version,
                            "license": license_type,
                            "cves": [],
                            "affected_apps": []
                        }

                    entry = results_map[lib_name]
                    # Update latest version if this version is higher
                    if version > entry["latest_version"]:
                        entry["latest_version"] = version
                        entry["license"] = license_type

                    app_ref = {
                        "id": app_id,
                        "name": app_name,
                        "version_used": version,
                        "dependency_type": attrs.get("dependency_type", "direct")
                    }
                    if app_ref not in entry["affected_apps"]:
                        entry["affected_apps"].append(app_ref)

    # Populate CVEs for the matching libraries
    for lib_name, entry in results_map.items():
        cves = []
        for score in library_scores.values():
            if score.library_name == lib_name and score.cve_id:
                cve_entry = {
                    "id": score.cve_id,
                    "cvss": score.cvss_score or 0.0,
                    "severity": score.predicted_severity.upper(),
                    "path": list(score.path) if score.path else [],
                }
                if not any(c["id"] == cve_entry["id"] for c in cves):
                    cves.append(cve_entry)
        entry["cves"] = cves

    # Sort results alphabetically by library name
    sorted_results = list(results_map.values())
    sorted_results.sort(key=lambda x: x["name"])
    return sorted_results
