"""Build NetworkX dependency graphs from SBOM data."""

from __future__ import annotations

import networkx as nx

from src.data_loader import Dependency, is_app_direct_parent, load_sbom

LibraryNode = tuple[str, str, str]  # (app_id, library_name, version)


def library_node_id(dep: Dependency) -> LibraryNode:
    return (dep.app_id, dep.library_name, dep.version)


def build_app_graph(app_id: str, dependencies: list[Dependency]) -> nx.DiGraph:
    """
    Build a directed graph for one application.

    Edges:
      - app_id -> direct library when parent_library is empty or app_id
      - parent_library -> transitive library otherwise

    Demo data is two levels deep only (App -> direct -> transitive).
    """
    graph: nx.DiGraph = nx.DiGraph()
    graph.add_node(app_id, kind="app")

    for dep in dependencies:
        node = library_node_id(dep)
        graph.add_node(
            node,
            kind="library",
            library_name=dep.library_name,
            version=dep.version,
            dependency_type=dep.dependency_type,
            license_type=dep.license_type,
            parent_library=dep.parent_library,
        )

    for dep in dependencies:
        node = library_node_id(dep)
        if dep.dependency_type == "direct" or is_app_direct_parent(dep.parent_library, app_id):
            graph.add_edge(app_id, node, kind="depends_on")
            continue

        parent_candidates = [
            library_node_id(d)
            for d in dependencies
            if d.library_name == dep.parent_library and d.dependency_type == "direct"
        ]
        if not parent_candidates:
            raise ValueError(
                f"{app_id}: transitive {dep.library_name}@{dep.version} "
                f"references unknown direct parent '{dep.parent_library}'"
            )
        graph.add_edge(parent_candidates[0], node, kind="depends_on")

    return graph


def build_all_graphs(
    sbom_by_app: dict[str, list[Dependency]] | None = None,
) -> dict[str, nx.DiGraph]:
    if sbom_by_app is None:
        sbom_by_app = load_sbom()
    return {app_id: build_app_graph(app_id, deps) for app_id, deps in sbom_by_app.items()}


def verify_full_resolution(
    sbom_by_app: dict[str, list[Dependency]] | None = None,
) -> bool:
    """
    Confirm every SBOM row is a graph node reachable from its app root.

    Also checks direct deps attach to the app and transitive deps attach to
    their declared parent_library (single edge, one level deep).
    """
    if sbom_by_app is None:
        sbom_by_app = load_sbom()

    ok = True
    total_nodes = 0

    for app_id, deps in sbom_by_app.items():
        graph = build_app_graph(app_id, deps)
        expected_nodes = {library_node_id(dep) for dep in deps}
        actual_nodes = {node for node in graph.nodes if isinstance(node, tuple)}
        total_nodes += len(expected_nodes)

        if expected_nodes != actual_nodes:
            missing = expected_nodes - actual_nodes
            extra = actual_nodes - expected_nodes
            print(f"FAIL {app_id}: node mismatch (missing={len(missing)}, extra={len(extra)})")
            ok = False

        reachable = nx.descendants(graph, app_id)
        unreachable = expected_nodes - reachable
        if unreachable:
            print(f"FAIL {app_id}: {len(unreachable)} libraries unreachable from app root")
            ok = False

        for dep in deps:
            node = library_node_id(dep)
            predecessors = list(graph.predecessors(node))

            if dep.dependency_type == "direct" or is_app_direct_parent(dep.parent_library, app_id):
                if predecessors != [app_id]:
                    print(
                        f"FAIL {app_id}: direct {dep.library_name} should have "
                        f"predecessor [{app_id}], got {predecessors}"
                    )
                    ok = False
            else:
                if len(predecessors) != 1:
                    print(
                        f"FAIL {app_id}: transitive {dep.library_name} expected 1 parent, "
                        f"got {len(predecessors)}"
                    )
                    ok = False
                    continue

                parent_node = predecessors[0]
                parent_name = graph.nodes[parent_node]["library_name"]
                if parent_name != dep.parent_library:
                    print(
                        f"FAIL {app_id}: {dep.library_name} parent edge is {parent_name}, "
                        f"expected {dep.parent_library}"
                    )
                    ok = False

                if graph.nodes[parent_node]["dependency_type"] != "direct":
                    print(
                        f"FAIL {app_id}: {dep.library_name} parent {dep.parent_library} "
                        "is not a direct dependency (graph is deeper than two levels)"
                    )
                    ok = False

    if ok:
        print(
            f"verify_full_resolution: PASS — {len(sbom_by_app)} apps, "
            f"{total_nodes} library nodes, all reachable"
        )
    else:
        print("verify_full_resolution: FAIL")

    return ok


def verify_chain_semantics(
    sbom_by_app: dict[str, list[Dependency]] | None = None,
) -> bool:
    """
    Confirm transitive rows form real 2-hop chains, not disguised direct edges.

    Checks:
      - every transitive row's parent_library names a direct dep in the same app
      - no transitive row uses app_id/empty as parent_library
      - graph path from app -> transitive is exactly 2 hops
      - graph edge parent matches CSV parent_library
    """
    if sbom_by_app is None:
        sbom_by_app = load_sbom()

    ok = True
    transitive_total = 0
    two_hop_total = 0

    for app_id, deps in sbom_by_app.items():
        graph = build_app_graph(app_id, deps)
        direct_names = {d.library_name for d in deps if d.dependency_type == "direct"}

        for dep in deps:
            if dep.dependency_type != "transitive":
                continue

            transitive_total += 1
            node = library_node_id(dep)

            if is_app_direct_parent(dep.parent_library, app_id):
                print(
                    f"FAIL {app_id}: transitive {dep.library_name} has "
                    f"app-level parent_library={dep.parent_library!r}"
                )
                ok = False

            if dep.parent_library not in direct_names:
                print(
                    f"FAIL {app_id}: transitive {dep.library_name} parent "
                    f"{dep.parent_library!r} is not a direct dependency"
                )
                ok = False

            path = nx.shortest_path(graph, app_id, node)
            depth = len(path) - 1
            if depth != 2:
                print(
                    f"FAIL {app_id}: transitive {dep.library_name} path depth is "
                    f"{depth}, expected 2 (path={path})"
                )
                ok = False
            else:
                two_hop_total += 1

            predecessors = list(graph.predecessors(node))
            if len(predecessors) != 1:
                print(
                    f"FAIL {app_id}: transitive {dep.library_name} expected 1 parent, "
                    f"got {len(predecessors)}"
                )
                ok = False
                continue

            parent_name = graph.nodes[predecessors[0]]["library_name"]
            if parent_name != dep.parent_library:
                print(
                    f"FAIL {app_id}: {dep.library_name} graph parent {parent_name} "
                    f"!= CSV parent_library {dep.parent_library}"
                )
                ok = False

    if ok:
        print(
            f"verify_chain_semantics: PASS — {transitive_total} transitive rows, "
            f"all {two_hop_total} are real 2-hop chains"
        )
    else:
        print("verify_chain_semantics: FAIL")

    return ok


if __name__ == "__main__":
    resolution_ok = verify_full_resolution()
    chains_ok = verify_chain_semantics()
    raise SystemExit(0 if resolution_ok and chains_ok else 1)
