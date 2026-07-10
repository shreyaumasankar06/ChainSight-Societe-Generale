ChainSight is an automated SBOM (Software Bill of Materials) risk-scoring tool. It builds a full dependency graph across applications, resolves every transitive dependency chain, cross-references known vulnerabilities and license conflicts, and produces a ranked, explainable risk report per application.

Approach: Graph-Based Dependency Analysis. A true graph traversal guarantees 100% transitive resolution by construction, avoiding the calibration risk of an ML classifier trained on a small labeled dataset — while still supporting a strong, visual demo.

Features


Dependency graph — full App → Library → nested Library traversal (NetworkX)
100% transitive resolution — DFS/BFS guarantees no nested dependency is missed
Vulnerability cross-referencing — matches resolved libraries against a CVE database (CVE ID, CVSS score, patch availability)
License compatibility checking — flags conflicts against a license rules matrix
Composite risk scoring — combines vulnerability severity, license risk, and maintenance signals
Dashboard — app list, library search (reverse lookup), risk-colored graph visualization
Exportable reports — downloadable PDF/HTML risk report per application