# Dashboard integration handoff

Scoring and graph analysis are wired into the Flask dashboard via `app/dashboard_data.py`.
You should not need to touch scoring internals — use the two entry points below.

## Entry points (use these)

```python
from src.scoring import score_all_libraries, compute_all_app_scores

library_scores = score_all_libraries()
# key: (app_id, library_name, version) -> LibraryRiskScore

app_scores = compute_all_app_scores(library_scores, method="max")
# key: app_id -> float (0–100)
```

The dashboard adapter (`get_dashboard_data()`) calls both once at startup and caches the result.

## Explainability: build graph viz and reports around `path`

Each `LibraryRiskScore` with a CVE carries `path` — a tuple of hop labels from the matcher, e.g.:

```
('APP-001', 'itsdangerous@5.3.23', 'cryptography@2.16.21')
```

Use this for:

- **Risk-colored graph** — highlight the exact chain, not just the leaf node score
- **Report text** — findings already expose `path` and `path_steps` in templates
- **Full graph JSON** — `app.graph` on each risk report (`nodes`, `edges`, per-node `severity` / `risk_score`)

Do not rely on `composite_score` alone for transitive explainability.

## License checker swap (when your version is ready)

Temporary inline lookup lives in `src/license_checker.py` (used by `src/scoring.py`).

When your rule engine is done, **only change this import** in `src/scoring.py`:

```python
# from src.license_checker import license_risk_score
from src.your_license_checker import license_risk_score  # same signature
```

No other changes needed in `scoring.py`, `dashboard_data.py`, or templates.

## Template hooks (Step 5)

| Template | Data |
|---|---|
| `app_list.html` | `apps`, `stats` |
| `risk_report.html` | `app.findings[]`, `app.graph`, `#graph-data` JSON script tag |
| `library_search.html` | `results[]` with `cves[].path` for reverse lookup |

## Run the dashboard

```bash
cd ChainSight-Societe-Generale
source .venv/bin/activate
python app/main.py
```

Open http://localhost:5000
