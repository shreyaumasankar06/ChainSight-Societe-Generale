import os
import sys
from pathlib import Path

# Allow imports from project root (src.*)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask, abort, render_template, request

from dashboard_data import get_dashboard_data

app = Flask(__name__)


@app.route("/")
def index():
    data = get_dashboard_data()
    apps = sorted(data["apps"].values(), key=lambda x: x["risk_score"], reverse=True)
    return render_template("app_list.html", apps=apps, stats=data["stats"])


@app.route("/library-search")
def library_search():
    query = request.args.get("q", "").strip().lower()
    data = get_dashboard_data()
    results = []
    if query:
        for lib in data["libraries"].values():
            if query in lib["name"].lower() or query in lib["license"].lower():
                results.append(lib)
        results.sort(key=lambda lib: lib["name"])
    return render_template("library_search.html", query=request.args.get("q", ""), results=results)


@app.route("/risk-report/<app_id>")
def risk_report(app_id):
    data = get_dashboard_data()
    app_data = data["apps"].get(app_id)
    if not app_data:
        abort(404)
    return render_template("risk_report.html", app=app_data)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
