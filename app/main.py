import os
from flask import Flask, render_template, request, abort

app = Flask(__name__)

# Mock Data
MOCK_APPS = {
    "payments-api": {
        "id": "payments-api",
        "name": "Payments API",
        "version": "v3.1.2",
        "department": "Transactional Banking",
        "language": "Java / Spring Boot",
        "risk_score": 82,
        "vulnerabilities": {"critical": 2, "high": 5, "medium": 12, "low": 8},
        "license_issues": 3,
        "dependencies_count": 84,
        "last_scanned": "2026-07-10 14:32:00",
        "description": "Core payment gateway handling ACH and wire transfer processing for retail customers.",
        "findings": [
            {"library": "log4j-core", "version": "2.14.1", "license": "Apache 2.0", "cve": "CVE-2021-44228", "cvss": 10.0, "severity": "CRITICAL", "status": "Vulnerable", "remediation": "Upgrade to version 2.17.1 or higher."},
            {"library": "jackson-databind", "version": "2.9.10", "license": "Apache 2.0", "cve": "CVE-2019-14540", "cvss": 7.5, "severity": "HIGH", "status": "Vulnerable", "remediation": "Upgrade to 2.9.10.1 or higher."},
            {"library": "gpl-uploader-lib", "version": "1.0.3", "license": "GPL 3.0", "cve": "None", "cvss": 0.0, "severity": "HIGH", "status": "License Conflict", "remediation": "Replace with Apache 2.0 licensed alternative to comply with corporate policy."},
            {"library": "spring-core", "version": "5.3.9", "license": "Apache 2.0", "cve": "CVE-2022-22965", "cvss": 9.8, "severity": "CRITICAL", "status": "Vulnerable", "remediation": "Upgrade spring-framework to 5.3.18+ or 5.2.20+."}
        ],
        "dependencies": {
            "name": "payments-api",
            "children": [
                {
                    "name": "spring-boot-starter-web",
                    "children": [
                        {"name": "spring-boot-starter"},
                        {"name": "spring-web"},
                        {"name": "spring-webmvc"}
                    ]
                },
                {
                    "name": "log4j-core",
                    "children": []
                },
                {
                    "name": "gpl-uploader-lib",
                    "children": [
                        {"name": "gpl-helper-core"}
                    ]
                }
            ]
        }
    },
    "customer-portal": {
        "id": "customer-portal",
        "name": "Customer Portal",
        "version": "v1.8.0",
        "department": "Retail Systems",
        "language": "TypeScript / React",
        "risk_score": 45,
        "vulnerabilities": {"critical": 0, "high": 1, "medium": 4, "low": 15},
        "license_issues": 0,
        "dependencies_count": 218,
        "last_scanned": "2026-07-09 09:15:00",
        "description": "User interface for retail banking clients to view statements, edit profile details, and initiate transfers.",
        "findings": [
            {"library": "axios", "version": "0.21.1", "license": "MIT", "cve": "CVE-2021-3749", "cvss": 7.5, "severity": "HIGH", "status": "Vulnerable", "remediation": "Update to axios 0.21.2 or higher."},
            {"library": "lodash", "version": "4.17.20", "license": "MIT", "cve": "CVE-2021-23337", "cvss": 5.3, "severity": "MEDIUM", "status": "Vulnerable", "remediation": "Upgrade lodash to 4.17.21 or higher."}
        ],
        "dependencies": {
            "name": "customer-portal",
            "children": [
                {
                    "name": "react",
                    "children": [{"name": "object-assign"}]
                },
                {
                    "name": "axios",
                    "children": [{"name": "follow-redirects"}]
                },
                {
                    "name": "lodash",
                    "children": []
                }
            ]
        }
    },
    "trade-settlement-service": {
        "id": "trade-settlement-service",
        "name": "Trade Settlement Service",
        "version": "v4.0.1",
        "department": "Capital Markets",
        "language": "C# / .NET 6",
        "risk_score": 15,
        "vulnerabilities": {"critical": 0, "high": 0, "medium": 1, "low": 2},
        "license_issues": 0,
        "dependencies_count": 42,
        "last_scanned": "2026-07-10 11:00:00",
        "description": "High-throughput matching engine for foreign exchange and equity transactions settlement.",
        "findings": [
            {"library": "Newtonsoft.Json", "version": "12.0.1", "license": "MIT", "cve": "CVE-2024-21907", "cvss": 7.5, "severity": "MEDIUM", "status": "Outdated", "remediation": "Upgrade Newtonsoft.Json to 13.0.1 or higher."}
        ],
        "dependencies": {
            "name": "trade-settlement-service",
            "children": [
                {
                    "name": "Microsoft.AspNetCore.App",
                    "children": []
                },
                {
                    "name": "Newtonsoft.Json",
                    "children": []
                }
            ]
        }
    }
}

MOCK_LIBRARIES = [
    {
        "name": "log4j-core",
        "latest_version": "2.20.0",
        "license": "Apache 2.0",
        "cves": [
            {"id": "CVE-2021-44228", "cvss": 10.0, "severity": "CRITICAL", "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints."}
        ],
        "affected_apps": [
            {"id": "payments-api", "name": "Payments API", "version_used": "2.14.1"}
        ]
    },
    {
        "name": "jackson-databind",
        "latest_version": "2.15.2",
        "license": "Apache 2.0",
        "cves": [
            {"id": "CVE-2019-14540", "cvss": 7.5, "severity": "HIGH", "description": "A polymorphic typing issue exists in jackson-databind. This is related to com.zaxxer.hikari.HikariConfig."}
        ],
        "affected_apps": [
            {"id": "payments-api", "name": "Payments API", "version_used": "2.9.10"}
        ]
    },
    {
        "name": "gpl-uploader-lib",
        "latest_version": "1.0.3",
        "license": "GPL 3.0",
        "cves": [],
        "affected_apps": [
            {"id": "payments-api", "name": "Payments API", "version_used": "1.0.3"}
        ]
    },
    {
        "name": "axios",
        "latest_version": "1.4.0",
        "license": "MIT",
        "cves": [
            {"id": "CVE-2021-3749", "cvss": 7.5, "severity": "HIGH", "description": "Regular expression out of bounds search (ReDoS) vulnerability in Axios."}
        ],
        "affected_apps": [
            {"id": "customer-portal", "name": "Customer Portal", "version_used": "0.21.1"}
        ]
    },
    {
        "name": "lodash",
        "latest_version": "4.17.21",
        "license": "MIT",
        "cves": [
            {"id": "CVE-2021-23337", "cvss": 5.3, "severity": "MEDIUM", "description": "Prototype pollution vulnerability in lodash."}
        ],
        "affected_apps": [
            {"id": "customer-portal", "name": "Customer Portal", "version_used": "4.17.20"}
        ]
    },
    {
        "name": "spring-core",
        "latest_version": "6.0.11",
        "license": "Apache 2.0",
        "cves": [
            {"id": "CVE-2022-22965", "cvss": 9.8, "severity": "CRITICAL", "description": "Spring Framework Remote Code Execution via data binding on JDK 9+."}
        ],
        "affected_apps": [
            {"id": "payments-api", "name": "Payments API", "version_used": "5.3.9"}
        ]
    },
    {
        "name": "Newtonsoft.Json",
        "latest_version": "13.0.3",
        "license": "MIT",
        "cves": [
            {"id": "CVE-2024-21907", "cvss": 7.5, "severity": "MEDIUM", "description": "Improper handling of JSON payloads allows stack overflow denial of service."}
        ],
        "affected_apps": [
            {"id": "trade-settlement-service", "name": "Trade Settlement Service", "version_used": "12.0.1"}
        ]
    }
]

@app.route("/")
def index():
    # Sort applications by risk score descending
    apps = sorted(MOCK_APPS.values(), key=lambda x: x["risk_score"], reverse=True)
    return render_template("app_list.html", apps=apps)

@app.route("/library-search")
def library_search():
    query = request.args.get("q", "").strip().lower()
    results = []
    if query:
        for lib in MOCK_LIBRARIES:
            if query in lib["name"].lower() or query in lib["license"].lower():
                results.append(lib)
    return render_template("library_search.html", query=request.args.get("q", ""), results=results)

@app.route("/risk-report/<app_id>")
def risk_report(app_id):
    app_data = MOCK_APPS.get(app_id)
    if not app_data:
        abort(404)
    return render_template("risk_report.html", app=app_data)

if __name__ == "__main__":
    # Get port from environment or fallback to 5000
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
