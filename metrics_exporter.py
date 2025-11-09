from flask import Flask, Response, request
from prometheus_client import generate_latest, Gauge, CollectorRegistry
from github import Github
import os, time, json, requests

G = Github(os.environ.get('GITHUB_TOKEN', ''))

app = Flask(__name__)
REG = CollectorRegistry()
g_latest_release = Gauge('webssh_latest_release_timestamp', 'unix timestamp of latest release', registry=REG)
g_open_issues = Gauge('webssh_open_issues_count', 'open issues count', registry=REG)
g_trivy_vulns = Gauge('webssh_trivy_vulnerabilities_total', 'trivy vuln count', ['severity'], registry=REG)

REPO = os.environ.get('REPO','isontheline/pro.webssh.net')

def update_metrics():
    repo = G.get_repo(REPO)
    try:
        release = repo.get_latest_release()
        g_latest_release.set(int(release.published_at.timestamp()))
    except Exception:
        g_latest_release.set(0)
    issues = repo.get_issues(state='open')
    g_open_issues.set(issues.totalCount)

    trivy_path = os.environ.get('TRIVY_PATH','/data/reports/trivy.json')
    try:
        with open(trivy_path) as f:
            data = json.load(f)
            counts = {}
            for vulnset in data.get('Results', []):
                for v in vulnset.get('Vulnerabilities', []) or []:
                    sev = v.get('Severity','UNKNOWN')
                    counts[sev] = counts.get(sev,0) + 1
            for s,c in counts.items():
                g_trivy_vulns.labels(severity=s).set(c)
    except Exception:
        pass

@app.route('/metrics')
def metrics():
    update_metrics()
    return Response(generate_latest(REG), mimetype='text/plain; version=0.0.4')

@app.route('/ingest', methods=['POST'])
def ingest():
    payload = request.get_json(force=True)
    return ('',204)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
