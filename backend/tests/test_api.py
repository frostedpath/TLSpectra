import os
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings

client = TestClient(app)
AUTH_HEADERS = {"Authorization": f"Bearer {settings.STATIC_BEARER_TOKEN}"}

CORPUS_DIR = Path(__file__).resolve().parent.parent.parent / "corpus"

def test_health_check():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["database"] == "connected"
    assert data["parsers_ready"] is True

def test_unauthorized_access():
    response = client.get("/api/v1/captures")
    assert response.status_code == 401
    err = response.json()
    assert "error" in err
    assert err["error"]["code"] == "UNAUTHORIZED"

def test_policy_get_and_put():
    # GET policy
    res = client.get("/api/v1/policy", headers=AUTH_HEADERS)
    assert res.status_code == 200
    policy = res.json()
    assert "tls_min_version" in policy
    assert policy["cert_max_validity_days"] == 398

    # PUT policy
    policy["cert_max_validity_days"] = 365
    res_put = client.put("/api/v1/policy", json=policy, headers=AUTH_HEADERS)
    assert res_put.status_code == 200
    assert res_put.json()["cert_max_validity_days"] == 365

def test_end_to_end_capture_pipeline():
    demo_pcap = CORPUS_DIR / "securemailscope_demo_corpus.pcap"
    assert demo_pcap.exists(), "Demo PCAP not generated"

    with open(demo_pcap, "rb") as f:
        upload_res = client.post(
            "/api/v1/captures",
            files={"file": ("securemailscope_demo_corpus.pcap", f, "application/vnd.tcpdump.pcap")},
            headers=AUTH_HEADERS
        )
    assert upload_res.status_code == 200
    cap_data = upload_res.json()
    capture_id = cap_data["capture_id"]
    assert capture_id.startswith("cap-")

    # The background task executes in TestClient synchronously
    # Check capture status
    get_res = client.get(f"/api/v1/captures/{capture_id}", headers=AUTH_HEADERS)
    assert get_res.status_code == 200
    assert get_res.json()["status"] == "COMPLETE"
    assert get_res.json()["completeness"] == 1.0

    # Check score
    score_res = client.get(f"/api/v1/captures/{capture_id}/score", headers=AUTH_HEADERS)
    assert score_res.status_code == 200
    score_data = score_res.json()
    assert 0 <= score_data["posture_score"] <= 100
    assert "breakdown" in score_data
    assert "disclaimer" in score_data
    assert "synthetic test corpus" in score_data["disclaimer"]

    # Check sessions
    sess_res = client.get(f"/api/v1/captures/{capture_id}/sessions", headers=AUTH_HEADERS)
    assert sess_res.status_code == 200
    sessions = sess_res.json()["items"]
    assert len(sessions) > 0
    test_session = sessions[0]
    session_id = test_session["session_id"]

    # Check session score
    sess_score_res = client.get(f"/api/v1/sessions/{session_id}/score", headers=AUTH_HEADERS)
    assert sess_score_res.status_code == 200
    assert 0 <= sess_score_res.json()["posture_score"] <= 100

    # Check session findings
    sess_find_res = client.get(f"/api/v1/sessions/{session_id}/findings", headers=AUTH_HEADERS)
    assert sess_find_res.status_code == 200

    # Check capture findings
    findings_res = client.get(f"/api/v1/captures/{capture_id}/findings", headers=AUTH_HEADERS)
    assert findings_res.status_code == 200
    findings = findings_res.json()["items"]
    assert len(findings) > 0
    test_finding = findings[0]
    finding_id = test_finding["finding_id"]

    # Check single finding detail
    find_detail = client.get(f"/api/v1/findings/{finding_id}", headers=AUTH_HEADERS)
    assert find_detail.status_code == 200
    assert find_detail.json()["finding_id"] == finding_id

    # Check analyst feedback PATCH
    fb_res = client.patch(
        f"/api/v1/findings/{finding_id}/feedback",
        json={"feedback": "Useful", "notes": "Verified against mail server log"},
        headers=AUTH_HEADERS
    )
    assert fb_res.status_code == 200
    assert fb_res.json()["feedback"] == "Useful"

    # Check hosts
    hosts_res = client.get(f"/api/v1/captures/{capture_id}/hosts", headers=AUTH_HEADERS)
    assert hosts_res.status_code == 200
    hosts = hosts_res.json()["items"]
    assert len(hosts) > 0
    host_id = hosts[0]["host_id"]

    # Check host score
    host_score = client.get(f"/api/v1/hosts/{host_id}/score", headers=AUTH_HEADERS)
    assert host_score.status_code == 200

    # Check reports (JSON and HTML)
    json_rep = client.get(f"/api/v1/captures/{capture_id}/report?format=json", headers=AUTH_HEADERS)
    assert json_rep.status_code == 200
    rep_json = json_rep.json()
    assert "section_1_executive_summary" in rep_json
    assert "section_12_methodology_and_limitations" in rep_json

    html_rep = client.get(f"/api/v1/captures/{capture_id}/report?format=html", headers=AUTH_HEADERS)
    assert html_rep.status_code == 200
    assert "<!DOCTYPE html>" in html_rep.text
    assert "TLSpectra" in html_rep.text
