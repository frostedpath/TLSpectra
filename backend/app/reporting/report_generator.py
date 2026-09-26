import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from jinja2 import Template
from sqlalchemy.orm import Session as DBSession, joinedload

from app.models import Capture, Host, Session, Finding, Score, TLSHandshake, Certificate
from app.scoring.engine import MANDATORY_DISCLAIMER

HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>TLSpectra Report - {{ capture.filename }}</title>
<style>
  body { font-family: Helvetica, Arial, sans-serif; line-height: 1.4; color: #111827; background: #FFFFFF; margin: 0; padding: 16px; }
  .container { max-width: 950px; margin: 0 auto; background: #FFFFFF; border: 1px solid #D8DEE8; padding: 24px; }
  h1, h2, h3 { color: #111827; }
  .header { border-bottom: 2px solid #2357D6; padding-bottom: 12px; margin-bottom: 20px; }
  .badge { display: inline-block; padding: 3px 6px; font-size: 11px; font-weight: bold; }
  .badge-critical { background: #FEE2E2; color: #B91C1C; }
  .badge-high { background: #FEF3C7; color: #B45309; }
  .badge-medium { background: #EFF6FF; color: #1D4ED8; }
  .badge-low { background: #F3F4F6; color: #4B5563; }
  .badge-confidence { background: #CCFBF1; color: #0F766E; }
  .score-box { background: #F8FAFC; border: 1px solid #D8DEE8; padding: 14px; margin-bottom: 20px; text-align: center; }
  .score-val { font-size: 40px; font-weight: bold; color: #2357D6; }
  table { width: 100%; margin: 12px 0; border: 1px solid #D8DEE8; }
  th, td { border: 1px solid #D8DEE8; padding: 6px 10px; text-align: left; font-size: 11px; word-wrap: break-word; }
  th { background: #F8FAFC; font-weight: bold; }
  .evidence-cell { font-family: Courier, monospace; font-size: 9px; max-width: 450px; word-break: break-all; }
  .disclaimer { font-size: 11px; color: #6B7280; font-style: italic; margin-top: 14px; border-top: 1px solid #E5E7EB; padding-top: 8px; }
  .export-warning { background: #FEF3C7; border-left: 4px solid #B45309; padding: 10px; font-size: 11px; margin-bottom: 16px; }
  .truncation-notice { background: #EFF6FF; border: 1px solid #BFDBFE; color: #1E40AF; padding: 8px 12px; font-size: 11px; margin: 8px 0; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>TLSpectra — Posture Assessment Report</h1>
    <div style="font-size: 13px; color: #4B5563; margin-top: -6px; margin-bottom: 8px; font-weight: 500;">Evidence-Driven Cryptographic Network Forensics</div>
    <p>Target Capture: <strong>{{ capture.filename }}</strong> | ID: <code>{{ capture.capture_id }}</code> | Generated: {{ generated_at }}</p>
  </div>

  <div class="export-warning">
    <strong>Investigation Notice:</strong> Reports may contain hostnames, IP addresses, packet references, and security findings. Store and share them according to your investigation policy.
  </div>

  <!-- Section 1: Executive summary -->
  <h2>1. Executive Summary</h2>
  <div class="score-box">
    <div>Overall Posture Score</div>
    <div class="score-val">{{ posture_score }}/100</div>
    <div>Total Sessions: {{ sessions|length }} | Total Findings: {{ findings|length }}</div>
  </div>

  <!-- Section 2: Capture metadata and limitations -->
  <h2>2. Capture Metadata & Passive Limitations</h2>
  <table>
    <tr><th>Filename</th><td>{{ capture.filename }}</td><th>Size</th><td>{{ capture.size_bytes }} bytes</td></tr>
    <tr><th>Uploaded At</th><td>{{ capture.uploaded_at }}</td><th>Processed At</th><td>{{ capture.processed_at }}</td></tr>
    <tr><th>Passive Visibility Rate</th><td>{{ (capture.passive_visibility_rate * 100)|round }}%</td><th>Completeness</th><td>{{ (capture.completeness * 100)|round }}%</td></tr>
  </table>
  <p><em>Note: Passive inspection observes in-transit traffic without active probes. In TLS 1.3, Server Certificates and handshake extensions are encrypted and marked as NOT_OBSERVABLE.</em></p>

  <!-- Section 3: Protocol/session distribution -->
  <h2>3. Protocol & Session Distribution</h2>
  <table>
    <tr><th>Protocol</th><th>Sessions Count</th><th>Authentication Observed</th></tr>
    {% for proto, count in protocol_dist.items() %}
    <tr><td>{{ proto }}</td><td>{{ count }}</td><td>{{ auth_dist.get(proto, 0) }}</td></tr>
    {% endfor %}
  </table>

  <!-- Section 4: STARTTLS/STLS transition analysis -->
  <h2>4. STARTTLS / STLS Transition Analysis</h2>
  <table>
    <tr><th>Transition State</th><th>Count</th></tr>
    {% for state, count in starttls_dist.items() %}
    <tr><td><code>{{ state }}</code></td><td>{{ count }}</td></tr>
    {% endfor %}
  </table>

  <!-- Section 5: TLS-version/cipher distribution -->
  <h2>5. TLS Version & Cipher Distribution</h2>
  <table>
    <tr><th>TLS Version</th><th>Cipher Suite</th><th>Forward Secrecy</th><th>Count</th></tr>
    {% for item in tls_dist %}
    <tr><td>{{ item.version }}</td><td><code>{{ item.cipher }}</code></td><td>{{ item.fs }}</td><td>{{ item.count }}</td></tr>
    {% endfor %}
  </table>

  <!-- Section 6: Certificate health and identity checks -->
  <h2>6. Certificate Health & Identity Checks</h2>
  <table>
    <tr><th>Subject</th><th>Issuer</th><th>Key Type</th><th>SAN</th><th>Validity</th></tr>
    {% for cert in certificates %}
    <tr>
      <td>{{ cert.subject }}</td>
      <td>{{ cert.issuer }}</td>
      <td>{{ cert.public_key_alg }} ({{ cert.key_bits }} bits)</td>
      <td>{{ cert.san|join(', ') }}</td>
      <td>{{ cert.not_before }} to {{ cert.not_after }}</td>
    </tr>
    {% endfor %}
  </table>

  <!-- Section 7: Cryptographic findings -->
  <h2>7. Cryptographic Security Findings</h2>
  <table>
    <tr><th>Rule ID</th><th>Severity</th><th>Confidence</th><th>Title</th><th>Impact</th></tr>
    {% for f in displayed_crypto %}
    <tr>
      <td><code>{{ f.rule_id }}</code></td>
      <td><span class="badge badge-{{ f.severity|lower }}">{{ f.severity }}</span></td>
      <td><span class="badge badge-confidence">{{ f.confidence }}</span></td>
      <td><strong>{{ f.title }}</strong></td>
      <td>{{ f.impact }}</td>
    </tr>
    {% endfor %}
  </table>
  {% if crypto_truncated %}
  <div class="truncation-notice">
    Showing top {{ displayed_crypto|length }} prioritized cryptographic findings of {{ crypto_findings|length }} total. Full list available via structured JSON export or interactive Findings Explorer.
  </div>
  {% endif %}

  <!-- Section 8: Behavioural anomaly findings -->
  <h2>8. Behavioural Anomaly Findings</h2>
  {% if displayed_anomalies %}
  <table>
    <tr><th>Finding ID</th><th>Model</th><th>Confidence</th><th>Supporting Signals</th></tr>
    {% for a in displayed_anomalies %}
    <tr>
      <td><code>{{ a.finding_id }}</code></td>
      <td>{{ a.ml_model_id }}</td>
      <td><span class="badge badge-confidence">{{ a.confidence }}</span></td>
      <td>{{ a.evidence_json.supporting_signals|join('; ') }}</td>
    </tr>
    {% endfor %}
  </table>
  {% if anomalies_truncated %}
  <div class="truncation-notice">
    Showing top {{ displayed_anomalies|length }} behavioral anomaly findings of {{ anomaly_findings|length }} total. Full list available via structured JSON export or interactive Findings Explorer.
  </div>
  {% endif %}
  {% else %}
  <p>No behavioural anomaly outliers detected or insufficient session baseline for unsupervised baselining.</p>
  {% endif %}

  <!-- Section 9: Per-host and overall posture score -->
  <h2>9. Host Posture & Score Breakdown</h2>
  <table>
    <tr><th>Host IP</th><th>Hostname</th><th>Sessions</th><th>Posture Score</th></tr>
    {% for h in hosts %}
    <tr>
      <td>{{ h.ip }}</td>
      <td>{{ h.hostname or "N/A" }}</td>
      <td>{{ h.sessions|length }}</td>
      <td><strong>{{ host_scores.get(h.host_id, posture_score) }}/100</strong></td>
    </tr>
    {% endfor %}
  </table>

  <!-- Section 10: Prioritized recommendations -->
  <h2>10. Prioritized Recommendations</h2>
  <ol>
    {% for rec in recommendations %}
    <li><strong>[{{ rec.rule_id }}]</strong> {{ rec.recommendation }} (<em>Ref: {{ rec.standards_ref }}</em>)</li>
    {% endfor %}
  </ol>

  <!-- Section 11: Evidence appendix -->
  <h2>11. Evidence Appendix & Traceability</h2>
  <table>
    <tr><th>Finding ID</th><th>Session</th><th>Evidence Trail</th></tr>
    {% for f in displayed_findings %}
    <tr>
      <td><code>{{ f.finding_id }}</code></td>
      <td><code>{{ f.session_id }}</code></td>
      <td class="evidence-cell"><code>{{ f.evidence_json }}</code></td>
    </tr>
    {% endfor %}
  </table>
  {% if findings_truncated %}
  <div class="truncation-notice">
    Showing top {{ displayed_findings|length }} prioritized findings (sorted by Critical -> High -> Medium) of {{ findings|length }} total findings. Full un-truncated forensic evidence trail is available in the structured JSON export (format=json) or interactive UI Evidence Explorer.
  </div>
  {% endif %}

  <!-- Section 12: Methodology and limitations -->
  <h2>12. Methodology & Limitations</h2>
  <p>TLSpectra utilizes passive network capture analysis, combining deterministic protocol decoders with heuristic state evaluation. Findings are categorized into DIRECT observation, HIGH/MEDIUM CONFIDENCE inference, and EXTERNAL VALIDATION. Deterministic rules are calibrated against RFC 8446, RFC 8996, RFC 8314, RFC 3207, RFC 6125, RFC 5280, and NIST SP 800-52 Rev. 2.</p>
  
  <div class="disclaimer">
    <strong>Disclaimer:</strong> {{ disclaimer }}
  </div>
</div>
</body>
</html>
"""

def generate_report(capture_id: str, db: DBSession, format: str = "json") -> Any:
    """
    Generates report with all 12 compliance sections in JSON, HTML, or PDF format.
    Optimized for high-throughput and large packet captures.
    """
    capture = db.query(Capture).filter(Capture.capture_id == capture_id).first()
    if not capture:
        return None

    sessions = db.query(Session).filter(Session.capture_id == capture_id).all()
    findings = db.query(Finding).filter(Finding.capture_id == capture_id).all()
    hosts = db.query(Host).filter(Host.capture_id == capture_id).all()
    capture_score_obj = db.query(Score).filter(Score.scope == "capture", Score.scope_id == capture_id).first()
    posture_score = capture_score_obj.posture_score if capture_score_obj else 100

    # Collect host scores in batch to eliminate N+1 queries
    host_scores = {}
    host_ids = [h.host_id for h in hosts]
    if host_ids:
        scores = db.query(Score).filter(Score.scope == "host", Score.scope_id.in_(host_ids)).all()
        host_score_map = {s.scope_id: s.posture_score for s in scores}
        for h in hosts:
            host_scores[h.host_id] = host_score_map.get(h.host_id, posture_score)

    # Distributions
    protocol_dist = {}
    auth_dist = {}
    starttls_dist = {}
    for s in sessions:
        p = s.protocol or "UNKNOWN"
        protocol_dist[p] = protocol_dist.get(p, 0) + 1
        if s.auth_observed:
            auth_dist[p] = auth_dist.get(p, 0) + 1
        st = s.starttls_state or "NOT_OFFERED"
        starttls_dist[st] = starttls_dist.get(st, 0) + 1

    # Eager load handshakes and certificates in one query instead of lazy per-session queries
    handshakes = (
        db.query(TLSHandshake)
        .join(Session)
        .filter(Session.capture_id == capture_id)
        .options(joinedload(TLSHandshake.certificates))
        .all()
    )
    tls_map = {}
    seen_cert_keys = set()
    certs_list = []
    for hs in handshakes:
        key = (hs.version or "UNKNOWN", hs.cipher_suite or "UNKNOWN", hs.forward_secrecy)
        tls_map[key] = tls_map.get(key, 0) + 1
        for c in hs.certificates:
            ckey = (c.subject, c.issuer, c.not_before, c.not_after)
            if ckey not in seen_cert_keys:
                seen_cert_keys.add(ckey)
                certs_list.append(c)

    tls_dist = [
        {"version": k[0], "cipher": k[1], "fs": k[2], "count": v}
        for k, v in tls_map.items()
    ]

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 99))
    crypto_findings = [f for f in sorted_findings if f.category in {"Cryptographic Security", "Certificate Security", "Protocol Security", "STARTTLS Security"}]
    anomaly_findings = [f for f in sorted_findings if f.category == "Behavioural Anomaly"]

    # Display caps for PDF/HTML rendering to keep generation under 2 seconds while JSON remains 100% complete
    MAX_DISPLAY_FINDINGS = 75
    displayed_findings = sorted_findings[:MAX_DISPLAY_FINDINGS]
    findings_truncated = len(sorted_findings) > MAX_DISPLAY_FINDINGS

    MAX_DISPLAY_CRYPTO = 100
    displayed_crypto = crypto_findings[:MAX_DISPLAY_CRYPTO]
    crypto_truncated = len(crypto_findings) > MAX_DISPLAY_CRYPTO

    MAX_DISPLAY_ANOMALIES = 50
    displayed_anomalies = anomaly_findings[:MAX_DISPLAY_ANOMALIES]
    anomalies_truncated = len(anomaly_findings) > MAX_DISPLAY_ANOMALIES

    # Deduplicated recommendations
    recs = []
    seen_rules = set()
    for f in sorted_findings:
        if f.rule_id not in seen_rules:
            recs.append({
                "rule_id": f.rule_id,
                "recommendation": f.recommendation,
                "standards_ref": f.standards_ref
            })
            seen_rules.add(f.rule_id)

    report_context = {
        "capture": capture,
        "posture_score": posture_score,
        "sessions": sessions,
        "findings": findings,
        "crypto_findings": crypto_findings,
        "displayed_crypto": displayed_crypto,
        "crypto_truncated": crypto_truncated,
        "anomaly_findings": anomaly_findings,
        "displayed_anomalies": displayed_anomalies,
        "anomalies_truncated": anomalies_truncated,
        "hosts": hosts,
        "host_scores": host_scores,
        "protocol_dist": protocol_dist,
        "auth_dist": auth_dist,
        "starttls_dist": starttls_dist,
        "tls_dist": tls_dist,
        "certificates": certs_list,
        "recommendations": recs,
        "displayed_findings": displayed_findings,
        "findings_truncated": findings_truncated,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "disclaimer": MANDATORY_DISCLAIMER
    }

    if format == "json":
        return {
            "section_1_executive_summary": {
                "capture_id": capture.capture_id,
                "posture_score": posture_score,
                "total_sessions": len(sessions),
                "total_findings": len(findings)
            },
            "section_2_capture_metadata_and_limitations": {
                "filename": capture.filename,
                "size_bytes": capture.size_bytes,
                "passive_visibility_rate": capture.passive_visibility_rate,
                "completeness": capture.completeness,
                "uploaded_at": capture.uploaded_at.isoformat() if capture.uploaded_at else None,
                "processed_at": capture.processed_at.isoformat() if capture.processed_at else None
            },
            "section_3_protocol_session_distribution": protocol_dist,
            "section_4_starttls_transition_analysis": starttls_dist,
            "section_5_tls_cipher_distribution": tls_dist,
            "section_6_certificate_health": [
                {"subject": c.subject, "issuer": c.issuer, "key_bits": c.key_bits, "san": c.san}
                for c in certs_list
            ],
            "section_7_cryptographic_findings": [
                {"finding_id": f.finding_id, "rule_id": f.rule_id, "severity": f.severity, "confidence": f.confidence, "title": f.title}
                for f in crypto_findings
            ],
            "section_8_behavioural_anomalies": [
                {"finding_id": a.finding_id, "model": a.ml_model_id, "evidence": a.evidence_json}
                for a in anomaly_findings
            ],
            "section_9_scores_breakdown": {
                "capture_score": posture_score,
                "host_scores": host_scores
            },
            "section_10_prioritized_recommendations": recs,
            "section_11_evidence_appendix": [
                {"finding_id": f.finding_id, "session_id": f.session_id, "evidence": f.evidence_json}
                for f in findings
            ],
            "section_12_methodology_and_limitations": {
                "standards": ["RFC 8446", "RFC 8996", "RFC 8314", "RFC 3207", "RFC 6125", "RFC 5280", "NIST SP 800-52"],
                "disclaimer": MANDATORY_DISCLAIMER
            }
        }

    template = Template(HTML_REPORT_TEMPLATE)
    html_content = template.render(**report_context)

    if format == "html":
        return html_content

    if format == "pdf":
        try:
            from io import BytesIO
            from xhtml2pdf import pisa
            pdf_buffer = BytesIO()
            pisa_status = pisa.CreatePDF(html_content, dest=pdf_buffer)
            if not pisa_status.err:
                return pdf_buffer.getvalue()
        except Exception:
            pass

        try:
            import importlib
            weasyprint_mod = importlib.import_module("weasyprint")
            return weasyprint_mod.HTML(string=html_content).write_pdf()
        except Exception:
            # Clean fallback returning rendered HTML if PDF libraries lack native OS cairo/pango
            return html_content

