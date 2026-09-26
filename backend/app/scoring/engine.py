import uuid
from typing import Dict, Any, List
from collections import defaultdict
from sqlalchemy.orm import Session as DBSession

from app.models import Score, Finding, Session, Host, Capture
from app.core.config import settings

MANDATORY_DISCLAIMER = (
    "Weights are documented design decisions calibrated against the synthetic test corpus, "
    "not an industry-standard formula."
)

# Base severity penalties calibrated against test corpus
SEVERITY_DEDUCTIONS = {
    "CRITICAL": 35,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 4,
    "INFO": 0
}

# Category maximum deduction caps
CATEGORY_WEIGHT_CAPS = {
    "Protocol Security": 25,
    "Cryptographic Security": 30,
    "Certificate Security": 25,
    "STARTTLS Security": 15,
    "Behavioural Anomaly": 5
}

def calculate_scores(capture_id: str, db: DBSession):
    """
    Calculates posture scores (0-100) with double-counting protection and audit trails
    for capture, hosts, and individual sessions.
    Optimized for high-throughput and large packet captures (10,000+ sessions).
    """
    findings = db.query(Finding).filter(Finding.capture_id == capture_id).all()
    sessions = db.query(Session).filter(Session.capture_id == capture_id).all()
    hosts = db.query(Host).filter(Host.capture_id == capture_id).all()

    # Pre-index findings by session for O(1) lookups
    findings_by_session: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        if f.session_id:
            findings_by_session[f.session_id].append(f)

    # Pre-fetch existing scores in batch to eliminate N+1 queries
    all_scope_ids = [capture_id] + [h.host_id for h in hosts] + [s.session_id for s in sessions]
    existing_scores: Dict[tuple, Score] = {}
    CHUNK_SIZE = 500
    for i in range(0, len(all_scope_ids), CHUNK_SIZE):
        chunk = all_scope_ids[i:i + CHUNK_SIZE]
        for sc in db.query(Score).filter(Score.scope_id.in_(chunk)).all():
            existing_scores[(sc.scope, sc.scope_id)] = sc

    # 1. Capture-level score
    capture_score, capture_breakdown, capture_audit = _compute_posture_score(findings)
    _upsert_score(db, existing_scores, "capture", capture_id, capture_score, capture_breakdown, capture_audit)

    # 2. Host-level scores
    for host in hosts:
        host_sess_ids = {s.session_id for s in host.sessions}
        host_findings = [f for s_id in host_sess_ids for f in findings_by_session.get(s_id, [])]
        host_score, host_breakdown, host_audit = _compute_posture_score(host_findings)
        _upsert_score(db, existing_scores, "host", host.host_id, host_score, host_breakdown, host_audit)

    # 3. Session-level scores
    # Pre-compute clean baseline for sessions with 0 findings (score=100)
    clean_score, clean_breakdown, clean_audit = _compute_posture_score([])

    for sess in sessions:
        sess_finds = findings_by_session.get(sess.session_id)
        if sess_finds:
            s_score, s_breakdown, s_audit = _compute_posture_score(sess_finds)
        else:
            s_score, s_breakdown, s_audit = clean_score, clean_breakdown, clean_audit
        _upsert_score(db, existing_scores, "session", sess.session_id, s_score, s_breakdown, s_audit)

    db.commit()

def _compute_posture_score(findings_list: List[Finding]):
    # Group findings by session and category to prevent double counting
    session_category_rules: Dict[str, Dict[str, List[Finding]]] = defaultdict(lambda: defaultdict(list))
    cat_counts: Dict[str, int] = defaultdict(int)
    cat_rules: Dict[str, set] = defaultdict(set)

    for f in findings_list:
        sess_key = f.session_id or "unassociated"
        session_category_rules[sess_key][f.category].append(f)
        cat_counts[f.category] += 1
        cat_rules[f.category].add(f.rule_id)

    category_raw_deductions: Dict[str, int] = defaultdict(int)
    audit_trail: List[Dict[str, Any]] = []

    for sess_id, cat_map in session_category_rules.items():
        for category, finds in cat_map.items():
            # Composite grouping: highest severity finding contributes full deduction;
            # additional related findings in the same session/category contribute 25% diminishing weight
            sorted_finds = sorted(finds, key=lambda x: SEVERITY_DEDUCTIONS.get(x.severity, 0), reverse=True)
            if sorted_finds:
                primary = sorted_finds[0]
                primary_deduction = SEVERITY_DEDUCTIONS.get(primary.severity, 0)
                secondary_deduction = sum(int(SEVERITY_DEDUCTIONS.get(sf.severity, 0) * 0.25) for sf in sorted_finds[1:])
                session_category_deduction = primary_deduction + secondary_deduction

                category_raw_deductions[category] += session_category_deduction

                audit_trail.append({
                    "session_id": sess_id,
                    "category": category,
                    "primary_rule": primary.rule_id,
                    "primary_severity": primary.severity,
                    "findings_count": len(sorted_finds),
                    "deduction": session_category_deduction,
                    "all_rules": [f.rule_id for f in sorted_finds]
                })

    # Normalize category deductions against category weight caps
    breakdown: List[Dict[str, Any]] = []
    total_deductions = 0

    for cat, cap in CATEGORY_WEIGHT_CAPS.items():
        raw = category_raw_deductions.get(cat, 0)
        # Cap category deduction at its documented maximum weight
        capped = min(cap, raw)
        total_deductions += capped
        breakdown.append({
            "category": cat,
            "deduction": capped,
            "raw_deduction": raw,
            "max_weight": cap,
            "findings_count": cat_counts.get(cat, 0),
            "grouped_rules": list(cat_rules.get(cat, set()))
        })

    posture_score = max(0, min(100, 100 - total_deductions))
    return posture_score, breakdown, audit_trail

def _upsert_score(db: DBSession, existing_scores: Dict[tuple, Score], scope: str, scope_id: str, score_val: int, breakdown: List[Dict[str, Any]], audit_trail: List[Dict[str, Any]]):
    key = (scope, scope_id)
    score_data = {
        "breakdown": breakdown,
        "audit_trail": audit_trail
    }
    if key in existing_scores:
        existing = existing_scores[key]
        existing.posture_score = score_val
        existing.breakdown_json = score_data
        existing.disclaimer = MANDATORY_DISCLAIMER
    else:
        new_score = Score(
            score_id=f"score-{uuid.uuid4().hex}",
            scope=scope,
            scope_id=scope_id,
            posture_score=score_val,
            breakdown_json=score_data,
            disclaimer=MANDATORY_DISCLAIMER
        )
        db.add(new_score)
        existing_scores[key] = new_score

def _save_score(db: DBSession, scope: str, scope_id: str, score_val: int, breakdown: List[Dict[str, Any]], audit_trail: List[Dict[str, Any]]):
    existing = db.query(Score).filter(Score.scope == scope, Score.scope_id == scope_id).first()
    score_data = {
        "breakdown": breakdown,
        "audit_trail": audit_trail
    }
    if existing:
        existing.posture_score = score_val
        existing.breakdown_json = score_data
        existing.disclaimer = MANDATORY_DISCLAIMER
    else:
        new_score = Score(
            score_id=f"score-{uuid.uuid4().hex}",
            scope=scope,
            scope_id=scope_id,
            posture_score=score_val,
            breakdown_json=score_data,
            disclaimer=MANDATORY_DISCLAIMER
        )
        db.add(new_score)

