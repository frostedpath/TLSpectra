import uuid
from typing import Optional, List
from fastapi import APIRouter, Depends, UploadFile, File, BackgroundTasks, Query, Response
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session as DBSession
from sqlalchemy import func, case

from app.core.database import get_db
from app.core.config import settings
from app.core.errors import SMSException, error_response
from app.core.security import verify_token
from app.models import Capture, Session, Finding, Host, Score
from app.schemas import (
    CaptureResponse, CaptureListResponse,
    SessionListResponse, SessionResponse,
    FindingListResponse, FindingResponse,
    HostListResponse, HostResponse,
    ScoreResponse
)
from app.parsers.capture_processor import process_pcap_file
from app.reporting.report_generator import generate_report

router = APIRouter(prefix="/captures", tags=["Captures"])

@router.post("", response_model=CaptureResponse)
async def upload_capture(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: DBSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    if not (file.filename.endswith(".pcap") or file.filename.endswith(".pcapng") or file.filename.endswith(".cap")):
        raise SMSException(400, "UNSUPPORTED_FILE_TYPE", "File must be a valid .pcap or .pcapng packet capture")

    capture_id = f"cap-{uuid.uuid4().hex}"
    dest_path = settings.UPLOAD_DIR / f"{capture_id}_{file.filename}"

    file_size = 0
    with open(dest_path, "wb") as buffer:
        while chunk := await file.read(1024 * 1024):  # 1MB chunks
            file_size += len(chunk)
            if file_size > settings.MAX_UPLOAD_SIZE_BYTES:
                dest_path.unlink(missing_ok=True)
                raise SMSException(400, "CAPTURE_TOO_LARGE", f"File size exceeds 2 GB limit ({file_size} bytes)")
            buffer.write(chunk)

    capture = Capture(
        capture_id=capture_id,
        filename=file.filename,
        size_bytes=file_size,
        status="QUEUED",
        processing_stage="QUEUED"
    )
    db.add(capture)
    db.commit()
    db.refresh(capture)

    # Launch background processing with dedicated SessionLocal session
    background_tasks.add_task(process_pcap_file, capture_id)

    return capture

@router.post("/demo", response_model=CaptureResponse)
def load_demo_capture(
    demo_type: str = Query("corpus", pattern="^(corpus|dropzone)$"),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: DBSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    target_filename = "securemailscope_demo_corpus.pcap" if demo_type == "corpus" else "live_dropzone_test.pcap"

    # Check if a completed capture already exists
    existing = db.query(Capture).filter(
        Capture.filename == target_filename,
        Capture.status == "COMPLETE"
    ).order_by(Capture.uploaded_at.desc()).first()

    if existing:
        return existing

    # Find source file
    source_pcap = None
    if demo_type == "corpus":
        candidate_paths = [
            settings.CORPUS_DIR / target_filename,
            settings.STORAGE_DIR / "uploads" / target_filename,
            settings.BASE_DIR / "storage" / target_filename
        ]
        for p in candidate_paths:
            if p.exists():
                source_pcap = p
                break
    else:
        candidate_paths = [
            settings.STORAGE_DIR / target_filename,
            settings.UPLOAD_DIR / target_filename
        ]
        for p in candidate_paths:
            if p.exists():
                source_pcap = p
                break

    if not source_pcap or not source_pcap.exists():
        raise SMSException(404, "DEMO_FILE_NOT_FOUND", f"Demo capture source file {target_filename} not found.")

    import shutil
    capture_id = f"cap-{uuid.uuid4().hex}"
    dest_path = settings.UPLOAD_DIR / f"{capture_id}_{target_filename}"
    settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source_pcap, dest_path)

    capture = Capture(
        capture_id=capture_id,
        filename=target_filename,
        size_bytes=source_pcap.stat().st_size,
        status="QUEUED",
        processing_stage="QUEUED"
    )
    db.add(capture)
    db.commit()
    db.refresh(capture)

    # Process immediately
    process_pcap_file(capture_id, db)
    db.refresh(capture)
    return capture

@router.get("", response_model=CaptureListResponse)
def list_captures(
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = None,
    db: DBSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    query = db.query(Capture).order_by(Capture.uploaded_at.desc())
    total = query.count()
    items = query.limit(limit).all()
    return {"items": items, "total": total, "limit": limit, "cursor": None}

@router.get("/{capture_id}", response_model=CaptureResponse)
def get_capture(
    capture_id: str,
    db: DBSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    capture = db.query(Capture).filter(Capture.capture_id == capture_id).first()
    if not capture:
        raise SMSException(404, "CAPTURE_NOT_FOUND", f"Capture {capture_id} not found")
    return capture

@router.delete("/{capture_id}")
def delete_capture(
    capture_id: str,
    db: DBSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    capture = db.query(Capture).filter(Capture.capture_id == capture_id).first()
    if not capture:
        raise SMSException(404, "CAPTURE_NOT_FOUND", f"Capture {capture_id} not found")

    filepath = settings.UPLOAD_DIR / f"{capture_id}_{capture.filename}"
    if filepath.exists():
        filepath.unlink(missing_ok=True)

    db.delete(capture)
    db.commit()
    return {"status": "deleted", "capture_id": capture_id}

@router.get("/{capture_id}/score", response_model=ScoreResponse)
def get_capture_score(
    capture_id: str,
    db: DBSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    score = db.query(Score).filter(Score.scope == "capture", Score.scope_id == capture_id).first()
    if not score:
        raise SMSException(404, "SCORE_NOT_FOUND", f"Score not yet computed for capture {capture_id}")
    
    breakdown_data = score.breakdown_json or {}
    return {
        "score_id": score.score_id,
        "scope": score.scope,
        "scope_id": score.scope_id,
        "posture_score": score.posture_score,
        "breakdown": breakdown_data.get("breakdown", []),
        "audit_trail": breakdown_data.get("audit_trail", []),
        "disclaimer": score.disclaimer
    }

@router.get("/{capture_id}/sessions", response_model=SessionListResponse)
def get_capture_sessions(
    capture_id: str,
    protocol: Optional[str] = None,
    starttls_state: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = None,
    db: DBSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    query = db.query(Session).filter(Session.capture_id == capture_id)
    if protocol:
        query = query.filter(Session.protocol == protocol.upper())
    if starttls_state:
        query = query.filter(Session.starttls_state == starttls_state)

    total = query.count()
    items = query.limit(limit).all()

    # Aggregate global STARTTLS state counts across all sessions of this capture
    tls_rows = db.query(Session.starttls_state, func.count(Session.session_id))\
                 .filter(Session.capture_id == capture_id)\
                 .group_by(Session.starttls_state).all()
    starttls_counts = {str(state): int(cnt) for state, cnt in tls_rows}

    return {"items": items, "total": total, "limit": limit, "cursor": None, "starttls_counts": starttls_counts}

@router.get("/{capture_id}/findings", response_model=FindingListResponse)
def get_capture_findings(
    capture_id: str,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    protocol: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = None,
    db: DBSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    query = db.query(Finding).filter(Finding.capture_id == capture_id)
    if severity:
        query = query.filter(Finding.severity == severity.upper())
    if category:
        query = query.filter(Finding.category == category)
    if protocol:
        query = query.filter(Finding.protocol == protocol.upper())

    total = query.count()
    sev_order = case(
        (Finding.severity == "CRITICAL", 1),
        (Finding.severity == "HIGH", 2),
        (Finding.severity == "MEDIUM", 3),
        (Finding.severity == "LOW", 4),
        else_=5
    )
    items = query.order_by(sev_order, Finding.finding_id.asc()).limit(limit).all()

    # Aggregate global severity breakdown across all findings of this capture
    sev_rows = db.query(Finding.severity, func.count(Finding.finding_id))\
                 .filter(Finding.capture_id == capture_id)\
                 .group_by(Finding.severity).all()
    severity_counts = {str(sev): int(cnt) for sev, cnt in sev_rows}

    return {"items": items, "total": total, "limit": limit, "cursor": None, "severity_counts": severity_counts}

@router.get("/{capture_id}/hosts", response_model=HostListResponse)
def get_capture_hosts(
    capture_id: str,
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = None,
    db: DBSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    hosts = db.query(Host).filter(Host.capture_id == capture_id).limit(limit).all()
    items = []
    for h in hosts:
        h_score = db.query(Score).filter(Score.scope == "host", Score.scope_id == h.host_id).first()
        items.append({
            "host_id": h.host_id,
            "capture_id": h.capture_id,
            "ip": h.ip,
            "hostname": h.hostname,
            "session_count": len(h.sessions),
            "posture_score": h_score.posture_score if h_score else None
        })
    return {"items": items, "total": len(items), "limit": limit, "cursor": None}

@router.get("/{capture_id}/report")
def get_capture_report(
    capture_id: str,
    format: str = Query("json", pattern="^(json|html|pdf)$"),
    db: DBSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    report_data = generate_report(capture_id, db, format=format)
    if report_data is None:
        raise SMSException(404, "CAPTURE_NOT_FOUND", f"Capture {capture_id} not found")

    if format == "json":
        return JSONResponse(content=report_data)
    elif format == "html":
        return HTMLResponse(content=report_data)
    elif format == "pdf":
        if isinstance(report_data, bytes):
            return Response(content=report_data, media_type="application/pdf", headers={
                "Content-Disposition": f"attachment; filename=report_{capture_id}.pdf"
            })
        else:
            return HTMLResponse(content=report_data)
