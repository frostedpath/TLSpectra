import uuid
import logging
from typing import Dict, Any, List, Optional, Tuple
from collections import Counter
from sqlalchemy.orm import Session as DBSession

from app.models import Session, Finding
from app.core.config import settings

logger = logging.getLogger(__name__)


def get_ml_telemetry() -> Dict[str, Any]:
    """
    Returns hardware telemetry and active ML engine state.
    Surfaces whether CUDA (RTX GPU) or standard CPU is currently detected.
    """
    torch_available = False
    cuda_available = False
    device = "cpu"
    device_name = "Standard CPU Host"

    try:
        import torch
        torch_available = True
        cuda_available = torch.cuda.is_available()
        if cuda_available:
            device = "cuda"
            device_name = torch.cuda.get_device_name(0)
        else:
            device = "cpu"
            device_name = "CPU (PyTorch Threaded)"
    except ImportError:
        pass

    return {
        "default_engine": "IsolationForest-1.0-local",
        "active_engine": settings.ML_ANOMALY_ENGINE,
        "device": device,
        "device_name": device_name,
        "cuda_available": cuda_available,
        "autoencoder_experimental_available": torch_available,
        "autoencoder_status": "EXPERIMENTAL: Unvalidated against synthetic test corpus baseline (IsolationForest remains default production model)",
        "supported_engines": ["isolation_forest", "autoencoder"]
    }


def extract_session_features(sessions: List[Session]) -> Tuple[List[List[float]], List[str], Counter, int]:
    """
    Extracts all 13 source behavioral signals:
    1. TLS version
    2. cipher family
    3. forward secrecy flag
    4. certificate quality indicator
    5. STARTTLS transition state
    6. SNI presence
    7. JA3 / JA3S components
    8. handshake duration
    9. packet count
    10. byte count
    11. TLS alert/failure count
    12. rarity of protocol-cipher-fingerprint combination
    """
    combos = []
    for s in sessions:
        hs = s.handshake
        proto = s.protocol or "UNKNOWN"
        cipher = hs.cipher_suite if hs else "NONE"
        ja3 = hs.ja3_fingerprint if hs else "NONE"
        combos.append(f"{proto}:{cipher}:{ja3}")

    combo_counts = Counter(combos)
    total_combos = len(combos)

    feature_matrix = []
    session_ids = []

    version_map = {"SSL 3.0": 0, "TLS 1.0": 1, "TLS 1.1": 2, "TLS 1.2": 3, "TLS 1.3": 4}
    state_map = {
        "NOT_OFFERED": 0, "OFFERED": 1, "REQUESTED": 2, "ACCEPTED": 3,
        "TLS_ESTABLISHED": 4, "REJECTED": 5, "FAILED": 6, "CLEARTEXT_AFTER_OFFER": 7
    }

    for s in sessions:
        hs = s.handshake
        certs = hs.certificates if hs else []
        leaf_cert = certs[0] if certs else None

        f_version = version_map.get(hs.version, 2) if hs else 0
        f_cipher_family = 1 if (hs and hs.cipher_suite and "AES" in hs.cipher_suite) else 0
        f_fs = 1 if (hs and hs.forward_secrecy) else 0
        f_cert_quality = (leaf_cert.key_bits or 0) if leaf_cert else 0
        f_starttls_state = state_map.get(s.starttls_state, 0)
        f_sni = 1 if (hs and hs.sni) else 0
        f_ja3 = int(hs.ja3_fingerprint[:8], 16) % 10000 if (hs and hs.ja3_fingerprint) else 0
        f_ja3s = int(hs.ja3s_fingerprint[:8], 16) % 10000 if (hs and hs.ja3s_fingerprint) else 0
        f_duration = hs.duration_ms if hs else 0.0
        f_packets = float(s.packet_count)
        f_bytes = float(s.byte_count)
        f_alerts = float(len(hs.alerts)) if hs else 0.0

        # Rarity calculation: inverse frequency of protocol-cipher-fingerprint combo
        combo_key = f"{s.protocol or 'UNKNOWN'}:{hs.cipher_suite if hs else 'NONE'}:{hs.ja3_fingerprint if hs else 'NONE'}"
        f_rarity = 1.0 - (combo_counts[combo_key] / total_combos)

        vector = [
            f_version, f_cipher_family, f_fs, f_cert_quality, f_starttls_state,
            f_sni, f_ja3, f_ja3s, f_duration, f_packets, f_bytes, f_alerts, f_rarity
        ]
        feature_matrix.append(vector)
        session_ids.append(s.session_id)

    return feature_matrix, session_ids, combo_counts, total_combos


def _extract_supporting_signals(vec: List[float]) -> List[str]:
    signals = []
    if vec[12] > 0.8:
        signals.append("Rare protocol-cipher-fingerprint combination observed in capture baseline")
    if vec[11] > 0:
        signals.append(f"TLS alert packets recorded ({int(vec[11])})")
    if vec[8] > 5000:
        signals.append(f"Abnormal handshake duration ({vec[8]:.1f}ms)")
    if not signals:
        signals.append("Multi-feature statistical outlier in session parameter baseline")
    return signals


def run_isolation_forest(
    capture_id: str,
    db: DBSession,
    feature_matrix: List[List[float]],
    session_ids: List[str]
):
    """
    Default Production Model: Scikit-Learn IsolationForest on local CPU.
    Calibrated against synthetic test corpus baseline.
    """
    import numpy as np
    from sklearn.ensemble import IsolationForest

    X = np.array(feature_matrix, dtype=float)

    # Train local Isolation Forest with 0.1 contamination
    clf = IsolationForest(contamination=0.1, random_state=42)
    clf.fit(X)
    scores = clf.decision_function(X)  # lower = more abnormal
    predictions = clf.predict(X)       # -1 = anomaly

    model_id = "IsolationForest-1.0-local"

    for i, pred in enumerate(predictions):
        if pred == -1:
            sess_id = session_ids[i]
            anom_score = float(scores[i])
            finding_id = f"anom-{uuid.uuid4().hex}"
            signals = _extract_supporting_signals(feature_matrix[i])

            finding = Finding(
                finding_id=finding_id,
                capture_id=capture_id,
                session_id=sess_id,
                rule_id="FP-001",
                ml_model_id=model_id,
                title="Suspicious TLS fingerprint / behavioural anomaly",
                severity="LOW",
                confidence="MEDIUM CONFIDENCE",
                protocol="SMTP",
                evidence_json={
                    "model_id": model_id,
                    "anomaly_score": round(anom_score, 4),
                    "confidence": "MEDIUM CONFIDENCE",
                    "supporting_signals": signals,
                    "model_name": "IsolationForest",
                    "model_version": "1.0-local",
                    "device": "cpu",
                    "qualifier": "Not proof of malicious activity."
                },
                impact="Session exhibits atypical parameters relative to the capture baseline.",
                recommendation="Investigate client software profile and verify if session originates from non-standard email agent or testing tool.",
                limitations_json={
                    "note": "Unsupervised anomaly detection: flags statistical outliers, not definitive security violations."
                },
                standards_ref="ML Baseline (Behavioural Anomaly Analysis)",
                category="Behavioural Anomaly"
            )
            db.add(finding)

    db.commit()


def run_pytorch_autoencoder(
    capture_id: str,
    db: DBSession,
    feature_matrix: List[List[float]],
    session_ids: List[str],
    force_device: Optional[str] = None
):
    """
    Optional / Experimental Model: Deep Neural Autoencoder running on PyTorch.
    Leverages CUDA (RTX GPU) if available, with automatic CPU fallback.
    Marked as experimental per user instruction (unvalidated against synthetic corpus).
    """
    import numpy as np
    import torch
    import torch.nn as nn
    import torch.optim as optim

    # Determine execution device (CUDA GPU if available, else CPU)
    if force_device:
        device = torch.device(force_device)
    else:
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    device_str = device.type
    device_name = torch.cuda.get_device_name(0) if device_str == "cuda" else "CPU"
    model_id = f"PyTorch-Autoencoder-1.0-experimental ({device_str.upper()})"

    logger.info(f"Running experimental PyTorch Autoencoder on device: {device_str} ({device_name})")

    # Feature normalization (Z-score standardization)
    X = np.array(feature_matrix, dtype=np.float32)
    mean = np.mean(X, axis=0)
    std = np.std(X, axis=0)
    std[std == 0] = 1.0  # Avoid division by zero
    X_norm = (X - mean) / std

    tensor_X = torch.tensor(X_norm, dtype=torch.float32).to(device)

    # Lightweight Neural Autoencoder Architecture (13 -> 8 -> 4 -> 8 -> 13)
    class AnomalyAutoencoder(nn.Module):
        def __init__(self):
            super().__init__()
            self.encoder = nn.Sequential(
                nn.Linear(13, 8),
                nn.ReLU(),
                nn.Linear(8, 4),
                nn.ReLU()
            )
            self.decoder = nn.Sequential(
                nn.Linear(4, 8),
                nn.ReLU(),
                nn.Linear(8, 13)
            )

        def forward(self, x):
            return self.decoder(self.encoder(x))

    torch.manual_seed(42)
    model = AnomalyAutoencoder().to(device)
    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=0.01)

    # Quick local fit (50 epochs on GPU/CPU)
    model.train()
    for _ in range(50):
        optimizer.zero_grad()
        outputs = model(tensor_X)
        loss = criterion(outputs, tensor_X)
        loss.backward()
        optimizer.step()

    # Calculate per-sample reconstruction error (MSE)
    model.eval()
    with torch.no_grad():
        reconstructed = model(tensor_X)
        sample_losses = torch.mean((tensor_X - reconstructed) ** 2, dim=1).cpu().numpy()

    # Contamination threshold at 90th percentile (top 10% highest reconstruction errors)
    threshold = float(np.percentile(sample_losses, 90))

    for i, loss_val in enumerate(sample_losses):
        if loss_val >= threshold:
            sess_id = session_ids[i]
            finding_id = f"anom-{uuid.uuid4().hex}"
            signals = _extract_supporting_signals(feature_matrix[i])

            finding = Finding(
                finding_id=finding_id,
                capture_id=capture_id,
                session_id=sess_id,
                rule_id="FP-001",
                ml_model_id=model_id,
                title="Suspicious TLS fingerprint / behavioural anomaly (Neural Autoencoder)",
                severity="LOW",
                confidence="MEDIUM CONFIDENCE",
                protocol="SMTP",
                evidence_json={
                    "model_id": model_id,
                    "reconstruction_loss": round(float(loss_val), 4),
                    "loss_threshold": round(threshold, 4),
                    "anomaly_score": round(float(-loss_val), 4),
                    "confidence": "MEDIUM CONFIDENCE",
                    "supporting_signals": signals,
                    "model_name": "PyTorch-Autoencoder",
                    "model_version": "1.0-experimental",
                    "device": device_str,
                    "device_name": device_name,
                    "experimental_status": "EXPERIMENTAL: Unvalidated against synthetic test corpus baseline",
                    "qualifier": "Not proof of malicious activity."
                },
                impact="Session exhibits atypical parameters relative to the neural network baseline.",
                recommendation="Investigate client software profile and verify if session originates from non-standard email agent or testing tool.",
                limitations_json={
                    "note": "Experimental PyTorch Autoencoder: flags statistical outliers by reconstruction error. Unvalidated against synthetic test corpus baseline."
                },
                standards_ref="ML Baseline (Behavioural Anomaly Analysis - Experimental Autoencoder)",
                category="Behavioural Anomaly"
            )
            db.add(finding)

    db.commit()


def run_anomaly_detection(capture_id: str, db: DBSession, engine: Optional[str] = None):
    """
    Executes unsupervised anomaly detection across session feature vectors.
    Default Model: IsolationForest (local CPU production model).
    Optional / Experimental: PyTorch Autoencoder (accelerated on CUDA GPU if available, with CPU fallback).
    """
    sessions = db.query(Session).filter(Session.capture_id == capture_id).all()
    if len(sessions) < 10:
        # Insufficient sessions for statistical baselining
        return

    feature_matrix, session_ids, combo_counts, total_combos = extract_session_features(sessions)

    selected_engine = (engine or settings.ML_ANOMALY_ENGINE or "isolation_forest").lower()

    if selected_engine == "autoencoder":
        try:
            logger.info("Attempting PyTorch Autoencoder anomaly detection...")
            run_pytorch_autoencoder(capture_id, db, feature_matrix, session_ids)
            return
        except Exception as e:
            logger.warning(
                "PyTorch Autoencoder unavailable or failed (%s). Gracefully falling back to default IsolationForest CPU.",
                e,
                exc_info=True
            )
            # Automatic fallback to IsolationForest
            run_isolation_forest(capture_id, db, feature_matrix, session_ids)
            return

    # Default production path
    run_isolation_forest(capture_id, db, feature_matrix, session_ids)
