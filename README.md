# TLSpectra

> **Evidence-Driven Cryptographic Network Forensics for Secure Email Communications**  
> *A passive, local-first cybersecurity platform for dissecting network packet captures, auditing email cryptographic posture against 21 deterministic standards-based rules, and detecting behavioral anomalies using unsupervised machine learning.*

**SIH 2026 Problem Statement:** SIH 26159 — *AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications*  
**Organization:** National Technical Research Organisation (NTRO)  
**Category:** Software | Blockchain and Cybersecurity  
**Team Name:** Neurolix  
**Team ID:** 141037  

[![Hugging Face Spaces](https://img.shields.io/badge/%F0%9F%A4%97%20Hugging%20Face-Spaces-yellow?style=for-the-badge)](https://huggingface.co/spaces/frostedpath/tlspectra)  
👉 **Live Cloud Interactive Dashboard:** [https://huggingface.co/spaces/frostedpath/tlspectra](https://huggingface.co/spaces/frostedpath/tlspectra)

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Key Architectural Differentiators](#-key-architectural-differentiators)
- [How It Works: End-to-End Pipeline](#-how-it-works-end-to-end-pipeline)
  - [Phase 1: Ingestion & Integrity Hashing](#phase-1-ingestion--integrity-hashing)
  - [Phase 2: Stream Reassembly & Protocol Classification](#phase-2-stream-reassembly--protocol-classification)
  - [Phase 3: Cryptographic & Handshake Dissection](#phase-3-cryptographic--handshake-dissection)
  - [Phase 4: Deterministic 21-Rule Compliance Engine](#phase-4-deterministic-21-rule-compliance-engine)
  - [Phase 5: Local Unsupervised Anomaly Detection](#phase-5-local-unsupervised-anomaly-detection)
  - [Phase 6: Explainable Posture Scoring](#phase-6-explainable-posture-scoring)
  - [Phase 7: Visualization & Multi-Format Reporting](#phase-7-visualization--multi-format-reporting)
- [Standards & RFC Grounding](#-standards--rfc-grounding)
- [Verified Performance Benchmarks](#-verified-performance-benchmarks)
- [Project Directory Structure](#-project-directory-structure)
- [Live Service Endpoints & Telemetry](#-live-service-endpoints--telemetry)
- [Live Cloud Preview (Hugging Face)](#-live-cloud-preview-hugging-face-spaces)
- [Quick Start: Running Locally](#-quick-start-running-locally)
  - [Option A: Native Development (Recommended)](#option-a-native-development-recommended)
  - [Option B: Containerized Deployment (Docker Compose)](#option-b-containerized-deployment-docker-compose)
- [Live Testing & Demonstration](#-live-testing--demonstration)
  - [1. One-Click Ingestion Demo (150 Ground-Truth Sessions)](#1-one-click-ingestion-demo-150-ground-truth-sessions)
  - [2. Live Network Capture Dropzone Test](#2-live-network-capture-dropzone-test)
  - [3. Multi-Format Report Builder](#3-multi-format-report-builder)
- [Automated Test Suite](#-automated-test-suite)
- [Technical Glossary](#-technical-glossary)
- [Roadmap & Defense Points](#-roadmap--defense-points)
- [License & Disclaimer](#-license--disclaimer)

---

## 🔍 Overview

**TLSpectra** addresses a fundamental operational blind spot in organizational network security: **passive, evidence-linked visibility into in-transit email encryption**.

Active network scanners (e.g. testssl.sh, SSLyze) are noisy, intrusive, and violate passive monitoring policies. Raw packet visualizers (e.g. Wireshark) expose packet bytes but lack automated compliance scoring, STARTTLS state tracking, and prioritized remediation workflows.

TLSpectra reconstructs email conversations passively from recorded network traffic (`.pcap` / `.pcapng`), walks the session across TCP and TLS handshakes, evaluates observable cryptographic attributes against authoritative standards (IETF RFCs, NIST SP 800-52 Rev. 2), and provides a transparent **0–100 Cryptographic Posture Score** with 100% packet-level traceability.

### Essential Security Questions Answered:
- Are mail relays enforcing modern **TLS 1.3** / **TLS 1.2**, or permitting vulnerable **TLS 1.0 / 1.1** fallbacks?
- Is opportunistic encryption (**STARTTLS / STLS**) being actively upgraded, silently stripped, or degraded to plaintext?
- Do negotiated cipher suites enforce **Perfect Forward Secrecy (PFS)**, or rely on static RSA, 3DES, or RC4?
- Are X.509 certificates unexpired, properly signed, and cryptographically aligned with domain identities (RFC 6125)?
- Are anomalous client or server handshake patterns emerging across traffic baselines?

---

## 🛡️ Key Architectural Differentiators

1. **Passive & Non-Intrusive:** Strictly analyzes captured packet frames. Zero active probes, zero connection handshakes sent to production mail servers.
2. **100% Local-First & Air-Gapped:** All stream reassembly, cryptographic parsing, rule evaluation, ML anomaly detection, and report generation execute locally. **Zero cloud APIs, zero external telemetry, zero risk of data leakage.**
3. **Evidence-Linked Auditability:** Every single finding links directly to verifiable raw evidence: packet frame numbers, byte offsets, hex representations, and exact RFC citations.
4. **RFC 8446 §4.4 Visibility Honesty:** TLS 1.3 encrypts certificate handshakes on the wire. TLSpectra explicitly tags encrypted certificates as `NOT_OBSERVABLE` instead of generating false-positive certificate failure alarms.
5. **Bounded Streaming Architecture:** Memory-bounded packet reader processes multi-gigabyte captures within a bounded RAM footprint without loading the full capture into memory.

---

## ⚙️ How It Works: End-to-End Pipeline

```
  ┌────────────────────────────────────────────────────────┐
  │         Raw Packet Capture (.pcap / .pcapng)           │
  └───────────────────────────┬────────────────────────────┘
                              │
                              ▼
  ┌────────────────────────────────────────────────────────┐
  │  Phase 1: Ingestion & Integrity Hashing                │
  │  • SHA-256 Forensic Integrity Checksum                 │
  │  • SQLite WAL-Mode Record Initialization               │
  └───────────────────────────┬────────────────────────────┘
                              │
                              ▼
  ┌────────────────────────────────────────────────────────┐
  │  Phase 2: Stream Reassembly & Protocol Classification  │
  │  • Bounded Stream Buffer (Zero-Copy Frame Processing)  │
  │  • TCP 4-Tuple Reassembly (IPs, Ports, Sequence/Ack)   │
  │  • Email Dissectors: SMTP (25/587/465), IMAP, POP3     │
  │  • STARTTLS Command / Response State Machine           │
  └───────────────────────────┬────────────────────────────┘
                              │
                              ▼
  ┌────────────────────────────────────────────────────────┐
  │  Phase 3: Cryptographic Dissection                     │
  │  • ClientHello: Ciphers, SNI, ALPN, Supported Groups   │
  │  • ServerHello: Selected Version & Negotiated Cipher   │
  │  • X.509 Certificate Dissection (Subject, SAN, Expiry) │
  │  • TLS 1.3 Encrypted Handshake Boundary Handling       │
  └───────────────────────────┬────────────────────────────┘
                              │
                              ▼
  ┌────────────────────────────────────────────────────────┐
  │  Phase 4: Deterministic 21-Rule Compliance Engine      │
  │  • Grounded in IETF RFCs & NIST SP 800-52 Rev. 2       │
  │  • 5-Tier Evidence Confidence Model                    │
  └───────────────────────────┬────────────────────────────┘
                              │
                              ▼
  ┌────────────────────────────────────────────────────────┐
  │  Phase 5: Local Unsupervised ML Anomaly Detection      │
  │  • 13-Dimensional Multi-Feature Vector per Session     │
  │  • Locally Fitted Isolation Forest (Pure CPU, Scikit)  │
  │  • Flags Statistical Handshake & Behavioral Outliers   │
  └───────────────────────────┬────────────────────────────┘
                              │
                              ▼
  ┌────────────────────────────────────────────────────────┐
  │  Phase 6: Explainable Posture Scoring                  │
  │  • Posture Score = 100 - sum(Capped Deductions)        │
  │  • Anti-Double-Counting Composite Logic (100% + 25%)   │
  │  • Hard Category Deduction Caps                        │
  └───────────────────────────┬────────────────────────────┘
                              │
                              ▼
  ┌────────────────────────────────────────────────────────┐
  │  Phase 7: Visualization & Multi-Format Reporting       │
  │  • FastAPI REST Endpoints (/api/v1/...)                │
  │  • React 18 + Tailwind CSS 12-Screen Analyst Console   │
  │  • Multi-Format Exports: Interactive HTML, JSON, PDF   │
  └────────────────────────────────────────────────────────┘
```

### Phase 1: Ingestion & Integrity Hashing
Upon upload, TLSpectra computes the capture's **SHA-256 cryptographic checksum** for legal and forensic chain-of-custody tracking. Metadata is recorded in SQLite configured with Write-Ahead Logging (WAL) for concurrent, lock-free analysis.

### Phase 2: Stream Reassembly & Protocol Classification
- Captures are ingested via a bounded stream buffer to guarantee low memory usage regardless of file size.
- Packets are correlated into bi-directional TCP conversations by 4-tuple: `(Client IP, Client Port, Server IP, Server Port)`.
- Reconstructs both **Implicit TLS** (Ports 465, 993, 995) and **Explicit Opportunistic TLS** (Ports 25, 587, 110, 143), maintaining a deterministic STARTTLS state machine:
  `NOT_OFFERED` $\rightarrow$ `OFFERED` $\rightarrow$ `REQUESTED` $\rightarrow$ `ACCEPTED` $\rightarrow$ `TLS_ESTABLISHED` (or `REJECTED` / `CLEARTEXT_AFTER_OFFER`).

### Phase 3: Cryptographic & Handshake Dissection
- **ClientHello:** Offered ciphers, Server Name Indication (SNI), ALPN, supported elliptic curves, signature schemes.
- **ServerHello:** Negotiated protocol version, selected cipher suite, session resumption flags.
- **X.509 Certificates (TLS $\le$ 1.2):** Full certificate chain extraction: Subject, Issuer, SAN, signature algorithm, RSA key modulus / ECC curve length, and validity windows.
- **TLS 1.3 Visibility Boundary:** In TLS 1.3 (RFC 8446 §4.4), certificates are encrypted on the wire; TLSpectra tags them `NOT_OBSERVABLE` to prevent false-positive alarms.

### Phase 4: Deterministic 21-Rule Compliance Engine
Evaluates every session against **21 deterministic security rules**:
- **Protocol Security (`TLS-001` to `TLS-007`):** Prohibits deprecated TLS 1.0/1.1 (RFC 8996), weak ciphers (RC4, 3DES, DES), static RSA key exchange (lack of PFS), and handshake alert floods.
- **STARTTLS Security (`ST-001` to `ST-003`):** Detects STARTTLS stripping, authentication credentials sent before TLS encryption, and failed upgrade attempts.
- **Certificate Security (`CERT-001` to `CERT-008`):** Flags expired certs (RFC 5280), self-signed certificates, hostname mismatches (RFC 6125), weak signatures (SHA-1/MD5), and short keys (<2048-bit RSA).
- **Flow & Behavior (`FLOW-001`):** Flags non-email traffic communicating on designated mail ports.

**5-Tier Confidence Model:**  
Every finding is tagged with an explicit confidence level:
`DIRECT` | `HIGH CONFIDENCE` | `MEDIUM CONFIDENCE` | `EXTERNAL VALIDATION` | `UNKNOWN`

### Phase 5: Local Unsupervised Anomaly Detection
- **Model:** Local Scikit-Learn **Isolation Forest** trained directly on session feature vectors extracted from the active capture.
- **Features Evaluated:** Protocol, TLS version, cipher family, forward secrecy flag, certificate quality, STARTTLS state, SNI presence, JA3/JA3S fingerprints, handshake duration, packet count, byte volume, and alert count.
- **100% Local CPU Execution:** Requires zero cloud connectivity, zero external weights, and zero GPU hardware.

### Phase 6: Explainable Posture Scoring
$$\text{Posture Score} = \max\left(0, \min\left(100, 100 - \sum \text{Capped Category Deductions}\right)\right)$$

| Category | Deduction Cap |
|---|---|
| **Cryptographic Security** | -30 points |
| **Protocol Security** | -25 points |
| **Certificate Security** | -25 points |
| **STARTTLS Security** | -15 points |
| **Behavioural Anomaly Risk** | -5 points |

**Anti-Double-Counting Logic:** When multiple related findings occur within the same session (e.g. deprecated version + weak cipher + static RSA), secondary findings are weighted at 25% rather than stacked additively, preventing disproportionate score collapse.

### Phase 7: Visualization & Multi-Format Reporting
- **Analyst Web Dashboard:** 12 purpose-built screens (Capture Overview, Findings, Email Sessions, Host Inventory, Evidence Explorer, Report Builder, Policy, Methodology, etc.).
- **Export Formats:** Generates comprehensive audit reports in **Interactive Standalone HTML**, **Structured JSON (SIEM-ready)**, and **Executive PDF**.

---

## 📜 Standards & RFC Grounding

| Authority | Standard | Subject / Requirement |
|---|---|---|
| **IETF** | **RFC 8446** | Transport Layer Security (TLS) Version 1.3 & Encrypted Handshake Boundary |
| **IETF** | **RFC 8996** | Formal Deprecation of TLS 1.0 and TLS 1.1 |
| **IETF** | **RFC 8314** | Cleartext Replacement & Implicit TLS in Email Protocols |
| **IETF** | **RFC 3207** | SMTP Service Extension for Secure SMTP over TLS (STARTTLS) |
| **IETF** | **RFC 6125** | Representation and Verification of Domain-Based Application Service Identity |
| **IETF** | **RFC 5280** | Internet X.509 PKI Certificate and CRL Profile |
| **IETF** | **RFC 7465** | Prohibiting RC4 Cipher Suites |
| **NIST** | **SP 800-52 Rev. 2** | Guidelines for the Selection, Configuration, and Use of TLS Implementations |
| **NIST** | **SP 800-131A Rev. 2** | Transitioning Cryptographic Algorithms and Key Lengths |

---

## ⚡ Verified Performance Benchmarks

The forensic ingestion pipeline was benchmarked using an automated 3-pass stress test against the 150-session reference capture on standard hardware. Complete documentation is maintained in [`docs/methodology.md`](docs/methodology.md#7-measured-benchmark-results).

### Test Environment:
- **Operating System:** Windows 11 (64-bit)
- **Processor:** Intel64 (12 Logical Cores)
- **RAM:** 15.7 GB
- **Storage:** Solid State Drive (SSD)
- **Execution Mode:** 100% Native CPU Stream Processing

### Measured Results:

| Metric | Measured Value | Standard Target | Status |
|---|---|---|---|
| **Corpus Coverage** | **150 sessions** (6 scenario categories) | Ground-Truth Baseline | ✅ Complete |
| **Run 1 Latency (Cold Ingest)** | **5.58 s** | — | — |
| **Run 2 Latency** | **1.65 s** | — | — |
| **Run 3 Latency** | **1.62 s** | — | — |
| **Median Wall-Clock Time** | **1.65 s** | $\le$ 60.0 s (Demo Latency Gate) | ✅ **Passed** |
| **Peak Working Memory** | **62.00 MB** | Bounded (< 500 MB) | ✅ **Passed** |
| **Ingestion Throughput** | **96.9 sessions/sec** | Stream-oriented reassembly | ✅ **Passed** |
| **Protocol Classification** | **100% (150/150)** | $\ge$ 95% Target | ✅ **Passed** |
| **Traceable Findings** | **160 RFC findings** | 100% Traceability | ✅ **Passed** |
| **Posture Score Integrity** | **65 / 100** | Calibrated Baseline Score | ✅ **Verified** |

---

## 📂 Project Directory Structure

```
TLSpectra/
├── backend/                        # FastAPI Backend Application
│   ├── app/
│   │   ├── api/v1/                 # REST API endpoints (captures, sessions, findings, hosts, policy)
│   │   ├── core/                   # Configuration, Database engine, Security token, Error handling
│   │   ├── ml/                     # Local Isolation Forest anomaly detection engine
│   │   ├── models/                 # SQLAlchemy ORM database models
│   │   ├── parsers/                # Streaming PCAP reader, TCP reassembler, SMTP/IMAP/POP3, TLS dissector
│   │   ├── reporting/              # Multi-format report generators (HTML, PDF, JSON)
│   │   ├── rules/                  # 21 Deterministic rule definitions & evaluator
│   │   ├── schemas/                # Pydantic request/response schemas
│   │   └── scoring/                # Posture scoring engine with anti-double-counting logic
│   ├── storage/                    # Local capture storage and reports directory
│   ├── tests/                      # Automated test suite (pytest)
│   ├── run_benchmark.py            # Automated 3-pass performance benchmark runner
│   ├── test_live_dropzone.py       # Live capture generator and dropzone simulation tester
│   ├── Dockerfile                  # Backend container configuration
│   └── requirements.txt            # Backend Python dependencies
│
├── frontend/                       # React 18 + TypeScript Web Dashboard
│   ├── src/
│   │   ├── api/                    # API client services & endpoints
│   │   ├── components/             # Reusable UI components (AppShell, FileDropzone, DataTables)
│   │   ├── pages/                  # 12 purpose-built application screens
│   │   └── types/                  # TypeScript domain models and interfaces
│   ├── Dockerfile                  # Multi-stage production container (Nginx)
│   ├── nginx.conf                  # Nginx reverse proxy configuration
│   └── package.json                # Frontend dependencies
│
├── corpus/                         # Test Data & Ground-Truth Corpus
│   ├── generator/                  # Synthetic ground-truth PCAP generator
│   ├── pcaps/                      # 150 individual scenario captures (BEHA, CERT, LEGA, MALF, SECU, STAR)
│   ├── manifests/                  # JSON verification manifests per session
│   ├── securemailscope_demo_corpus.pcap # 150-session pre-compiled reference capture
│   └── manifest_index.json         # Master manifest index
│
├── docs/                           # Documentation
│   └── methodology.md              # Technical methodology & benchmark protocol
│
├── docker-compose.yml              # Offline container orchestration specification
└── README.md                       # Master project documentation
```

---

## 🌐 Live Service Endpoints & Telemetry

When running locally, the following access points are available:

| Interface / Service | Local URL | Description |
|---|---|---|
| **Analyst Web Dashboard** | `http://localhost:5173` | React 18 + Vite UI (12 interactive screens) |
| **Interactive Swagger API** | `http://localhost:8000/api/v1/docs` | OpenAPI interactive documentation and test explorer |
| **Alternative ReDoc API** | `http://localhost:8000/api/v1/redoc` | Formatted API specifications |
| **Health & Telemetry** | `http://localhost:8000/api/v1/health` | Service health, SQLite status & ML engine telemetry |
| **Default Bearer Token** | `sms_sec_token_v1` | Static authorization token for API endpoints & UI |

---

## 🚀 Quick Start: Running Locally

### Option A: Native Development (Recommended)

#### 1. Start the Backend (Port 8000)
Open a terminal in the `backend/` directory:

```bash
cd backend
```

Create and activate the virtual environment:

* **Windows (PowerShell):**
  ```powershell
  python -m venv .venv
  .\.venv\Scripts\Activate.ps1
  ```
* **Windows (Command Prompt):**
  ```cmd
  python -m venv .venv
  .venv\Scripts\activate
  ```
* **Linux / macOS:**
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  ```

Install dependencies:
```bash
pip install -r requirements.txt
```

Launch the FastAPI server:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
*Direct execution on Windows without activating:*
```cmd
.venv\Scripts\python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

* API will be active at: `http://localhost:8000`
* Swagger docs: `http://localhost:8000/api/v1/docs`

---

#### 2. Start the Frontend (Port 5173)
Open a second terminal in the `frontend/` directory:

```bash
cd frontend
npm install
npm run dev
```

* Web Dashboard will be live at: **`http://localhost:5173`**
* The frontend automatically proxies `/api` calls to `http://localhost:8000`.

---

### Option B: Containerized Deployment (Docker Compose)

If Docker Desktop is installed, start the entire stack with a single command:

```bash
docker-compose up --build
```

Access points:
* **Frontend Dashboard:** `http://localhost:3000`
* **Backend API:** `http://localhost:8000`
* **API Documentation:** `http://localhost:8000/api/v1/docs`

---

### 🌐 Live Cloud Preview (Hugging Face Spaces)

Experience the full interactive SOC dashboard directly in your browser without local installation or Docker:

👉 **[https://huggingface.co/spaces/frostedpath/tlspectra](https://huggingface.co/spaces/frostedpath/tlspectra)**

* **0–100 Cryptographic Posture Score:** Visual breakdown and deduction audit trail.
* **Email Stream Dissection:** Full visibility into SMTP, IMAP, and POP3 handshakes and STARTTLS state transitions.
* **160 RFC/NIST Findings:** Frame-by-frame evidence inspection and mitigation guidance.
* **Real-time Assessment Policy:** Customizable security thresholds and scoring weights.

---

## 🧪 Live Testing & Demonstration

### 1. One-Click Ingestion Demo (150 Ground-Truth Sessions)
When you open `http://localhost:5173`, the **New Analysis** screen features dedicated **One-Click Demonstration Buttons**:
* Click **"⚡ 150-Session Ground-Truth Corpus"**: Instantly loads the calibrated reference capture into **Capture Overview** with the **65/100 Posture Score**, full session breakdown, and 160 RFC findings.
* Click **"🧪 Live Sample Dropzone Capture"**: Loads a multi-flow live capture featuring SMTP + STARTTLS (TLS 1.3), SMTPS, IMAPS, and Plaintext Auth violations.

### 2. Live Network Capture Dropzone Test
To test live capture ingestion and stream reassembly on the fly:
```cmd
# Run live dropzone simulation test:
.venv\Scripts\python test_live_dropzone.py

# Or test with any external packet capture:
.venv\Scripts\python test_live_dropzone.py --pcap path/to/capture.pcap
```

### 3. Multi-Format Report Builder
Navigate to **Report Builder** (`/report-builder`) in the dashboard to trigger one-click exports:
* **HTML Document:** Standalone interactive offline report with linked evidence.
* **Structured JSON:** Machine-readable report formatted for SIEM ingestion.
* **PDF Report:** Executive-ready cryptographic security assessment document.

---

## 🔬 Automated Test Suite

### Run Backend Integration Tests
From the `backend/` directory:
```bash
pytest tests/ -v
```
*Validates API endpoints, packet parsers, rule evaluation, and posture scoring calculations.*

### Validate Frontend Production Build
From the `frontend/` directory:
```bash
npm run build
```
*Validates TypeScript correctness and compiles the optimized production distribution.*

---

## 📖 Technical Glossary

| Term | Meaning / Context |
|---|---|
| **TLSpectra** | The evidence-driven cryptographic network forensics platform |
| **SIH 26159** | Smart India Hackathon problem statement by NTRO |
| **NTRO** | National Technical Research Organisation |
| **SMTP** | Simple Mail Transfer Protocol (ports 25, 587, 465) |
| **IMAP** | Internet Message Access Protocol (ports 143, 993) |
| **POP3** | Post Office Protocol version 3 (ports 110, 995) |
| **STARTTLS** | Protocol command upgrading a cleartext TCP connection to TLS |
| **TLS** | Transport Layer Security cryptographic privacy protocol |
| **PFS** | Perfect Forward Secrecy (ephemeral key exchange protecting past traffic) |
| **ECDHE** | Elliptic-Curve Diffie–Hellman Ephemeral key exchange |
| **RSA** | Asymmetric algorithm used for key transport and digital signatures |
| **AES-GCM** | Authenticated symmetric encryption cipher mode |
| **SNI** | Server Name Indication (TLS extension indicating destination host) |
| **ALPN** | Application-Layer Protocol Negotiation extension |
| **SAN** | Subject Alternative Name (X.509 certificate extension for domain matching) |
| **JA3 / JA3S** | TLS client and server handshake fingerprinting algorithms |
| **PCAP / PCAPNG** | Standard network packet capture container formats |
| **WAL** | SQLite Write-Ahead Logging mode enabling concurrent read/write operations |
| **NIST** | National Institute of Standards and Technology (SP 800-52 Rev. 2) |
| **IETF** | Internet Engineering Task Force (standards organization publishing RFCs) |

---

## 🗺️ Roadmap & Defense Points

### Pre-Presentation Gate (100% Completed)
- [x] **Run Formal Performance Benchmark** *(Recorded in [docs/methodology.md](docs/methodology.md#7-measured-benchmark-results))*
- [x] **Validate Multi-Format Report Downloads** *(Verified in Report Builder UI: HTML, JSON, PDF)*
- [x] **Live Network Capture Dropzone Test** *(Verified via `test_live_dropzone.py`)*

### Technical Q&A Defense for Evaluators
* **"Why not just use Wireshark or Zeek?"**  
  $\rightarrow$ Wireshark decodes packets, and Zeek outputs event logs. Neither computes an automated cryptographic posture score, evaluates email compliance against RFCs/NIST rules, or verifies STARTTLS state transitions into prioritized remediation actions.
* **"How do you handle encrypted TLS 1.3 certificates?"**  
  $\rightarrow$ Per RFC 8446 §4.4, certificates in TLS 1.3 are encrypted in flight. TLSpectra explicitly tags them as `NOT_OBSERVABLE` to prevent false-positive alarms.
* **"Why an unsupervised Isolation Forest?"**  
  $\rightarrow$ Purely local, CPU-bound, zero cloud APIs, zero pre-trained weights. Adapts dynamically to the specific baseline of each organization's capture without leaking sensitive email traffic.

---

## ⚖️ License & Disclaimer

- **License:** Open-source for academic and evaluation purposes under SIH 2026.
- **Privacy Notice:** TLSpectra performs passive inspection of protocol headers and cryptographic metadata. It does not store or process email body contents or attachments.
- **Machine Learning Disclaimer:** Behavioral anomaly detection scores reflect statistical deviations from the capture baseline and do not constitute definitive proof of malicious activity.
- **Scoring Methodology Disclaimer:** Posture score deduction weights are documented engineering design decisions calibrated against the synthetic test corpus, rather than a single universal industry-standard formula.
