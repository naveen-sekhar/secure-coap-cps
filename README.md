# Secure CoAP Communication for Cyber-Physical Systems (CPS)

A clean, working Python implementation demonstrating secure communication between IoT/CPS devices using **CoAP** (Constrained Application Protocol) and genuine **DTLS 1.2** (Datagram Transport Layer Security).

---

## 📌 What This Project Does

In typical IoT/CPS setups (e.g. smart agriculture, water treatment, industrial plants):
- **Plain CoAP over UDP** sends plain text packets without encryption. Anyone can sniff the data, spoof sensor readings, or replay commands to trigger physical actuators (e.g. pumps, valves).
- **This Project Solves That** by implementing:
  1. **Genuine DTLS 1.2 (AEAD `AES-256-GCM`)**: Encrypts all CoAP datagrams over UDP.
  2. **Mutual X.509 Certificate Authentication**: Both Gateway and Devices verify each other's digital certificates against a trusted Certificate Authority (CA).
  3. **Role-Based Access Control (RBAC)**: Sensors can only upload readings; only controllers can operate the pump.
  4. **Application-Level Replay Protection**: Monotonically increasing sequence counters reject duplicate or replayed command packets.

---

## 🏗️ Architecture & How It Works

```text
[ Sensor Node ] ----(coaps://127.0.0.1:5684)----+
(X.509: sensor-01)   [DTLS 1.2 Encrypted UDP]   |
                                                v
[ Controller  ] ----(coaps://127.0.0.1:5684)--> [ CPS Gateway Server ]
(X.509: controller-01)                          ├── 1. Mutual Certificate Verification
                                                ├── 2. Decrypt CoAP Message (AES-256-GCM)
[ Attacker    ] ----(Untrusted / Replay)------> ├── 3. Enforce RBAC (Sensor vs Controller)
(Rogue Cert / Duplicate Sequence)               ├── 4. Check Sequence > Last Seen
                                                └── 5. Control Actuator (Water Pump)
```

The server runs two endpoints at the same time:
- **Port 5683 (`coap://`)**: Insecure plain CoAP (baseline for comparison).
- **Port 5684 (`coaps://`)**: Secure DTLS 1.2 (mutual authentication & encryption).

---

## 📁 File Structure

```text
secure-coap-cps/
├── crypto_utils.py       # Generates Root CA & device X.509 certificates
├── dtls_transport.py     # OpenSSL DTLS 1.2 Client & Server transport over UDP
├── security.py           # RBAC rules, monotonic sequence replay protection, audit log
├── server.py             # Dual-mode CPS Gateway (serves Plain 5683 & DTLS 5684)
├── client.py             # CLI client for devices and attack demonstrations
├── benchmark.py          # Benchmarks latency, throughput, and CPU/memory
├── requirements.txt      # Dependencies (aiocoap, cryptography, pyOpenSSL, psutil)
├── tests/
│   ├── test_security.py   # Unit tests for RBAC & replay protection logic
│   ├── test_dtls.py       # DTLS mutual handshake & rogue certificate tests
│   └── test_integration.py# Full end-to-end integration & attack tests
└── results/
    └── benchmark_comparison.csv # Real measured benchmark data
```

---

## 🚀 Quick Start Guide

### 1. Setup Environment
```powershell
# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Generate lab X.509 certificates (CA, Gateway, Sensor, Controller, Rogue)
python crypto_utils.py
```

---

### 2. Start the CPS Gateway
In **Terminal 1**, start the gateway:
```powershell
python server.py
```
*The gateway is now listening on `coap://127.0.0.1:5683` (plain) and `coaps://127.0.0.1:5684` (secure DTLS).*

---

### 3. Run Client Commands
In **Terminal 2**, test legitimate device actions:

#### A. Read Sensor Telemetry (over secure DTLS)
```powershell
python client.py --mode dtls --device sensor get /sensor/moisture
python client.py --mode dtls --device sensor get /sensor/temperature
```

#### B. Read Device Status
```powershell
python client.py --mode dtls --device sensor get /device/status
```

#### C. Turn Pump Actuator ON / OFF (Controller Role)
```powershell
python client.py --mode dtls --device controller pump-on
python client.py --mode dtls --device controller pump-off
```

#### D. Compare with Plain CoAP (Insecure baseline)
```powershell
python client.py --mode plain get /sensor/moisture
```

---

## 🛡️ Attack Demonstrations

Run these commands to see the security defenses in action:

### 1. Replay Attack Defense
An attacker captures a valid `pump-on` command and replays it later:
```powershell
python client.py replay-attack
```
- **Step 1:** Legitimate command is accepted (`2.04 Changed`).
- **Step 2:** Replayed command with duplicate sequence is **rejected** (`4.03 Forbidden: Replay Attack Rejected`).

### 2. Rogue Certificate Attack Defense
An attacker creates a fake certificate signed by an untrusted rogue CA:
```powershell
python client.py rogue-attack
```
- **Result:** Gateway terminates connection during DTLS handshake (`tlsv1 alert unknown ca`). Attack packet never reaches the application.

### 3. Privilege Escalation Defense
A sensor tries to command the pump actuator:
```powershell
python client.py privilege-escalation
```
- **Result:** Gateway enforces RBAC and rejects the command (`4.03 Forbidden: RBAC Forbidden: Role for 'sensor-01' cannot command pump`).

---

## 🧪 Run Automated Tests

Run the complete test suite (19 automated tests):
```powershell
python -m unittest discover -s tests -v
```
All 19 tests pass:
- RBAC permissions & identity checks
- DTLS handshake & cipher validation
- Rogue certificate blocking
- Replay attack rejection
- End-to-end telemetry and pump control

---

## 📊 Performance Benchmark

Compare performance between Plain CoAP and Secure DTLS CoAP:
```powershell
python benchmark.py --requests 30
```

### Actual Measured Results (Local Loopback)

| Metric | Plain CoAP (Insecure 5683) | Secure CoAP (DTLS 1.2 5684) | Explanation |
|---|---|---|---|
| **Success Rate** | 30 / 30 (100%) | 30 / 30 (100%) | Both transports are reliable |
| **Throughput** | ~2,300 req/s | ~50 req/s | DTLS executes full mutual crypto handshake |
| **Median Latency** | 0.30 ms | 18.34 ms | Sub-millisecond vs ~18 ms with cryptographic key exchange |
| **Handshake Time** | 0.00 ms (None) | 13.02 ms | ECDHE key exchange + RSA certificate validation |
| **Memory Footprint**| 76.9 MB | 78.1 MB | Lightweight (~1.2 MB difference) |
| **Security** | None (Cleartext) | **AES-256-GCM AEAD** | Mutual Authentication & Encryption |

---

## 💡 Summary of Changes Made
- **Removed Dashboard:** Dropped `dashboard.py` and removed heavy dependencies (`streamlit`, `pandas`, `altair`, etc.).
- **Streamlined Codebase:** Kept only core, essential logic (`server.py`, `client.py`, `dtls_transport.py`, `security.py`, `crypto_utils.py`, `benchmark.py`).
- **Clean CLI & Benchmark:** Simplified client commands and terminal benchmark reporting.
- **Fast & Direct:** Clear documentation explaining how the system works without unnecessary fluff.
