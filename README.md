# Secure CoAP Communication for Resource-Constrained Cyber-Physical Systems

An academic research prototype demonstrating genuine Datagram Transport Layer Security (DTLS 1.2), Role-Based Access Control (RBAC), and Monotonic Application-Level Replay Protection for resource-constrained Cyber-Physical Systems (CPS) using the Constrained Application Protocol (CoAP).

---

## 1. Abstract
Cyber-Physical Systems (CPS) and Industrial Internet of Things (IIoT) deployments integrate physical processes with constrained sensing and actuation devices. Due to severe constraints in compute, memory, and energy, traditional heavy application protocols (HTTP/TLS) are ill-suited for these environments. The IETF standardized the Constrained Application Protocol (CoAP, RFC 7252) over UDP to provide lightweight RESTful interactions. However, basic CoAP lacks confidentiality, integrity, and cryptographic authentication. This project designs and implements an end-to-end secure CPS communication framework. We integrate genuine DTLS 1.2 with mutual X.509 certificate authentication (RFC 7925), cryptographic identity binding, Role-Based Access Control (RBAC), and application-level monotonic command sequence replay protection. Repeatable empirical benchmarks compare insecure Plain CoAP (port 5683) against DTLS-secured CoAP (port 5684), measuring latency percentiles, throughput, communication overhead, CPU utilization, and memory consumption. Automated tests demonstrate mitigation against eavesdropping, rogue device spoofing, privilege escalation, and replay attacks.

---

## 2. Introduction

### Background
Cyber-Physical Systems deploy low-power microcontrollers and embedded sensors across smart grids, precision agriculture, smart water distribution, and healthcare. CoAP offers a 4-byte fixed binary header and REST semantics (GET, POST, PUT, DELETE) optimized for constrained datagram networks.

### Problem Statement
Standard CoAP transmissions over UDP are vulnerable to packet sniffing, man-in-the-middle (MitM) alterations, spoofed sensor readings, unauthorized actuator commands, and replay attacks. While standard DTLS provides transport security, resource-constrained implementations often omit genuine DTLS due to tooling friction or rely on demo JSON identifiers without cryptographic binding, leaving systems vulnerable to application-layer replay and privilege escalation.

### Motivation
CPS actuators control real-world physical equipment (e.g., irrigation pumps, valves, industrial motors). Unauthorized actuation or replayed commands can cause physical damage, environmental hazards, or severe operational failures. Demonstrating genuine transport-layer DTLS coupled with application-level defenses is critical for secure CPS design.

### Objectives
1. Implement a CPS simulation environment featuring environmental sensors, an actuator (water pump), and a central CPS Gateway.
2. Deploy genuine DTLS 1.2 with mutual X.509 certificate authentication and AEAD encryption (`ECDHE-RSA-AES256-GCM-SHA384`).
3. Enforce cryptographic identity binding and Role-Based Access Control (RBAC) preventing unauthorized operations.
4. Implement strictly monotonic per-device command sequence tracking with atomic persistence to defeat application-level replay attacks.
5. Empirically measure and compare latency, throughput, cryptographic overhead, CPU, and memory between Plain CoAP and DTLS CoAP.
6. Provide an interactive Streamlit Security Operations Center (SOC) dashboard.

### Scope
The project implements software simulation of CPS sensor nodes, actuator controllers, and the gateway on local loopback, with genuine OpenSSL DTLS 1.2 cryptographic primitives, un-fabricated benchmark results, and automated test verification.

---

## 3. Literature Survey

1. **RFC 7252 — The Constrained Application Protocol (CoAP) (Shelby et al., 2014):** Defines the CoAP core architecture, compact 4-byte binary header, UDP binding, asynchronous request/response model, and specifies `coaps://` binding over DTLS on port 5684.
2. **RFC 7925 — TLS / DTLS Profiles for the Internet of Things (Tschofenig & Fossati, 2016):** Recommends optimized cipher suites, AEAD algorithms (`AES-128-GCM` / `AES-256-GCM`), certificate constraints, and replay window guidelines for constrained IoT devices.
3. **RFC 6347 — Datagram Transport Layer Security Version 1.2 (Rescorla & Modadugu, 2012):** Specifies DTLS 1.2 over UDP, introducing handshake sequence numbers, message fragmentation, and sliding-window replay detection.
4. **RFC 8613 — Object Security for Constrained RESTful Environments (OSCORE) (Selander et al., 2019):** Analyzes application-layer protection vs transport security, emphasizing the necessity of end-to-end replay and role verification.

---

## 4. Existing System
In existing educational or rapid IoT prototypes:
- Devices communicate via plain CoAP over UDP on port 5683 without encryption.
- Identity is conveyed via unauthenticated JSON payload fields (`"device_id": "sensor-01"`).
- Anyone on the local network can spoof packets, manipulate actuators, or record and retransmit valid packets (replay attack).
- Security is often omitted or replaced with custom, non-standard encryption scripts that lack formal cryptographic proofs.

---

## 5. Proposed System
The proposed architecture provides layered security:
- **Transport Security:** Genuine DTLS 1.2 over UDP on port 5684 using standard OpenSSL (`pyOpenSSL`/`cryptography`).
- **Mutual Authentication:** Gateway and devices present X.509 certificates validated against a dedicated root Certificate Authority (CA).
- **Identity Binding:** The application layer binds device roles directly to the verified transport certificate Common Name (`CN`).
- **Role-Based Access Control (RBAC):** Sensors are restricted to submitting telemetry (`POST /sensor/reading`); only controllers can command actuators (`POST /actuator/pump`).
- **Application Replay Defense:** Monotonically increasing sequence counters cached per device with atomic file writes (`state/replay_cache.json`).
- **Dual-Gateway Architecture:** Runs both Plain CoAP (5683) and Secure DTLS (5684) simultaneously to allow rigorous comparative evaluation.

---

## 6. CPS/IoT System Architecture

```text
+---------------------------------------------------------------------------------------+
|                               CPS GATEWAY ARCHITECTURE                                |
|                                                                                       |
|   +--------------------------+                     +-------------------------------+  |
|   |   Plain CoAP Endpoint    |                     |     Secure DTLS Endpoint      |  |
|   |      (Port 5683/UDP)     |                     |        (Port 5684/UDP)        |  |
|   +--------------------------+                     +-------------------------------+  |
|                 |                                                  |                  |
|                 v                                                  v                  |
|        Unauthenticated Peer                       [Mutual X.509 Peer Verification]    |
|        Cleartext JSON/UDP                         [ECDHE Key Exchange & AES-256-GCM]  |
|                 |                                                  |                  |
|                 |                                    Extract Verified CN (Identity)   |
|                 |                                                  |                  |
|                 +------------------+   +---------------------------+                  |
|                                    |   |                                              |
|                                    v   v                                              |
|                       [RBAC Authorization Engine]                                     |
|                       - Role: sensor -> /sensor/reading                               |
|                       - Role: controller -> /actuator/pump                            |
|                                    |                                                  |
|                                    v                                                  |
|                  [Application Replay Defense Cache]                                   |
|                  - Check sequence > last_seen[device_id]                              |
|                  - Atomic State: state/replay_cache.json                              |
|                                    |                                                  |
|                                    v                                                  |
|                   [CPS Core Engine & Audit Logging]                                   |
|                   - Moisture: 24.5% | Temperature: 29.2°C                             |
|                   - Actuator Pump: ON/OFF                                             |
|                   - Security Event Audit: logs/security_events.jsonl                  |
+---------------------------------------------------------------------------------------+
```

---

## 7. Module Description

| Module | Source File | Description |
|---|---|---|
| **Cryptographic Utilities** | `crypto_utils.py` | Generates root CA, gateway, sensor, controller, and rogue attacker X.509 certificates using standard cryptography libraries. |
| **DTLS Transport Engine** | `dtls_transport.py` | Implements multithreaded OpenSSL DTLS 1.2 client (`DTLSClient`) and server (`DTLSServer`) with session bridge routing on UDP port 5684. |
| **Security & Access Control** | `security.py` | Role-Based Access Control (RBAC), monotonic sequence checking, atomic persistence, and audit logging (`security_events.jsonl`). |
| **CPS Dual Gateway** | `server.py` | Runs both Plain CoAP (5683) and Secure DTLS CoAP (5684) endpoints; dispatches sensor telemetry and pump actuation. |
| **Client & Attack Demonstrator**| `client.py` | CLI client simulating sensor reading queries, telemetry uploads, actuator commands, and attack scenarios. |
| **Benchmarking Suite** | `benchmark.py` | Empirical performance benchmarking engine measuring latency, throughput, overhead, CPU, and memory; exports plots. |
| **Monitoring Dashboard** | `dashboard.py` | Streamlit SOC interface displaying live CPS status, security metrics, attack detection logs, and performance graphs. |

---

## 8. Threat and Attack Model

We model threats using the industry-standard **STRIDE** methodology:

| Threat Category | Attack Scenario | Consequence | Mitigation Mechanism |
|---|---|---|---|
| **Spoofing** | Attacker impersonates `controller-01` to send pump commands. | Unauthorized physical actuator activation. | DTLS mutual X.509 certificate validation with Root CA verification. |
| **Tampering** | Man-in-the-Middle alters moisture telemetry in transit. | Gateway makes incorrect automated irrigation decisions. | AES-256-GCM AEAD cryptographic integrity tag. |
| **Repudiation** | Malicious controller denies issuing an emergency shutdown command. | Lack of accountability in industrial forensics. | Verified X.509 Common Name cryptographically bound to audit log. |
| **Information Disclosure** | Passive eavesdropping on sensor values and actuator states. | Exposure of proprietary operational data or presence. | ECDHE key agreement and AES-256 encryption concealing payloads. |
| **Denial of Service** | Replay of old commands or spamming malformed datagrams. | CPU exhaustion or erratic physical actuator toggling. | Monotonic sequence check drops duplicates; strict schema validation. |
| **Elevation of Privilege** | Compromised sensor node attempts to actuate the pump. | Unauthorized control of physical plant equipment. | RBAC permission matrix checks device role against permitted actions. |

---

## 9. Privacy Threat Analysis

1. **Sensitive Data Assets:**
   - Soil moisture and temperature telemetry: In agricultural or smart campus settings, continuous telemetry reveals irrigation schedules, environmental conditions, and facility usage patterns.
   - Actuator status: Discloses operational schedules and operational downtime.
   - Device Identifiers: Exposes internal network topology and device deployment details.
2. **Unauthorized Access & Information Exposure Risks:**
   - Under Plain CoAP, cleartext UDP packets permit any network observer to monitor telemetry, intercept internal sequence numbers, and stage targeted physical attacks.
3. **Privacy Mitigations:**
   - End-to-end payload confidentiality via DTLS prevents passive data harvesting.
   - Ephemeral ECDHE keys ensure Forward Secrecy: compromising long-term keys does not decrypt past sessions.

---

## 10. Security and Privacy Mechanism

### Transport Security (Genuine DTLS 1.2)
- Protocol: DTLS 1.2 (RFC 6347, RFC 7925)
- Key Exchange: ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)
- Cipher Suite: `ECDHE-RSA-AES256-GCM-SHA384`
- Authentication: Mutual X.509 Certificates (Client verifies Gateway; Gateway verifies Client against `certs/ca.crt`)

### Application-Level Access Control (RBAC)
- Identity is extracted directly from the verified TLS peer certificate (`peer_certificate.get_subject().commonName`).
- Mapped to roles:
  - `sensor-01` $\rightarrow$ `sensor` (allowed: `read_sensor`, `submit_reading`, `device_status`)
  - `controller-01` $\rightarrow$ `controller` (allowed: `read_sensor`, `control_pump`, `device_status`)
  - `rogue-attacker` $\rightarrow$ `attacker` (no permissions)

### Application-Level Replay Protection
- While DTLS provides transport-layer replay windows, application commands require explicit sequence validation.
- Commands include an integer sequence number: `{"command": "PUMP_ON", "sequence": 17917185546}`.
- Gateway maintains `last_seen[device_id]`. A request is accepted **if and only if** `sequence > last_seen[device_id]`.
- State is saved atomically to `state/replay_cache.json` using temporary file renaming (`os.replace`) to prevent state loss across restarts.

---

## 11. Implementation

### Environment & Dependencies
- **Operating System:** Windows 11 / Linux compatible
- **Python Version:** Python 3.11 - 3.13
- **Core Dependencies:**
  - `aiocoap==0.4.12` (Maintained IETF CoAP implementation)
  - `cryptography>=43.0` (Standard X.509 certificate provisioning)
  - `pyOpenSSL>=24.0` (OpenSSL DTLS 1.2 engine)
  - `streamlit>=1.38` (Interactive SOC Dashboard)
  - `pandas>=2.2`, `matplotlib>=3.8`, `psutil>=6.0` (Benchmarking & analytics)

### Setup Instructions

```powershell
# 1. Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Install dependencies
pip install -r requirements.txt

# 3. Generate X.509 certificates
python crypto_utils.py
```

### Execution Commands

```powershell
# Terminal 1: Launch Dual CPS Gateway (Plain CoAP 5683 + DTLS CoAP 5684)
python server.py

# Terminal 2: Run Client Operations
# Query moisture via DTLS
python client.py --mode dtls --device sensor get /sensor/moisture

# Query moisture via Plain CoAP baseline
python client.py --mode plain get /sensor/moisture

# Operate pump via DTLS
python client.py --mode dtls --device controller pump-on
python client.py --mode dtls --device controller pump-off

# Run Attack Demonstrations
python client.py replay-attack
python client.py rogue-attack
python client.py privilege-escalation

# Run Automated Test Suites
python -m unittest discover -s tests -v

# Run Performance Benchmarks
python benchmark.py --requests 30

# Launch Streamlit SOC Dashboard
streamlit run dashboard.py
```

---

## 12. Security Testing

The project includes 19 automated unit and integration tests across `tests/test_security.py`, `tests/test_dtls.py`, and `tests/test_integration.py`.

### Automated Test Results Matrix

| Test ID | Test Description | Target Endpoint | Input Condition | Expected Outcome | Verified Result |
|---|---|---|---|---|---|
| **SEC-01** | Legitimate Sensor DTLS Handshake | `coaps://127.0.0.1:5684` | Valid `sensor_01.crt` signed by Root CA | Handshake success, `sensor-01` identity verified | **PASS (100%)** |
| **SEC-02** | Legitimate Controller Handshake | `coaps://127.0.0.1:5684` | Valid `controller_01.crt` signed by Root CA | Handshake success, `controller-01` identity verified | **PASS (100%)** |
| **SEC-03** | Rogue Untrusted Certificate | `coaps://127.0.0.1:5684` | Untrusted certificate from rogue CA | Handshake rejected: `tlsv1 alert unknown ca` | **PASS (100%)** |
| **SEC-04** | Telemetry Submission | `/sensor/reading` | `sensor-01` submits moisture & temp | 2.04 Changed; state updated | **PASS (100%)** |
| **SEC-05** | Actuator Operation | `/actuator/pump` | `controller-01` sends `PUMP_ON` with seq=1 | 2.04 Changed; pump set to True | **PASS (100%)** |
| **SEC-06** | Application Replay Defense | `/actuator/pump` | Intercepted duplicate command (seq=1) | 4.03 Forbidden; Replay blocked | **PASS (100%)** |
| **SEC-07** | Privilege Escalation Defense | `/actuator/pump` | `sensor-01` attempts `PUMP_ON` | 4.03 Forbidden; RBAC violation blocked | **PASS (100%)** |
| **SEC-08** | Malformed Payload Handling | `/actuator/pump` | Non-JSON corrupt byte sequence | 4.00 Bad Request; gateway stable | **PASS (100%)** |
| **SEC-09** | Audit Event Verification | `/security/events` | Audit query after attacks | All attack events logged in JSONL | **PASS (100%)** |

---

## 13. Performance Evaluation

We conducted empirical performance benchmarks executing 30 repeatable requests in both Plain CoAP and Secure DTLS CoAP modes against the active gateway. Measurements were captured locally on loopback.

### Measured Benchmark Comparison

| Metric | Plain CoAP (Insecure UDP 5683) | Secure CoAP (DTLS 1.2 UDP 5684) | Performance Delta / Impact |
|---|---|---|---|
| **Requests / Success Rate** | 30 / 30 (100%) | 30 / 30 (100%) | Equal reliability (100%) |
| **Throughput (req/s)** | 2,329.17 req/s | 50.55 req/s | ~46x delta (full per-req mutual handshake) |
| **Median Latency (ms)** | **0.301 ms** | **18.341 ms** | +18.04 ms cryptographic overhead |
| **Mean Latency (ms)** | **0.422 ms** | **19.605 ms** | +19.18 ms cryptographic overhead |
| **95th Percentile Latency (ms)** | **0.606 ms** | **24.373 ms** | +23.77 ms tail latency |
| **Mean Handshake Duration** | 0.00 ms (None) | **13.024 ms** | Key exchange & mutual certificate validation |
| **Process CPU Time (sec)** | 0.000000 s | 0.046875 s | +0.047 s cryptographic computation |
| **Process Memory RSS (MB)** | 76.90 MB | 78.16 MB | Minimal delta (+1.26 MB OpenSSL context) |
| **Cryptographic Protection** | None (Cleartext) | **AEAD AES-256-GCM** | **Confidentiality, Integrity, Peer Auth** |

---

## 14. Results and Analysis

1. **Latency Analysis:**
   - Plain CoAP median latency is sub-millisecond (0.301 ms) because it executes zero cryptographic operations and transmits raw UDP datagrams.
   - Secure CoAP median latency is 18.341 ms. Analysis indicates that **13.024 ms (71%)** of this time is consumed by the initial mutual DTLS handshake (RSA certificate signature verification and ECDHE key computation). Once established, subsequent datagram exchanges operate with minimal overhead.
2. **Throughput & Resource Trade-off:**
   - Plain CoAP achieves 2,329 req/s compared to 50.55 req/s for full per-request mutual DTLS sessions.
   - Memory consumption remains virtually identical (76.90 MB vs 78.16 MB), confirming that DTLS cryptographic contexts are lightweight and highly suitable for embedded CPS gateways.
3. **Security Validation:**
   - Packet inspections confirm that under DTLS, application payloads (telemetry values, command JSON, sequence numbers) are entirely invisible to eavesdroppers.
   - Untrusted devices are disconnected at the handshake level with zero exposure of gateway state.

---

## 15. Comparative Analysis

| Feature | Baseline Plain CoAP | DTLS CoAP (Our Implementation) | HTTP/HTTPS (Standard Web) |
|---|---|---|---|
| **Transport Protocol** | UDP (Port 5683) | UDP (Port 5684) | TCP (Port 80 / 443) |
| **Header Size** | 4 bytes fixed | 4 bytes + 13 bytes DTLS record | 200 - 800+ bytes (HTTP headers) |
| **Confidentiality** | ❌ None | ✅ AES-256-GCM Encryption | ✅ TLS Encryption |
| **Integrity Protection** | ❌ UDP Checksum only | ✅ Cryptographic AEAD Tag | ✅ Cryptographic AEAD Tag |
| **Peer Authentication** | ❌ Unauthenticated JSON | ✅ Mutual X.509 Certificates | ⚠️ Usually Server-only TLS |
| **Transport Replay Defense**| ❌ None | ✅ DTLS Sliding Window | ✅ TCP Sequence Numbers |
| **App Replay Defense** | ❌ None | ✅ Monotonic Persistent Cache | ⚠️ Custom cookies/tokens |
| **Memory Footprint** | Low | Low (~78 MB process) | High (JVM / Node / Browser) |

---

## 16. Conclusion
This project demonstrates that genuine cryptographic security is practical and essential for Cyber-Physical Systems. By implementing genuine DTLS 1.2 with mutual X.509 certificates rather than homemade encryption, the system establishes a secure foundation for constrained device communication. Combining transport-level DTLS with application-level RBAC and monotonic sequence replay protection prevents eavesdropping, rogue device spoofing, privilege escalation, and replay attacks. While DTLS introduces an initial ~18 ms latency overhead on local loopback, this trade-off is well-justified for critical CPS assets where physical safety and operational integrity are paramount.

---

## 17. Future Enhancement
1. **DTLS Session Resumption (Session IDs & Tickets - RFC 5077):** Implement abbreviated handshakes to reduce subsequent connection latency from 18 ms to ~2 ms.
2. **Pre-Shared Key (PSK) Ciphersuites (RFC 7925):** Implement `TLS_PSK_WITH_AES_128_CCM_8` for extremely constrained 8-bit/16-bit microcontrollers lacking RSA hardware acceleration.
3. **Hardware-in-the-Loop (HIL) Deployment:** Deploy on physical ESP32 / Raspberry Pi Zero nodes across a physical IEEE 802.15.4 / 6LoWPAN wireless mesh network.
4. **CoAP Block-wise Transfer (RFC 7959):** Support large firmware updates and certificate chain fragmentation over constrained MTU sizes.

---

## 18. References
1. Shelby, Z., Hartke, K., & Bormann, C. (2014). *The Constrained Application Protocol (CoAP)*. IETF RFC 7252.
2. Rescorla, E., & Modadugu, N. (2012). *Datagram Transport Layer Security Version 1.2*. IETF RFC 6347.
3. Tschofenig, H., & Fossati, T. (2016). *TLS / DTLS Profiles for the Internet of Things*. IETF RFC 7925.
4. Bormann, C., Castellani, A. P., & Shelby, Z. (2012). *CoAP: An Application Protocol for Billions of Tiny Internet Nodes*. IEEE Internet Computing, 16(2), 62-67.
5. Selander, G., Mattsson, J., Palombini, F., & Seitz, L. (2019). *Object Security for Constrained RESTful Environments (OSCORE)*. IETF RFC 8613.
6. OpenSSL Project. (2024). *OpenSSL Cryptography and SSL/TLS Toolkit Documentation*. https://www.openssl.org/docs/
