# Secure CoAP Communication for Resource-Constrained CPS

Educational Python prototype. The first milestone is **plain CoAP over UDP on loopback**, not a secure deployment. Do not expose it to a network or use it to control real hardware.

The JSON `device_id` is a demo identity, not cryptographic authentication. This project is not DTLS-secured until a compatible CoAP/DTLS implementation is configured and the handshake and packet-protection tests pass. Do not replace DTLS with homemade encryption.

## Setup (Windows PowerShell)
```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```
If activation is blocked, use `.\.venv\Scripts\python.exe -m pip install -r requirements.txt` and run commands with that Python executable.

## Run the first working component
Terminal 1:
```powershell
python server.py
```
Terminal 2:
```powershell
python client.py get /sensor/moisture
python client.py get /sensor/temperature
python client.py get /device/status
python client.py pump-on
python client.py get /actuator/pump
```
Server binds only to `127.0.0.1:5683`.

## Tests and baseline
```powershell
python -m unittest discover -s tests -v
python benchmark.py --requests 100
streamlit run dashboard.py
```
The benchmark writes `results/plain_coap_baseline.csv`. Results are local-loopback measurements, not evidence of performance on constrained physical hardware.

## One-week plan
1. Day 1: Run plain CoAP client/server; understand resources and response codes.
2. Day 2: Implement roles and authorization; label JSON identity as simulation-only.
3. Day 3: Configure actual DTLS using a maintained CoAP implementation and a documented, supported DTLS backend.
4. Day 4: Add persistent, concurrency-safe command IDs/sequence tracking and test duplicates.
5. Day 5: Add resource metrics and compare plain CoAP with DTLS.
6. Day 6: Run normal, invalid-credential, unauthorized-action, replay, and malformed-input tests.
7. Day 7: Capture packets in Wireshark, make graphs, document limitations and results.

## DTLS integration gate
- Choose a maintained CoAP implementation whose current docs explicitly support DTLS on your OS.
- Follow official credential and URI configuration instructions.
- Use lab-only credentials and bind to loopback.
- Verify a legitimate peer can complete a DTLS handshake and GET `/sensor/moisture`.
- Verify invalid credentials fail authentication.
- Capture traffic in Wireshark and verify application payload is not visible as plaintext.
- Record library version, backend, cipher suite, and authentication mode.
- If Python DTLS support is unreliable on Windows, use WSL2 with a documented native CoAP/DTLS stack or another maintained implementation with a supported backend. Do not claim DTLS is implemented until these tests pass.

## Architecture and resources
Simulated sensor/controller -> CoAP resources -> CPS gateway -> logs/metrics -> dashboard.

- `GET /sensor/moisture`
- `GET /sensor/temperature`
- `GET /device/status`
- `GET /actuator/pump`
- `POST /actuator/pump`

## Security design targets
- Transport authentication: DTLS credentials/certificates or PSK, as supported.
- Authorization: sensors may submit readings; controllers may issue actuator commands.
- Transport replay defense: handled by the DTLS implementation.
- Application replay defense: unique command IDs or monotonic per-device sequences; persist state and update atomically.
- Resource management: latency, success/failure counts, process CPU and memory. Energy remains simulated unless measured with physical equipment.

This is an academic lab prototype. The first milestone is deliberately insecure plain CoAP. App-level identity fields do not authenticate a peer.
