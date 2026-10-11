"""Multi-mode CoAP CPS Client and Attack Demonstrator.

Supports:
1. Plain CoAP over UDP (Insecure baseline)
2. Secure CoAP over DTLS 1.2 (Mutual X.509 authenticated)
3. Simulated Devices: Sensor, Controller, Rogue Attacker
4. Attack Scenarios: Replay Attack, Rogue Certificate Attack, Privilege Escalation
"""

import argparse
import asyncio
import json
import os
import time
from aiocoap import Context, Message, GET, POST
from crypto_utils import CERTS_DIR, ensure_credentials
from dtls_transport import DTLSClient

PLAIN_BASE = "coap://127.0.0.1:5683"
DTLS_HOST = "127.0.0.1"
DTLS_PORT = 5684

ensure_credentials()

CA_PATH = os.path.join(CERTS_DIR, "ca.crt")
DEVICE_CREDS = {
    "sensor": (os.path.join(CERTS_DIR, "sensor_01.crt"), os.path.join(CERTS_DIR, "sensor_01.key")),
    "controller": (os.path.join(CERTS_DIR, "controller_01.crt"), os.path.join(CERTS_DIR, "controller_01.key")),
    "rogue": (os.path.join(CERTS_DIR, "rogue", "rogue_device.crt"), os.path.join(CERTS_DIR, "rogue", "rogue_device.key"))
}

async def execute_plain_coap(method, path: str, payload_data: dict = None, device_id: str = "controller-01"):
    """Sends a request via insecure Plain CoAP on port 5683."""
    protocol = await Context.create_client_context()
    try:
        uri = PLAIN_BASE + path
        msg = Message(code=method, uri=uri)
        if payload_data is not None:
            if "device_id" not in payload_data:
                payload_data["device_id"] = device_id
            msg.payload = json.dumps(payload_data).encode("utf-8")
            
        start = time.perf_counter()
        resp = await protocol.request(msg).response
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        
        print(f"[Plain CoAP] Response Code: {resp.code} | Latency: {elapsed_ms:.2f} ms")
        print(f"[Plain CoAP] Security: None (Cleartext UDP on port 5683)")
        _print_payload(resp.payload)
        return resp
    finally:
        await protocol.shutdown()

def execute_dtls_coap(method, path: str, payload_data: dict = None, device: str = "controller"):
    """Sends a request via secure DTLS 1.2 on port 5684."""
    cert_path, key_path = DEVICE_CREDS.get(device, DEVICE_CREDS["controller"])
    client = DTLSClient(cert_path=cert_path, key_path=key_path, ca_path=CA_PATH, timeout=4.0)
    
    uri = f"coaps://{DTLS_HOST}:{DTLS_PORT}{path}"
    msg = Message(code=method, uri=uri)
    if payload_data is not None:
        msg.payload = json.dumps(payload_data).encode("utf-8")
        
    resp, stats = client.send_coap_request(DTLS_HOST, DTLS_PORT, msg)
    if resp is None:
        print(f"[DTLS CoAP] Request FAILED!")
        print(f"  Error: {stats.get('error')}")
        print(f"  Total Duration: {stats.get('total_time_ms', 0):.2f} ms")
        return None
        
    print(f"[DTLS CoAP] Response Code: {resp.code} | Total Latency: {stats['total_time_ms']:.2f} ms")
    print(f"[DTLS CoAP] Handshake Time: {stats['handshake_time_ms']:.2f} ms | Cipher: {stats['cipher']}")
    print(f"[DTLS CoAP] Peer Server Verified: {stats['authenticated_server']}")
    print(f"[DTLS CoAP] Wire Bytes: {stats['wire_bytes_sent']} sent / {stats['wire_bytes_received']} received")
    _print_payload(resp.payload)
    return resp

def _print_payload(payload_bytes: bytes):
    if not payload_bytes:
        return
    try:
        parsed = json.loads(payload_bytes.decode("utf-8"))
        print("Payload:")
        print(json.dumps(parsed, indent=2))
    except Exception:
        print(f"Payload: {payload_bytes.decode('utf-8', errors='replace')}")

def main():
    parser = argparse.ArgumentParser(description="Secure CoAP CPS Client & Attack Demonstration")
    parser.add_argument("--mode", choices=["plain", "dtls"], default="dtls", help="Transport mode")
    parser.add_argument("--device", choices=["sensor", "controller", "rogue"], default="controller", help="Simulated device")
    
    sub = parser.add_subparsers(dest="action", required=True)
    
    # GET
    get_p = sub.add_parser("get")
    get_p.add_argument("path", choices=[
        "/sensor/moisture", "/sensor/temperature", "/device/status", "/actuator/pump", "/security/events"
    ])
    
    # PUMP COMMANDS
    on_p = sub.add_parser("pump-on")
    on_p.add_argument("--sequence", type=int, default=None)
    
    off_p = sub.add_parser("pump-off")
    off_p.add_argument("--sequence", type=int, default=None)

    # UPLOAD SENSOR TELEMETRY
    tele_p = sub.add_parser("upload-reading")
    tele_p.add_argument("--moisture", type=float, default=28.5)
    tele_p.add_argument("--temperature", type=float, default=31.0)
    
    # ATTACK DEMONSTRATIONS
    sub.add_parser("replay-attack")
    sub.add_parser("rogue-attack")
    sub.add_parser("privilege-escalation")

    args = parser.parse_args()

    # 1. GET
    if args.action == "get":
        if args.mode == "plain":
            asyncio.run(execute_plain_coap(GET, args.path, device_id=f"{args.device}-01"))
        else:
            execute_dtls_coap(GET, args.path, device=args.device)

    # 2. PUMP ON / OFF
    elif args.action in ("pump-on", "pump-off"):
        cmd = "PUMP_ON" if args.action == "pump-on" else "PUMP_OFF"
        seq = args.sequence if args.sequence is not None else int(time.time() * 10)
        data = {"command": cmd, "sequence": seq}
        if args.mode == "plain":
            asyncio.run(execute_plain_coap(POST, "/actuator/pump", data, device_id=f"{args.device}-01"))
        else:
            execute_dtls_coap(POST, "/actuator/pump", data, device=args.device)

    # 3. UPLOAD TELEMETRY
    elif args.action == "upload-reading":
        data = {"soil_moisture": args.moisture, "temperature": args.temperature}
        if args.mode == "plain":
            asyncio.run(execute_plain_coap(POST, "/sensor/reading", data, device_id=f"{args.device}-01"))
        else:
            execute_dtls_coap(POST, "/sensor/reading", data, device=args.device)

    # 4. REPLAY ATTACK DEMONSTRATION
    elif args.action == "replay-attack":
        fixed_seq = int(time.time() * 10)
        print(f"\n[DEMO] Initiating Application-Level Replay Attack with sequence={fixed_seq}...")
        print("Step 1: Sending legitimate command...")
        cmd_data = {"command": "PUMP_ON", "sequence": fixed_seq}
        if args.mode == "plain":
            asyncio.run(execute_plain_coap(POST, "/actuator/pump", cmd_data, device_id="controller-01"))
        else:
            execute_dtls_coap(POST, "/actuator/pump", cmd_data, device="controller")
            
        print("\nStep 2: Attacker replaying intercepted command packet (identical sequence)...")
        if args.mode == "plain":
            asyncio.run(execute_plain_coap(POST, "/actuator/pump", cmd_data, device_id="controller-01"))
        else:
            execute_dtls_coap(POST, "/actuator/pump", cmd_data, device="controller")

    # 5. ROGUE CERTIFICATE ATTACK DEMONSTRATION
    elif args.action == "rogue-attack":
        print("\n[DEMO] Initiating Rogue Certificate Attack (untrusted CA certificate)...")
        execute_dtls_coap(GET, "/sensor/moisture", device="rogue")

    # 6. PRIVILEGE ESCALATION ATTACK DEMONSTRATION
    elif args.action == "privilege-escalation":
        print("\n[DEMO] Initiating Privilege Escalation: Sensor device attempting to command Actuator pump...")
        seq = int(time.time() * 10)
        cmd_data = {"command": "PUMP_ON", "sequence": seq}
        if args.mode == "plain":
            asyncio.run(execute_plain_coap(POST, "/actuator/pump", cmd_data, device_id="sensor-01"))
        else:
            execute_dtls_coap(POST, "/actuator/pump", cmd_data, device="sensor")

if __name__ == "__main__":
    main()
