"""Secure CoAP CPS Gateway Server.

Implements dual endpoints:
1. Insecure baseline Plain CoAP over UDP on port 5683 (RFC 7252)
2. Genuine Secure CoAP over DTLS 1.2 on port 5684 (RFC 7252 / RFC 7925)

Enforces Mutual X.509 Peer Authentication, Role-Based Access Control (RBAC),
and Application-Level Monotonic Replay Protection with persistent state.
"""

import asyncio
import json
import logging
import os
import time
from aiocoap import (
    Context, Message, resource,
    CHANGED, CONTENT, BAD_REQUEST, FORBIDDEN, METHOD_NOT_ALLOWED
)
from crypto_utils import CERTS_DIR, ensure_credentials
from dtls_transport import DTLSServer
from security import (
    authorized, accept_sequence, log_security_event,
    get_recent_security_events, get_security_metrics, load_replay_state
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("cps-gateway")

# Global CPS state
STATE = {
    "soil_moisture": 24.5,
    "temperature": 29.2,
    "pump_on": False,
    "started_at": time.time(),
    "plain_requests": 0,
    "dtls_requests": 0,
    "rejected_commands": 0,
    "replays_detected": 0,
    "rbac_violations": 0,
}

def payload_json(data: dict) -> bytes:
    return json.dumps(data, indent=2).encode("utf-8")

def process_coap_dispatch(req: Message, peer_identity: str, is_dtls: bool, path_override: str = None) -> Message:
    """Core dispatch logic shared between Plain and DTLS transports."""
    if is_dtls:
        STATE["dtls_requests"] += 1
    else:
        STATE["plain_requests"] += 1

    if path_override:
        path = path_override
    else:
        path_tokens = list(req.opt.uri_path)
        path = "/" + "/".join(path_tokens)
    method_code = req.code

    # 1. /sensor/moisture (GET)
    if path == "/sensor/moisture":
        if method_code != 1:  # GET
            return Message(code=METHOD_NOT_ALLOWED, payload=b"Method Not Allowed")
        return Message(code=CONTENT, payload=payload_json({
            "resource": "/sensor/moisture",
            "soil_moisture": round(STATE["soil_moisture"], 2),
            "unit": "percent",
            "timestamp": time.time(),
            "security_mode": "DTLS 1.2" if is_dtls else "Plain CoAP (Insecure)"
        }))

    # 2. /sensor/temperature (GET)
    if path == "/sensor/temperature":
        if method_code != 1:  # GET
            return Message(code=METHOD_NOT_ALLOWED, payload=b"Method Not Allowed")
        return Message(code=CONTENT, payload=payload_json({
            "resource": "/sensor/temperature",
            "temperature": round(STATE["temperature"], 2),
            "unit": "Celsius",
            "timestamp": time.time(),
            "security_mode": "DTLS 1.2" if is_dtls else "Plain CoAP (Insecure)"
        }))

    # 3. /sensor/reading (POST telemetry upload)
    if path == "/sensor/reading":
        if method_code != 2:  # POST
            return Message(code=METHOD_NOT_ALLOWED, payload=b"Method Not Allowed")
        if not authorized(peer_identity, "submit_reading"):
            STATE["rbac_violations"] += 1
            STATE["rejected_commands"] += 1
            return Message(code=FORBIDDEN, payload=b"RBAC Denied: Sensor role required to submit telemetry")
        try:
            body = json.loads(req.payload.decode("utf-8"))
            if "soil_moisture" in body:
                STATE["soil_moisture"] = float(body["soil_moisture"])
            if "temperature" in body:
                STATE["temperature"] = float(body["temperature"])
            log_security_event("TELEMETRY_UPDATED", peer_identity, "submit_reading", f"Updated sensor values", True)
            return Message(code=CHANGED, payload=payload_json({
                "status": "Telemetry updated",
                "soil_moisture": STATE["soil_moisture"],
                "temperature": STATE["temperature"]
            }))
        except Exception as e:
            STATE["rejected_commands"] += 1
            return Message(code=BAD_REQUEST, payload=f"Malformed payload: {e}".encode())

    # 4. /device/status (GET)
    if path == "/device/status":
        if method_code != 1:  # GET
            return Message(code=METHOD_NOT_ALLOWED, payload=b"Method Not Allowed")
        uptime = round(time.time() - STATE["started_at"], 2)
        metrics = get_security_metrics()
        return Message(code=CONTENT, payload=payload_json({
            "gateway_status": "online",
            "uptime_seconds": uptime,
            "actuator_pump_on": STATE["pump_on"],
            "sensor_moisture": round(STATE["soil_moisture"], 2),
            "sensor_temperature": round(STATE["temperature"], 2),
            "total_plain_requests": STATE["plain_requests"],
            "total_dtls_requests": STATE["dtls_requests"],
            "rejected_commands": STATE["rejected_commands"],
            "replays_detected": STATE["replays_detected"],
            "rbac_violations": STATE["rbac_violations"],
            "security_metrics": metrics
        }))

    # 5. /actuator/pump (GET / POST)
    if path == "/actuator/pump":
        if method_code == 1:  # GET
            return Message(code=CONTENT, payload=payload_json({
                "pump_on": STATE["pump_on"],
                "status": "RUNNING" if STATE["pump_on"] else "STOPPED"
            }))
        elif method_code == 2:  # POST
            try:
                data = json.loads(req.payload.decode("utf-8"))
                cmd = str(data.get("command", "")).upper()
                seq = data.get("sequence")
                # In plain mode, allow simulated identity from payload; in DTLS mode, use verified transport CN
                active_id = peer_identity if is_dtls else str(data.get("device_id", "unauthenticated-peer"))
            except Exception as e:
                STATE["rejected_commands"] += 1
                log_security_event("MALFORMED_INPUT", peer_identity, "control_pump", str(e), False)
                return Message(code=BAD_REQUEST, payload=b"Malformed JSON payload")

            # RBAC Enforcement
            if not authorized(active_id, "control_pump"):
                STATE["rbac_violations"] += 1
                STATE["rejected_commands"] += 1
                return Message(code=FORBIDDEN, payload=f"RBAC Forbidden: Role for '{active_id}' cannot command pump".encode())

            # Application-level Replay Protection
            replay_cache = load_replay_state()
            if not accept_sequence(active_id, seq, replay_cache):
                STATE["replays_detected"] += 1
                STATE["rejected_commands"] += 1
                return Message(code=FORBIDDEN, payload=b"Replay Attack Rejected: Stale or duplicate command sequence")

            # Command Validation
            if cmd not in ("PUMP_ON", "PUMP_OFF"):
                STATE["rejected_commands"] += 1
                return Message(code=BAD_REQUEST, payload=b"Unsupported command; use PUMP_ON or PUMP_OFF")

            STATE["pump_on"] = (cmd == "PUMP_ON")
            log.info("Pump state updated to %s by authenticated device %s (seq=%s)", cmd, active_id, seq)
            log_security_event("COMMAND_ACCEPTED", active_id, "control_pump", f"Executed {cmd} with seq={seq}", True)
            return Message(code=CHANGED, payload=payload_json({
                "accepted": True,
                "pump_on": STATE["pump_on"],
                "sequence": seq,
                "operator": active_id,
                "authenticated_by": "DTLS X.509 Certificate" if is_dtls else "Unauthenticated Demo Header"
            }))
        else:
            return Message(code=METHOD_NOT_ALLOWED, payload=b"Method Not Allowed")

    # 6. /security/events (GET)
    if path == "/security/events":
        if method_code != 1:  # GET
            return Message(code=METHOD_NOT_ALLOWED, payload=b"Method Not Allowed")
        events = get_recent_security_events(30)
        return Message(code=CONTENT, payload=payload_json({"events": events}))

    return Message(code=BAD_REQUEST, payload=f"Resource {path} not found".encode())


# ---------------- Plain CoAP Resource Adapters ----------------

class PlainResourceAdapter(resource.Resource):
    def __init__(self, path: str):
        super().__init__()
        self.path = path

    async def render_get(self, request):
        return process_coap_dispatch(request, "unauthenticated-peer", is_dtls=False, path_override=self.path)

    async def render_post(self, request):
        return process_coap_dispatch(request, "unauthenticated-peer", is_dtls=False, path_override=self.path)


def dtls_server_handler(req: Message, peer_identity: str) -> Message:
    """Callback invoked by DTLSServer with authenticated peer CN."""
    return process_coap_dispatch(req, peer_identity, is_dtls=True)


async def run_plain_coap_server(host: str = "127.0.0.1", port: int = 5683, ready_event=None):
    """Binds plain CoAP UDP server on port 5683."""
    site = resource.Site()
    site.add_resource(["sensor", "moisture"], PlainResourceAdapter("/sensor/moisture"))
    site.add_resource(["sensor", "temperature"], PlainResourceAdapter("/sensor/temperature"))
    site.add_resource(["sensor", "reading"], PlainResourceAdapter("/sensor/reading"))
    site.add_resource(["device", "status"], PlainResourceAdapter("/device/status"))
    site.add_resource(["actuator", "pump"], PlainResourceAdapter("/actuator/pump"))
    site.add_resource(["security", "events"], PlainResourceAdapter("/security/events"))

    ctx = await Context.create_server_context(site, bind=(host, port))
    if ready_event:
        ready_event.set()
    log.info("Plain CoAP baseline listening at coap://%s:%d (INSECURE)", host, port)
    return ctx


def start_gateway(host: str = "127.0.0.1", plain_port: int = 5683, dtls_port: int = 5684):
    """Starts both Plain CoAP and Secure DTLS CoAP servers concurrently."""
    ensure_credentials()
    ca_crt = os.path.join(CERTS_DIR, "ca.crt")
    gw_crt = os.path.join(CERTS_DIR, "gateway.crt")
    gw_key = os.path.join(CERTS_DIR, "gateway.key")

    # Start Secure DTLS Server
    dtls_server = DTLSServer(
        host=host,
        port=dtls_port,
        cert_path=gw_crt,
        key_path=gw_key,
        ca_path=ca_crt,
        handler_fn=dtls_server_handler
    )
    dtls_server.start()

    # Start Plain CoAP Server
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.create_task(run_plain_coap_server(host, plain_port))

    log.info("CPS Dual Gateway Server is fully operational!")
    log.info("  1. Insecure Plain CoAP: coap://%s:%d", host, plain_port)
    log.info("  2. Secure DTLS 1.2:     coaps://%s:%d", host, dtls_port)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        log.info("Shutting down Gateway...")
    finally:
        dtls_server.stop()
        loop.stop()

if __name__ == "__main__":
    start_gateway()
