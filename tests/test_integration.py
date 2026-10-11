"""End-to-end integration and security test suite for Secure CoAP CPS.

Verifies:
- Plain CoAP communication
- Genuine DTLS CoAP communication
- Sensor telemetry submission
- Controller actuator operation
- RBAC enforcement (Privilege Escalation defense)
- Monotonic application-level Replay Protection
- Rogue certificate rejection (DTLS mutual authentication defense)
- Malformed payload rejection
- Security audit event logging
"""

import json
import os
import threading
import time
import unittest
import asyncio
from aiocoap import Context, Message, GET, POST, CONTENT, CHANGED, FORBIDDEN, BAD_REQUEST
from crypto_utils import CERTS_DIR, ensure_credentials
from dtls_transport import DTLSClient, DTLSServer
from server import dtls_server_handler, run_plain_coap_server, STATE
from security import get_recent_security_events, load_replay_state, save_replay_state

class SecureCoAPIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        save_replay_state({})
        ensure_credentials()
        cls.ca_crt = os.path.join(CERTS_DIR, "ca.crt")
        cls.gw_crt = os.path.join(CERTS_DIR, "gateway.crt")
        cls.gw_key = os.path.join(CERTS_DIR, "gateway.key")
        cls.sensor_crt = os.path.join(CERTS_DIR, "sensor_01.crt")
        cls.sensor_key = os.path.join(CERTS_DIR, "sensor_01.key")
        cls.controller_crt = os.path.join(CERTS_DIR, "controller_01.crt")
        cls.controller_key = os.path.join(CERTS_DIR, "controller_01.key")
        cls.rogue_crt = os.path.join(CERTS_DIR, "rogue", "rogue_device.crt")
        cls.rogue_key = os.path.join(CERTS_DIR, "rogue", "rogue_device.key")

        cls.plain_port = 5683
        cls.dtls_port = 5684

        # Start DTLS Server
        cls.dtls_server = DTLSServer(
            host="127.0.0.1",
            port=cls.dtls_port,
            cert_path=cls.gw_crt,
            key_path=cls.gw_key,
            ca_path=cls.ca_crt,
            handler_fn=dtls_server_handler
        )
        cls.dtls_server.start()

        # Start Plain CoAP Server in a dedicated event loop thread
        cls.plain_loop = asyncio.new_event_loop()
        cls.plain_ready = threading.Event()
        def plain_runner():
            asyncio.set_event_loop(cls.plain_loop)
            cls.plain_loop.create_task(run_plain_coap_server("127.0.0.1", cls.plain_port, ready_event=cls.plain_ready))
            cls.plain_loop.run_forever()

        cls.plain_thread = threading.Thread(target=plain_runner, daemon=True)
        cls.plain_thread.start()
        cls.plain_ready.wait(timeout=5.0)

    @classmethod
    def tearDownClass(cls):
        cls.dtls_server.stop()
        cls.plain_loop.call_soon_threadsafe(cls.plain_loop.stop)

    # 1. Plain CoAP Baseline
    def test_01_plain_coap_get_moisture(self):
        async def do_get():
            ctx = await Context.create_client_context()
            try:
                msg = Message(code=GET, uri=f"coap://127.0.0.1:{self.plain_port}/sensor/moisture")
                resp = await ctx.request(msg).response
                return resp
            finally:
                await ctx.shutdown()
        resp = asyncio.run(do_get())
        self.assertEqual(resp.code, CONTENT)
        body = json.loads(resp.payload.decode())
        self.assertIn("soil_moisture", body)
        self.assertEqual(body["unit"], "percent")

    # 2. Genuine DTLS CoAP Moisture Query
    def test_02_dtls_coap_get_moisture(self):
        client = DTLSClient(self.sensor_crt, self.sensor_key, self.ca_crt)
        msg = Message(code=GET, uri=f"coaps://127.0.0.1:{self.dtls_port}/sensor/moisture")
        resp, stats = client.send_coap_request("127.0.0.1", self.dtls_port, msg)
        self.assertIsNotNone(resp)
        self.assertEqual(resp.code, CONTENT)
        self.assertTrue(stats["peer_authenticated"])
        self.assertEqual(stats["authenticated_server"], "coap-gateway")
        self.assertIn("ECDHE", stats["cipher"])

    # 3. Sensor Submitting Telemetry
    def test_03_sensor_telemetry_upload(self):
        client = DTLSClient(self.sensor_crt, self.sensor_key, self.ca_crt)
        msg = Message(code=POST, uri=f"coaps://127.0.0.1:{self.dtls_port}/sensor/reading")
        msg.payload = json.dumps({"soil_moisture": 32.1, "temperature": 27.8}).encode()
        resp, stats = client.send_coap_request("127.0.0.1", self.dtls_port, msg)
        self.assertIsNotNone(resp)
        self.assertEqual(resp.code, CHANGED)
        self.assertEqual(STATE["soil_moisture"], 32.1)
        self.assertEqual(STATE["temperature"], 27.8)

    # 4. Controller Operating Pump Actuator
    def test_04_controller_operates_pump(self):
        client = DTLSClient(self.controller_crt, self.controller_key, self.ca_crt)
        seq = load_replay_state().get("controller-01", 0) + 1
        msg = Message(code=POST, uri=f"coaps://127.0.0.1:{self.dtls_port}/actuator/pump")
        msg.payload = json.dumps({"command": "PUMP_ON", "sequence": seq}).encode()
        resp, stats = client.send_coap_request("127.0.0.1", self.dtls_port, msg)
        self.assertIsNotNone(resp)
        self.assertEqual(resp.code, CHANGED)
        self.assertTrue(STATE["pump_on"])

    # 5. Application-level Replay Protection
    def test_05_application_replay_attack_rejected(self):
        client = DTLSClient(self.controller_crt, self.controller_key, self.ca_crt)
        seq = load_replay_state().get("controller-01", 0) + 1
        # First send legitimate command
        msg1 = Message(code=POST, uri=f"coaps://127.0.0.1:{self.dtls_port}/actuator/pump")
        msg1.payload = json.dumps({"command": "PUMP_OFF", "sequence": seq}).encode()
        resp1, _ = client.send_coap_request("127.0.0.1", self.dtls_port, msg1)
        self.assertEqual(resp1.code, CHANGED)

        # Now re-send same command with identical sequence (Replay Attack)
        msg2 = Message(code=POST, uri=f"coaps://127.0.0.1:{self.dtls_port}/actuator/pump")
        msg2.payload = json.dumps({"command": "PUMP_ON", "sequence": seq}).encode()
        resp2, _ = client.send_coap_request("127.0.0.1", self.dtls_port, msg2)
        self.assertEqual(resp2.code, FORBIDDEN)
        self.assertIn(b"Replay Attack Rejected", resp2.payload)

    # 6. Privilege Escalation Defense (Sensor cannot control pump)
    def test_06_privilege_escalation_denied(self):
        client = DTLSClient(self.sensor_crt, self.sensor_key, self.ca_crt)
        seq = load_replay_state().get("sensor-01", 0) + 1
        msg = Message(code=POST, uri=f"coaps://127.0.0.1:{self.dtls_port}/actuator/pump")
        msg.payload = json.dumps({"command": "PUMP_ON", "sequence": seq}).encode()
        resp, _ = client.send_coap_request("127.0.0.1", self.dtls_port, msg)
        self.assertEqual(resp.code, FORBIDDEN)
        self.assertIn(b"RBAC Forbidden", resp.payload)

    # 7. Rogue Certificate Blocked at DTLS Handshake
    def test_07_rogue_certificate_blocked(self):
        rogue_client = DTLSClient(self.rogue_crt, self.rogue_key, self.ca_crt)
        msg = Message(code=GET, uri=f"coaps://127.0.0.1:{self.dtls_port}/sensor/moisture")
        resp, stats = rogue_client.send_coap_request("127.0.0.1", self.dtls_port, msg)
        self.assertIsNone(resp, "Rogue device must be rejected during DTLS handshake!")
        self.assertIsNotNone(stats["error"])

    # 8. Malformed Payload Rejected
    def test_08_malformed_payload_rejected(self):
        client = DTLSClient(self.controller_crt, self.controller_key, self.ca_crt)
        msg = Message(code=POST, uri=f"coaps://127.0.0.1:{self.dtls_port}/actuator/pump")
        msg.payload = b"NOT_VALID_JSON{{"
        resp, _ = client.send_coap_request("127.0.0.1", self.dtls_port, msg)
        self.assertEqual(resp.code, BAD_REQUEST)

    # 9. Audit Event Log
    def test_09_audit_events_recorded(self):
        events = get_recent_security_events(30)
        self.assertTrue(len(events) > 0)
        event_types = {e["event_type"] for e in events}
        self.assertIn("COMMAND_ACCEPTED", event_types)
        self.assertIn("REPLAY_BLOCKED", event_types)
        self.assertIn("RBAC_DENIED", event_types)

if __name__ == "__main__":
    unittest.main()
