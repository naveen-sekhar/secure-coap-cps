"""Automated verification of genuine DTLS 1.2 security mechanisms.

Tests mutual X.509 certificate authentication, cipher suite negotiation,
and rejection of rogue/untrusted devices at the DTLS transport handshake stage.
"""

import os
import unittest
import time
from aiocoap import Message, GET, CONTENT, CHANGED, FORBIDDEN
from crypto_utils import CERTS_DIR, ensure_credentials
from dtls_transport import DTLSServer, DTLSClient

class DTLSSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ensure_credentials()
        cls.ca_path = os.path.join(CERTS_DIR, "ca.crt")
        cls.srv_crt = os.path.join(CERTS_DIR, "gateway.crt")
        cls.srv_key = os.path.join(CERTS_DIR, "gateway.key")
        cls.sensor_crt = os.path.join(CERTS_DIR, "sensor_01.crt")
        cls.sensor_key = os.path.join(CERTS_DIR, "sensor_01.key")
        cls.controller_crt = os.path.join(CERTS_DIR, "controller_01.crt")
        cls.controller_key = os.path.join(CERTS_DIR, "controller_01.key")
        
        rogue_dir = os.path.join(CERTS_DIR, "rogue")
        cls.rogue_crt = os.path.join(rogue_dir, "rogue_device.crt")
        cls.rogue_key = os.path.join(rogue_dir, "rogue_device.key")

        # Echo / simple CoAP dispatcher for testing
        def test_handler(req: Message, peer_cn: str) -> Message:
            path = "/" + "/".join(req.opt.uri_path)
            return Message(
                code=CONTENT,
                payload=f"OK:peer={peer_cn}:path={path}".encode("utf-8")
            )

        cls.server_port = 5690
        cls.server = DTLSServer(
            host="127.0.0.1",
            port=cls.server_port,
            cert_path=cls.srv_crt,
            key_path=cls.srv_key,
            ca_path=cls.ca_path,
            handler_fn=test_handler
        )
        cls.server.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_legitimate_sensor_dtls_handshake_and_exchange(self):
        """Verifies mutual DTLS handshake, AEAD cipher suite, and CoAP request-response."""
        client = DTLSClient(
            cert_path=self.sensor_crt,
            key_path=self.sensor_key,
            ca_path=self.ca_path
        )
        msg = Message(code=GET, mtype=0, mid=101, uri="coaps://127.0.0.1/sensor/moisture")
        resp, stats = client.send_coap_request("127.0.0.1", self.server_port, msg)
        
        self.assertIsNotNone(resp, f"Response was None. Error: {stats.get('error')}")
        self.assertTrue(stats["peer_authenticated"])
        self.assertEqual(stats["authenticated_server"], "coap-gateway")
        self.assertIn("ECDHE", stats["cipher"])
        self.assertIn("GCM", stats["cipher"])
        self.assertIn("b'OK:peer=sensor-01:path=/sensor/moisture'", str(resp.payload))

    def test_controller_dtls_handshake(self):
        """Verifies controller device certificate passes DTLS authentication."""
        client = DTLSClient(
            cert_path=self.controller_crt,
            key_path=self.controller_key,
            ca_path=self.ca_path
        )
        msg = Message(code=GET, mtype=0, mid=102, uri="coaps://127.0.0.1/actuator/pump")
        resp, stats = client.send_coap_request("127.0.0.1", self.server_port, msg)
        
        self.assertIsNotNone(resp)
        self.assertIn("peer=controller-01", resp.payload.decode())

    def test_rogue_certificate_handshake_rejected(self):
        """Verifies that a certificate from an untrusted rogue CA is rejected during handshake."""
        rogue_client = DTLSClient(
            cert_path=self.rogue_crt,
            key_path=self.rogue_key,
            ca_path=self.ca_path
        )
        msg = Message(code=GET, mtype=0, mid=999, uri="coaps://127.0.0.1/sensor/moisture")
        resp, stats = rogue_client.send_coap_request("127.0.0.1", self.server_port, msg)
        
        self.assertIsNone(resp, "Server should not accept rogue certificate!")
        self.assertIsNotNone(stats["error"])
        self.assertIn("DTLS", stats["error"])

if __name__ == "__main__":
    unittest.main()
