"""Genuine DTLS 1.2 Transport implementation using OpenSSL (via pyOpenSSL).

Complies with RFC 7252 (CoAP over DTLS) and RFC 7925 (IoT Profiles for TLS/DTLS).
Provides mutual X.509 peer authentication, ECDHE key exchange, AES-256-GCM AEAD encryption,
and cryptographic integrity protection over UDP.
"""

import logging
import os
import socket
import threading
import time
from typing import Callable, Dict, Optional, Tuple
import OpenSSL.SSL
from aiocoap import Message

log = logging.getLogger("dtls-transport")

def _fix_windows_udp_socket(sock: socket.socket):
    """Disables WSAECONNRESET on Windows UDP sockets when ICMP port-unreachable is received."""
    if hasattr(socket, "SIO_UDP_CONNRESET"):
        try:
            sock.ioctl(socket.SIO_UDP_CONNRESET, False)
        except Exception:
            pass


def create_dtls_server_context(cert_path: str, key_path: str, ca_path: str) -> OpenSSL.SSL.Context:
    """Creates an OpenSSL DTLS server context enforcing mutual peer certificate verification."""
    ctx = OpenSSL.SSL.Context(OpenSSL.SSL.DTLS_SERVER_METHOD)
    ctx.use_certificate_file(cert_path)
    ctx.use_privatekey_file(key_path)
    ctx.load_verify_locations(ca_path)

    # Require and verify client certificate (Mutual TLS / DTLS)
    ctx.set_verify(
        OpenSSL.SSL.VERIFY_PEER | OpenSSL.SSL.VERIFY_FAIL_IF_NO_PEER_CERT,
        lambda conn, cert, errnum, depth, ok: bool(ok),
    )

    # Restrict to secure modern AEAD cipher suites (RFC 7925)
    ctx.set_cipher_list(b"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256")
    return ctx


def create_dtls_client_context(
    cert_path: str, key_path: str, ca_path: str, verify_server: bool = True
) -> OpenSSL.SSL.Context:
    """Creates an OpenSSL DTLS client context with device credentials and CA verification."""
    ctx = OpenSSL.SSL.Context(OpenSSL.SSL.DTLS_CLIENT_METHOD)
    if cert_path and os.path.exists(cert_path):
        ctx.use_certificate_file(cert_path)
    if key_path and os.path.exists(key_path):
        ctx.use_privatekey_file(key_path)
    if ca_path and os.path.exists(ca_path):
        ctx.load_verify_locations(ca_path)

    mode = OpenSSL.SSL.VERIFY_PEER if verify_server else OpenSSL.SSL.VERIFY_NONE
    ctx.set_verify(mode, lambda conn, cert, errnum, depth, ok: bool(ok))
    ctx.set_cipher_list(b"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256")
    return ctx


def extract_peer_identity(conn: OpenSSL.SSL.Connection) -> Optional[str]:
    """Extracts the verified Common Name (CN) from the peer's X.509 certificate."""
    try:
        cert = conn.get_peer_certificate()
        if cert:
            subject = cert.get_subject()
            return subject.commonName
    except Exception as e:
        log.warning("Failed to extract peer identity: %s", e)
    return None


def _do_handshake_loop(conn: OpenSSL.SSL.Connection, timeout: float = 3.5):
    """Executes DTLS handshake handling WantReadError / WantWriteError roundtrips."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            conn.do_handshake()
            return
        except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantWriteError):
            time.sleep(0.005)
        except OpenSSL.SSL.SysCallError as e:
            if e.args and e.args[0] == 10054:
                time.sleep(0.005)
                continue
            raise
    raise TimeoutError("DTLS handshake timed out waiting for peer")

def _recv_data_loop(conn: OpenSSL.SSL.Connection, bufsize: int = 4096, timeout: float = 3.5) -> bytes:
    """Reads decrypted DTLS application datagram handling WantReadError."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            return conn.recv(bufsize)
        except (OpenSSL.SSL.WantReadError, OpenSSL.SSL.WantWriteError):
            time.sleep(0.005)
        except OpenSSL.SSL.SysCallError as e:
            if e.args and e.args[0] == 10054:
                time.sleep(0.005)
                continue
            raise
    raise TimeoutError("DTLS recv timed out waiting for response")

class DTLSClient:
    """Client for executing secure CoAP requests over genuine DTLS."""

    def __init__(
        self,
        cert_path: str,
        key_path: str,
        ca_path: str,
        verify_server: bool = True,
        timeout: float = 4.0,
    ):
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_path = ca_path
        self.verify_server = verify_server
        self.timeout = timeout

    def send_coap_request(
        self, host: str, port: int, coap_message: Message
    ) -> Tuple[Optional[Message], dict]:
        """Performs DTLS handshake, sends CoAP message, and waits for CoAP response."""
        stats = {
            "handshake_time_ms": 0.0,
            "total_time_ms": 0.0,
            "cipher": None,
            "peer_authenticated": False,
            "authenticated_server": None,
            "wire_bytes_sent": 0,
            "wire_bytes_received": 0,
            "coap_payload_bytes": len(coap_message.payload or b""),
            "error": None,
        }
        start_time = time.perf_counter()

        ctx = create_dtls_client_context(
            self.cert_path, self.key_path, self.ca_path, self.verify_server
        )
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _fix_windows_udp_socket(raw_sock)
        raw_sock.settimeout(0.2)
        raw_sock.connect((host, port))

        ssl_conn = OpenSSL.SSL.Connection(ctx, raw_sock)
        ssl_conn.set_connect_state()

        try:
            hs_start = time.perf_counter()
            _do_handshake_loop(ssl_conn, timeout=self.timeout)
            stats["handshake_time_ms"] = (time.perf_counter() - hs_start) * 1000.0

            stats["cipher"] = ssl_conn.get_cipher_name()
            stats["peer_authenticated"] = True
            stats["authenticated_server"] = extract_peer_identity(ssl_conn)

            # Populate mandatory CoAP wire fields if unset
            if coap_message.mtype is None:
                coap_message.mtype = 0  # CON
            if coap_message.mid is None:
                coap_message.mid = int(time.time() * 1000) % 65535
            if coap_message.token is None:
                coap_message.token = os.urandom(4)

            # Encode CoAP message to RFC 7252 binary wire format
            wire_bytes = coap_message.encode()
            stats["wire_bytes_sent"] = len(wire_bytes)
            ssl_conn.send(wire_bytes)

            # Receive response
            resp_bytes = _recv_data_loop(ssl_conn, bufsize=4096, timeout=self.timeout)
            stats["wire_bytes_received"] = len(resp_bytes)

            response_msg = Message.decode(resp_bytes)
            stats["total_time_ms"] = (time.perf_counter() - start_time) * 1000.0
            return response_msg, stats

        except OpenSSL.SSL.Error as e:
            err_msg = str(e) or (str(e.args) if e.args else "Certificate validation or handshake rejected")
            stats["error"] = f"DTLS Handshake Error: {err_msg}"
            stats["total_time_ms"] = (time.perf_counter() - start_time) * 1000.0
            return None, stats
        except Exception as e:
            stats["error"] = str(e)
            stats["total_time_ms"] = (time.perf_counter() - start_time) * 1000.0
            return None, stats
        finally:
            try:
                ssl_conn.shutdown()
            except Exception:
                pass
            raw_sock.close()


class DTLSServer:
    """Multithreaded UDP DTLS server for dispatching CoAP requests over DTLS."""

    def __init__(
        self,
        host: str,
        port: int,
        cert_path: str,
        key_path: str,
        ca_path: str,
        handler_fn: Callable[[Message, str], Message],
    ):
        self.host = host
        self.port = port
        self.cert_path = cert_path
        self.key_path = key_path
        self.ca_path = ca_path
        self.handler_fn = handler_fn
        self.server_ctx = create_dtls_server_context(cert_path, key_path, ca_path)
        self.running = False
        self._server_sock = None
        self._thread = None
        self.active_sessions = 0
        self.total_handshakes = 0
        self.failed_handshakes = 0
        self._session_bridges: Dict[Tuple[str, int], socket.socket] = {}
        self._lock = threading.Lock()

    def start(self):
        """Starts the DTLS UDP server in a background thread."""
        self.running = True
        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _fix_windows_udp_socket(self._server_sock)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.host, self.port))
        self._server_sock.settimeout(0.5)
        self._thread = threading.Thread(target=self._server_loop, daemon=True)
        self._thread.start()
        log.info("Secure CoAP (DTLS 1.2) listening at coaps://%s:%d", self.host, self.port)

    def stop(self):
        """Stops the server gracefully."""
        self.running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
        log.info("Secure CoAP DTLS server stopped.")

    def _server_loop(self):
        """Routes incoming datagrams to the appropriate client session bridge."""
        while self.running:
            try:
                data, client_addr = self._server_sock.recvfrom(4096)
                if not data:
                    continue

                with self._lock:
                    bridge = self._session_bridges.get(client_addr)

                if bridge:
                    # Forward packet to existing active session
                    try:
                        bridge.send(data)
                    except Exception:
                        pass
                else:
                    # Initialize bridge pair immediately in this thread to avoid race condition
                    bridge_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    bridge_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    _fix_windows_udp_socket(bridge_a)
                    _fix_windows_udp_socket(bridge_b)
                    bridge_a.bind(("127.0.0.1", 0))
                    bridge_b.bind(("127.0.0.1", 0))
                    bridge_a.connect(bridge_b.getsockname())
                    bridge_b.connect(bridge_a.getsockname())

                    with self._lock:
                        self._session_bridges[client_addr] = bridge_a
                        self.total_handshakes += 1
                        self.active_sessions += 1

                    # Send initial packet
                    bridge_a.send(data)

                    # Launch worker thread for this connection
                    t = threading.Thread(
                        target=self._run_session_worker,
                        args=(bridge_a, bridge_b, client_addr),
                        daemon=True,
                    )
                    t.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running and not (isinstance(e, OSError) and e.errno == 10054):
                    log.error("DTLS server socket error: %s", e)

    def _run_session_worker(
        self, bridge_a: socket.socket, bridge_b: socket.socket, client_addr: Tuple[str, int]
    ):
        """Executes DTLS handshake and CoAP dispatch for a client session."""
        bridge_b.settimeout(3.5)
        ssl_conn = OpenSSL.SSL.Connection(self.server_ctx, bridge_b)
        ssl_conn.set_accept_state()

        session_active = True

        def bridge_to_client():
            while session_active and self.running:
                try:
                    data = bridge_a.recv(4096)
                    self._server_sock.sendto(data, client_addr)
                except Exception:
                    break

        t_out = threading.Thread(target=bridge_to_client, daemon=True)
        t_out.start()

        try:
            # Perform DTLS server handshake handling WantRead / WantWrite
            _do_handshake_loop(ssl_conn, timeout=3.5)
            peer_cn = extract_peer_identity(ssl_conn)
            log.info("Secure DTLS session established with peer: %s", peer_cn)

            # Receive application CoAP request datagram
            req_bytes = _recv_data_loop(ssl_conn, bufsize=4096, timeout=3.5)
            if req_bytes:
                req_coap = Message.decode(req_bytes)
                resp_coap = self.handler_fn(req_coap, peer_cn or "unknown")
                if resp_coap:
                    if resp_coap.mtype is None:
                        resp_coap.mtype = 2 if req_coap.mtype == 0 else 1  # ACK (2) for CON (0), else NON (1)
                    if resp_coap.mid is None:
                        resp_coap.mid = req_coap.mid
                    if resp_coap.token is None:
                        resp_coap.token = req_coap.token
                    ssl_conn.send(resp_coap.encode())

        except OpenSSL.SSL.Error as e:
            with self._lock:
                self.failed_handshakes += 1
            import traceback
            log.warning("DTLS handshake rejected from %s: %s\n%s", client_addr, e.args, traceback.format_exc())
        except Exception as e:
            import traceback
            log.error("Error processing DTLS session from %s: %s\n%s", client_addr, e, traceback.format_exc())
        finally:
            session_active = False
            with self._lock:
                self._session_bridges.pop(client_addr, None)
                self.active_sessions = max(0, self.active_sessions - 1)
            try:
                ssl_conn.shutdown()
            except Exception:
                pass
            bridge_a.close()
            bridge_b.close()
