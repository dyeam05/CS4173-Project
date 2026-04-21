"""
network.py
==========
Socket-based P2P network layer for Secure Messenger.

Architecture:
  - One peer acts as SERVER (listens on a port).
  - The other peer acts as CLIENT (connects to server's IP:port).
  - After the TCP handshake, both sides are symmetric – they can both
    send and receive at any time using background threads.
  - Messages are length-prefixed (4-byte big-endian uint32) so the
    receiver knows exactly how many bytes to read per message.
  - A lightweight application-level handshake exchanges:
        • The server's random salt (16 bytes, base64)
        • DH public keys (if DH mode is selected)
    before any encrypted chat messages flow.
"""

import socket
import threading
import struct
import base64
import json
import queue
from crypto_core import (
    get_random_bytes,
    dh_generate_private_key,
    dh_public_key,
    dh_shared_secret,
)

HANDSHAKE_TIMEOUT = 30   # seconds
RECV_BUFFER       = 4096


class ConnectionError(Exception):
    pass


def _send_framed(sock: socket.socket, data: str):
    """Send a length-prefixed UTF-8 string."""
    encoded = data.encode("utf-8")
    header  = struct.pack(">I", len(encoded))
    sock.sendall(header + encoded)


def _recv_framed(sock: socket.socket) -> str:
    """Receive a length-prefixed UTF-8 string."""
    header = _recv_exactly(sock, 4)
    length = struct.unpack(">I", header)[0]
    return _recv_exactly(sock, length).decode("utf-8")


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        buf += chunk
    return buf


class PeerConnection:
    """
    Represents an active P2P connection.

    After construction, call start_receiving(callback) to begin a
    background listener thread.  Use send(message_json) to transmit.
    """

    def __init__(self, sock: socket.socket, salt: bytes,
                 dh_secret: bytes = None, role: str = "?"):
        self.sock       = sock
        self.salt       = salt
        self.dh_secret  = dh_secret
        self.role       = role
        self._recv_thread = None
        self._stop_event  = threading.Event()

    def send(self, message_json: str):
        try:
            _send_framed(self.sock, message_json)
        except OSError as e:
            raise ConnectionError(f"Send failed: {e}")

    def start_receiving(self, on_message, on_disconnect=None):
        """
        Start a background thread that calls on_message(json_str) for
        each received message, and on_disconnect() when connection drops.
        """
        self._stop_event.clear()

        def _loop():
            while not self._stop_event.is_set():
                try:
                    data = _recv_framed(self.sock)
                    on_message(data)
                except (ConnectionError, OSError):
                    if not self._stop_event.is_set():
                        if on_disconnect:
                            on_disconnect()
                    break

        self._recv_thread = threading.Thread(target=_loop, daemon=True)
        self._recv_thread.start()

    def close(self):
        self._stop_event.set()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


# ---------------------------------------------------------------------------
# Server side
# ---------------------------------------------------------------------------

def start_server(host: str, port: int, use_dh: bool,
                 on_connected, on_error):
    """
    Listen for one incoming connection.
    Runs in a daemon thread; calls on_connected(PeerConnection) when ready,
    or on_error(str) on failure.
    """
    def _serve():
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.settimeout(120)  # 2-minute accept timeout
            srv.bind((host, port))
            srv.listen(1)
            conn, addr = srv.accept()
            srv.close()
            conn.settimeout(HANDSHAKE_TIMEOUT)

            # Server generates and sends the salt
            salt = get_random_bytes(16)
            salt_b64 = base64.b64encode(salt).decode()

            dh_secret = None
            if use_dh:
                priv  = dh_generate_private_key()
                pub   = dh_public_key(priv)
                hello = json.dumps({
                    "salt": salt_b64,
                    "dh":   str(pub),
                })
                _send_framed(conn, hello)
                client_hello = json.loads(_recv_framed(conn))
                their_pub    = int(client_hello["dh"])
                dh_secret    = dh_shared_secret(their_pub, priv)
            else:
                _send_framed(conn, json.dumps({"salt": salt_b64}))
                _recv_framed(conn)  # consume client ack

            conn.settimeout(None)
            peer = PeerConnection(conn, salt, dh_secret, role="server")
            on_connected(peer)

        except Exception as e:
            on_error(str(e))

    t = threading.Thread(target=_serve, daemon=True)
    t.start()


# ---------------------------------------------------------------------------
# Client side
# ---------------------------------------------------------------------------

def connect_to_server(host: str, port: int, use_dh: bool,
                      on_connected, on_error):
    """
    Connect to the server peer.
    Runs in a daemon thread.
    """
    def _connect():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(HANDSHAKE_TIMEOUT)
            sock.connect((host, port))

            server_hello = json.loads(_recv_framed(sock))
            salt         = base64.b64decode(server_hello["salt"])

            dh_secret = None
            if use_dh and "dh" in server_hello:
                their_pub = int(server_hello["dh"])
                priv      = dh_generate_private_key()
                pub       = dh_public_key(priv)
                dh_secret = dh_shared_secret(their_pub, priv)
                _send_framed(sock, json.dumps({"dh": str(pub)}))
            else:
                _send_framed(sock, json.dumps({"ack": "ok"}))

            sock.settimeout(None)
            peer = PeerConnection(sock, salt, dh_secret, role="client")
            on_connected(peer)

        except Exception as e:
            on_error(str(e))

    t = threading.Thread(target=_connect, daemon=True)
    t.start()
