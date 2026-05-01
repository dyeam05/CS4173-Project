"""
network.py
Socket-based P2P network layer for Secure Messenger.
"""

import socket
import threading
import struct
import base64
import json
from crypto_core import (
    get_random_bytes,
    dh_generate_private_key,
    dh_public_key,
    dh_shared_secret,
)

HANDSHAKE_TIMEOUT = 30   # seconds to wait for the handshake to complete
RECV_BUFFER       = 4096


class PeerConnectionError(Exception):
    pass


def _send_framed(sock: socket.socket, data: str):
    # Prefix the message with its length so the receiver knows exactly how many bytes to read
    encoded = data.encode("utf-8")
    header  = struct.pack(">I", len(encoded))
    sock.sendall(header + encoded)


def _recv_framed(sock: socket.socket) -> str:
    header = _recv_exactly(sock, 4)
    length = struct.unpack(">I", header)[0]

    # Sanity check — reject anything suspiciously large before allocating memory
    if length > 10 * 1024 * 1024:
        raise PeerConnectionError("Incoming message exceeds 10 MB limit")

    return _recv_exactly(sock, length).decode("utf-8")


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    # Keep reading until we have all n bytes — recv() can return less than asked
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise PeerConnectionError("Connection closed unexpectedly")
        buf += chunk
    return buf


class PeerConnection:
    """Represents an active connection to the other peer."""

    def __init__(self, sock: socket.socket, salt: bytes,
                 dh_secret: bytes = None, role: str = "?"):
        self.sock      = sock
        self.salt      = salt
        self.dh_secret = dh_secret
        self.role      = role
        self._recv_thread = None
        self._stop_event  = threading.Event()

    def send(self, message_json: str):
        try:
            _send_framed(self.sock, message_json)
        except OSError as e:
            raise PeerConnectionError(f"Send failed: {e}")

    def start_receiving(self, on_message, on_disconnect=None):
        # Runs in a background thread so the UI never blocks waiting for data
        self._stop_event.clear()

        def _loop():
            while not self._stop_event.is_set():
                try:
                    data = _recv_framed(self.sock)
                    on_message(data)
                except (PeerConnectionError, OSError):
                    if not self._stop_event.is_set() and on_disconnect:
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


# --- Server ---

def start_server(host: str, port: int, use_dh: bool, on_connected, on_error):
    def _serve():
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.settimeout(120)  # give the other peer up to 2 minutes to connect
            srv.bind((host, port))
            srv.listen(1)
            conn, addr = srv.accept()
            srv.close()
            conn.settimeout(HANDSHAKE_TIMEOUT)

            # Server is responsible for generating and sending the salt
            salt     = get_random_bytes(16)
            salt_b64 = base64.b64encode(salt).decode()

            dh_secret = None
            if use_dh:
                priv = dh_generate_private_key()
                pub  = dh_public_key(priv)
                # Send salt and our DH public key together in one message
                _send_framed(conn, json.dumps({"salt": salt_b64, "dh": str(pub)}))
                client_hello = json.loads(_recv_framed(conn))
                their_pub    = int(client_hello["dh"])
                dh_secret    = dh_shared_secret(their_pub, priv)
            else:
                _send_framed(conn, json.dumps({"salt": salt_b64}))
                _recv_framed(conn)  # wait for client ack before continuing

            conn.settimeout(None)
            on_connected(PeerConnection(conn, salt, dh_secret, role="server"))

        except Exception as e:
            on_error(str(e))

    threading.Thread(target=_serve, daemon=True).start()


# --- Client ---

def connect_to_server(host: str, port: int, use_dh: bool, on_connected, on_error):
    def _connect():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(HANDSHAKE_TIMEOUT)
            sock.connect((host, port))

            server_hello = json.loads(_recv_framed(sock))
            salt         = base64.b64decode(server_hello["salt"])

            dh_secret = None
            if use_dh:
                if "dh" not in server_hello:
                    # Server didn't offer DH — don't silently fall back, just fail loudly
                    raise PeerConnectionError("DH requested but server did not send a public key")
                their_pub = int(server_hello["dh"])
                priv      = dh_generate_private_key()
                pub       = dh_public_key(priv)
                dh_secret = dh_shared_secret(their_pub, priv)
                _send_framed(sock, json.dumps({"dh": str(pub)}))
            else:
                _send_framed(sock, json.dumps({"ack": "ok"}))

            sock.settimeout(None)
            on_connected(PeerConnection(sock, salt, dh_secret, role="client"))

        except Exception as e:
            on_error(str(e))

    threading.Thread(target=_connect, daemon=True).start()