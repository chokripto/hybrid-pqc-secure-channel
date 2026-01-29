import json, socket, struct
from typing import Any, Dict

def send_frame(sock: socket.socket, obj: Dict[str, Any]) -> None:
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack("!I", len(data)) + data)

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    out = b""
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise ConnectionError("Socket closed")
        out += chunk
    return out

def recv_frame(sock: socket.socket) -> Dict[str, Any]:
    (ln,) = struct.unpack("!I", _recv_exact(sock, 4))
    return json.loads(_recv_exact(sock, ln).decode("utf-8"))
