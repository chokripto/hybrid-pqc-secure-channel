import os, base64, hashlib
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def b64e(b: bytes) -> str: return base64.b64encode(b).decode()
def b64d(s: str) -> bytes: return base64.b64decode(s.encode())

def fp(b: bytes, n: int = 10) -> str:
    return hashlib.sha256(b).hexdigest()[:2*n]

@dataclass
class NonceState:
    prefix4: bytes
    counter: int = 0
    def next(self) -> bytes:
        self.counter += 1
        return self.prefix4 + self.counter.to_bytes(8, "big")

def enc(key: bytes, nonce: bytes, pt: bytes, aad: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, pt, aad)

def dec(key: bytes, nonce: bytes, ct: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ct, aad)
