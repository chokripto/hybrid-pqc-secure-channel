import os, socket
import oqs
from cryptography.hazmat.primitives.asymmetric import x25519
from src.common.message import send_frame, recv_frame
from src.common.hkdf import hkdf_derive
from src.common.aead import b64e, b64d, fp, NonceState, enc, dec

HOST, PORT = "server", 9000   # docker-compose service name
KEM_ALG = "Kyber512"

def info(session_id: bytes) -> bytes:
    return b"hybrid-pqc-demo|" + session_id

def run():
    assert oqs.is_kem_enabled(KEM_ALG)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        hello = recv_frame(s)
        pk_pqc = b64d(hello["pk_pqc"])
        pk_s  = b64d(hello["pk_ecdh"])
        session_id = b64d(hello["session_id"])
        salt = b64d(hello["salt"])
        srv_prefix = b64d(hello["srv_prefix"])

        kem = oqs.KeyEncapsulation(KEM_ALG)
        ct_pqc, ss_pqc = kem.encap_secret(pk_pqc)

        sk_c = x25519.X25519PrivateKey.generate()
        pk_c = sk_c.public_key().public_bytes_raw()
        ss_ecdh = sk_c.exchange(x25519.X25519PublicKey.from_public_bytes(pk_s))

        K = hkdf_derive(ss_pqc + ss_ecdh, salt, info(session_id), 32)
        print("[client] session established", "sid(fp)=", fp(session_id), "K(fp)=", fp(K))

        cli_prefix = os.urandom(4)
        send_frame(s, {
            "type":"client_kem",
            "ct_pqc": b64e(ct_pqc),
            "pk_ecdh_c": b64e(pk_c),
            "cli_prefix": b64e(cli_prefix),
        })

        send_state = NonceState(cli_prefix)
        recv_state = NonceState(srv_prefix)

        ack = recv_frame(s)
        n = b64d(ack["n"]); aad = b64d(ack["aad"]); ct = b64d(ack["ct"])
        if n != recv_state.next(): raise ValueError("nonce mismatch in ack")
        print("[client] ack:", dec(K,n,ct,aad))

        # send data
        aad2 = b"data|client->server"
        n2 = send_state.next()
        send_frame(s, {"type":"data", "n":b64e(n2), "aad":b64e(aad2),
                       "ct":b64e(enc(K,n2,b"hello from hybrid channel",aad2))})

        # receive response
        r = recv_frame(s)
        n3 = b64d(r["n"]); aad3 = b64d(r["aad"]); ct3 = b64d(r["ct"])
        if n3 != recv_state.next(): raise ValueError("nonce mismatch in response")
        print("[client] resp:", dec(K,n3,ct3,aad3))

if __name__ == "__main__":
    run()
