import os, socket
import oqs
from cryptography.hazmat.primitives.asymmetric import x25519
from src.common.message import send_frame, recv_frame
from src.common.hkdf import hkdf_derive
from src.common.aead import b64e, b64d, fp, NonceState, enc, dec

HOST = "0.0.0.0"
KEM_ALG = "Kyber512"

def info(session_id: bytes) -> bytes:
    return b"hybrid-pqc-demo|" + session_id

def run():
    assert oqs.is_kem_enabled(KEM_ALG)
    kem = oqs.KeyEncapsulation(KEM_ALG)
    pk_pqc = kem.generate_keypair()

    sk_s = x25519.X25519PrivateKey.generate()
    pk_s = sk_s.public_key().public_bytes_raw()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[server] listening on {HOST}:{PORT}")

        c, addr = s.accept()
        with c:
            session_id = os.urandom(16)
            salt = os.urandom(16)
            srv_prefix = os.urandom(4)

            send_frame(c, {
                "type":"server_hello",
                "kem":KEM_ALG,
                "pk_pqc": b64e(pk_pqc),
                "pk_ecdh": b64e(pk_s),
                "session_id": b64e(session_id),
                "salt": b64e(salt),
                "srv_prefix": b64e(srv_prefix),
            })

            m = recv_frame(c)
            ct_pqc = b64d(m["ct_pqc"])
            pk_c = b64d(m["pk_ecdh_c"])
            cli_prefix = b64d(m["cli_prefix"])

            ss_pqc = kem.decap_secret(ct_pqc)
            ss_ecdh = sk_s.exchange(x25519.X25519PublicKey.from_public_bytes(pk_c))
            K = hkdf_derive(ss_pqc + ss_ecdh, salt, info(session_id), 32)

            print("[server] session established",
                  "sid(fp)=", fp(session_id),
                  "K(fp)=", fp(K))

            send_state = NonceState(srv_prefix)
            recv_state = NonceState(cli_prefix)

            # ack
            aad = b"ack|server"
            n = send_state.next()
            send_frame(c, {"type":"ack", "n":b64e(n), "aad":b64e(aad), "ct":b64e(enc(K,n,b"OK",aad))})

            # data in
            dm = recv_frame(c)
            n_in = b64d(dm["n"]); aad_in = b64d(dm["aad"]); ct_in = b64d(dm["ct"])
            if n_in != recv_state.next(): raise ValueError("nonce mismatch (replay/out-of-order)")
            pt = dec(K,n_in,ct_in,aad_in)
            print("[server] got:", pt.decode(errors="replace"))

            # response
            aad2 = b"data|server->client"
            n2 = send_state.next()
            send_frame(c, {"type":"data", "n":b64e(n2), "aad":b64e(aad2), "ct":b64e(enc(K,n2,b"ACK",aad2))})

if __name__ == "__main__":
    run()
