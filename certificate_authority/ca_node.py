import socket
import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from crypto_modules.custom_rsa import CustomRSA
from crypto_modules.logger import (
    banner, phase_header, log, session_complete,
    STARTUP, PHASE1, SUCCESS, ERROR
)

HOST = '127.0.0.1'
PORT = 65431


class CertificateAuthority:
    def __init__(self):
        banner("TLS HANDSHAKE SIMULATION - CA")

        self.rsa = CustomRSA()

        priv_key_path = os.path.join(os.path.dirname(__file__), 'ca_storage', 'ca_private_key.json')
        pub_key_path  = os.path.join(os.path.dirname(__file__), 'ca_storage', 'ca_public_key.json')

        try:
            with open(priv_key_path, 'r') as f:
                key_data = json.load(f)
                self.rsa.private_key = (key_data['d'], key_data['n'])
            with open(pub_key_path, 'r') as f:
                key_data = json.load(f)
                self.rsa.public_key = (key_data['e'], key_data['n'])
                self.rsa.n = key_data['n']
            log(SUCCESS, "Successfully loaded CA's RSA keys from storage.")
        except FileNotFoundError:
            log(STARTUP, "Generating 1024-bit RSA keys for the CA...")
            self.rsa.generate_keys(1024)
            with open(priv_key_path, 'w') as f:
                json.dump({"d": self.rsa.private_key[0], "n": self.rsa.private_key[1]}, f, indent=4)
            with open(pub_key_path, 'w') as f:
                json.dump({"e": self.rsa.public_key[0], "n": self.rsa.public_key[1]}, f, indent=4)
            log(SUCCESS, "CA keys successfully generated and saved to storage.")

    def generate_certificate(self, server_identity, server_public_key):
        """
        Phase 1: Generates a digital certificate for the requesting server.
        """
        claim = f"Identity={server_identity},PubKey={server_public_key[0]},{server_public_key[1]}"
        enc_signature = CustomRSA.sign_data(claim, self.rsa.private_key, self.rsa.n)
        return {
            "plaintext_claim": claim,
            "signature": enc_signature
        }

    def start(self):
        """
        Starts the socket server to listen for registration requests from Servers.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()
            log(STARTUP, f"CA is listening on {HOST}:{PORT}...")

            conn, addr = s.accept()
            with conn:
                phase_header(PHASE1, "Phase 1: Certificate Issuance")
                log(PHASE1, f"Connection established with Server at {addr}")

                req_data = conn.recv(4096).decode()
                req = json.loads(req_data)

                certificate = self.generate_certificate(req['identity'], req['public_key'])

                conn.sendall(json.dumps(certificate).encode())

                log(SUCCESS, "Certificate generated and sent to Server.")
                session_complete()


if __name__ == "__main__":
    ca = CertificateAuthority()
    ca.start()
