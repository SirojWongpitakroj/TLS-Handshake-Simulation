import socket
import json
import os
import sys
import hashlib
import secrets

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from crypto_modules.custom_rsa import CustomRSA
from crypto_modules.diffie_hellman import DHOakley
from crypto_modules.secure_tunnel import AESCipher
from crypto_modules.logger import (
    banner, phase_header, log, session_complete,
    STARTUP, PHASE1, PHASE2, PHASE4, PHASE5, PHASE6,
    SUCCESS, ERROR, CIPHER
)

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432

CA_HOST = '127.0.0.1'
CA_PORT = 65431

CERT_PATH       = os.path.join(os.path.dirname(__file__), 'server_storage', 'server_certificate.json')
CA_PUB_KEY_PATH = os.path.join(os.path.dirname(__file__), '..', 'certificate_authority', 'ca_storage', 'ca_public_key.json')


def _load_ca_public_key():
    """Reads the CA's current public key from disk."""

    with open(CA_PUB_KEY_PATH, 'r') as f:
        key_data = json.load(f)

    return (key_data['e'], key_data['n']), key_data['n']


def _request_new_certificate(rsa):
    """Connects to the CA and requests a freshly signed certificate."""

    phase_header(PHASE1, "Phase 1: CA Certificate Request")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ca_sock:
        ca_sock.connect((CA_HOST, CA_PORT))

        registration_request = {
            "identity":   "Server",
            "public_key": rsa.public_key
        }

        ca_sock.sendall(json.dumps(registration_request).encode())
        log(PHASE1, "Sent Identity and Public Key to CA.")

        cert_data   = ca_sock.recv(4096).decode()
        certificate = json.loads(cert_data)

        with open(CERT_PATH, 'w') as f:
            json.dump(certificate, f, indent=4)

        log(SUCCESS, "Successfully received and saved Digital Certificate from CA.")
        return certificate


def get_certificate(rsa):
    """Returns a valid, CA-verified certificate for this server.
    
    Loads from disk if cached. Automatically discards and re-requests
    the certificate if it fails validation against the current CA key.
    """

    ca_pub_key, ca_n = _load_ca_public_key()

    if os.path.exists(CERT_PATH):

        with open(CERT_PATH, "r") as file:
            cached_cert = json.load(file)

        # Validate the cached cert against the current CA public key
        is_valid = CustomRSA.verify_signature(
            cached_cert['plaintext_claim'],
            cached_cert['signature'],
            ca_pub_key,
            ca_n
        )

        if is_valid:
            log(SUCCESS, "Loaded and validated cached certificate from storage.")
            return cached_cert
        else:
            log(STARTUP, "Cached certificate is stale (CA key mismatch). Requesting a new one...")
            os.remove(CERT_PATH)

    return _request_new_certificate(rsa)


def start_server():
    banner("TLS HANDSHAKE SIMULATION - SERVER")

    rsa = CustomRSA()

    priv_key_path = os.path.join(os.path.dirname(__file__), 'server_storage', 'server_private_key.json')
    pub_key_path  = os.path.join(os.path.dirname(__file__), 'server_storage', 'server_public_key.json')

    try:
        with open(priv_key_path, 'r') as f:
            key_data = json.load(f)
            rsa.private_key = (key_data['d'], key_data['n'])
        with open(pub_key_path, 'r') as f:
            key_data = json.load(f)
            rsa.public_key = (key_data['e'], key_data['n'])
            rsa.n = key_data['n']
        log(SUCCESS, "Successfully loaded Server's RSA keys from storage.")
    except FileNotFoundError:
        log(STARTUP, "Keys not found. Generating new 1024-bit RSA keys for the Server...")
        rsa.generate_keys(1024)
        with open(priv_key_path, 'w') as f:
            json.dump({"d": rsa.private_key[0], "n": rsa.private_key[1]}, f, indent=4)
        with open(pub_key_path, 'w') as f:
            json.dump({"e": rsa.public_key[0], "n": rsa.public_key[1]}, f, indent=4)
        log(SUCCESS, "Successfully generated and saved Server's RSA keys.")

    certificate = get_certificate(rsa)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((SERVER_HOST, SERVER_PORT))
        s.listen()
        log(STARTUP, f"Listening for Client connections on {SERVER_HOST}:{SERVER_PORT}...")

        conn, addr = s.accept()
        with conn:
            log(STARTUP, f"Connection established with {addr}\n")

            # Phase 2: Receive ClientHello
            phase_header(PHASE2, "Phase 2: Receive ClientHello")
            data = conn.recv(4096)
            client_msg = json.loads(data.decode())
            log(PHASE2, f"Received from Client: {client_msg['type']}")
            log(PHASE2, f"Client supported protocol: {client_msg.get('version')}")
            client_nonce = client_msg['nonce_c']

            # Phase 2: Send ServerHello & Certificate
            phase_header(PHASE2, "Phase 2: Send ServerHello & Certificate")
            server_nonce = secrets.token_hex(32)
            
            # Select the first supported cipher suite or default
            client_suites = client_msg.get('cipher_suites', [])
            selected_suite = client_suites[0] if client_suites else "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"

            server_hello = {
                "type": "ServerHello",
                "version": "TLS 1.2",
                "cipher_suite": selected_suite,
                "nonce_s": server_nonce,
                "certificate": certificate
            }
            conn.sendall(json.dumps(server_hello).encode())
            log(PHASE2, "Sent ServerHello and Digital Certificate.")

            # Phase 4: Diffie-Hellman Key Exchange
            phase_header(PHASE4, "Phase 4: Diffie-Hellman Key Exchange")
            server_dh = DHOakley()
            (p, g, X_s, Y_s) = server_dh.generate_params(2048)
            plaintext = {"p": p, "g": g, "Y_s": Y_s}

            dh_claim_str = json.dumps(plaintext)
            dh_signature = CustomRSA.sign_data(dh_claim_str, rsa.private_key, rsa.n)
            dh_params_signature = {
                "type": "ServerKeyExchange",
                "p": p, "g": g, "Y_s": Y_s,
                "signature": dh_signature
            }
            conn.sendall(json.dumps(dh_params_signature).encode())
            log(PHASE4, "Sent ServerKeyExchange with DH parameters and signature.")

            client_key_data = conn.recv(4096)
            client_key_msg = json.loads(client_key_data.decode())
            Y_c = client_key_msg['Y_c']
            log(PHASE4, "Received ClientKeyExchange.")

            session_key = server_dh.calculate_session_key(Y_c, client_nonce, server_nonce)
            log(SUCCESS, "Session key derived successfully!")

            # Phase 5: Handshake Verification
            phase_header(PHASE5, "Phase 5: Handshake Verification")
            log(PHASE5, "Verifying Handshake Integrity...")

            all_messages = (
                json.dumps(client_msg) +
                json.dumps(server_hello) +
                json.dumps(dh_params_signature) +
                json.dumps(client_key_msg)
            )
            handshake_hash = hashlib.sha256(all_messages.encode()).hexdigest()

            cipher = AESCipher(session_key)

            client_finished_data = conn.recv(4096)
            client_finished_msg = json.loads(client_finished_data.decode())

            client_hash = cipher.decrypt(client_finished_msg['verify_data'])
            if client_hash == handshake_hash:
                log(SUCCESS, "Client Handshake Hash Verified Successfully!")
            else:
                log(ERROR, "Client Handshake Hash Verification Failed! Man-in-the-Middle detected.")
                return

            server_finished = {
                "type": "ServerFinished",
                "verify_data": cipher.encrypt(handshake_hash)
            }
            conn.sendall(json.dumps(server_finished).encode())
            log(SUCCESS, "Sent ServerFinished. Handshake Fully Verified!")

            # Phase 6: The Secure Tunnel (Data Transfer)
            phase_header(PHASE6, "Phase 6: Secure Tunnel (Data Transfer)")
            log(PHASE6, "Secure Chat started. Waiting for Client...")

            while True:
                encrypted_data = conn.recv(4096).decode()
                if not encrypted_data:
                    break

                log(CIPHER, f"\nReceived Ciphertext: {encrypted_data[:50]}...")

                try:
                    decrypted_message = cipher.decrypt(encrypted_data)
                    if decrypted_message.strip().lower() == 'exit':
                        log(PHASE6, "Client closed the connection.")
                        break

                    log(SUCCESS, f"[Client] Message: {decrypted_message}")

                    # Server Response
                    reply = input("[Server] You: ")
                    if reply.strip().lower() == 'exit':
                        conn.sendall(cipher.encrypt("exit").encode())
                        break

                    encrypted_reply = cipher.encrypt(reply)
                    log(CIPHER, f"Sending Ciphertext: {encrypted_reply[:50]}...")
                    conn.sendall(encrypted_reply.encode())

                except Exception as e:
                    log(ERROR, f"Failed to decrypt data or MAC verification failed: {e}")
                    break

            session_complete()


if __name__ == "__main__":
    start_server()