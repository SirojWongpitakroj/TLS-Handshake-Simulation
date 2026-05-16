import socket
import json
import sys
import os
import hashlib
import secrets

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from crypto_modules.custom_rsa import CustomRSA
from crypto_modules.diffie_hellman import DHOakley
from crypto_modules.secure_tunnel import AESCipher
from crypto_modules.logger import (
    banner, phase_header, log, session_complete,
    STARTUP, PHASE2, PHASE3, PHASE4, PHASE5, PHASE6,
    SUCCESS, ERROR, CIPHER
)

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 65432


def start_client():
    banner("TLS HANDSHAKE SIMULATION - CLIENT")

    ca_pub_key_path = os.path.join(
        os.path.abspath(os.path.join(os.path.dirname(__file__), '..')),
        'certificate_authority', 'ca_storage', 'ca_public_key.json'
    )
    ca_rsa = CustomRSA()

    with open(ca_pub_key_path, 'r') as f:
        key_data = json.load(f)
        ca_rsa.public_key = (key_data['e'], key_data['n'])
        ca_rsa.n = key_data['n']

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_HOST, SERVER_PORT))
        log(STARTUP, "Connected to Server.")

        # Phase 2: Send ClientHello
        phase_header(PHASE2, "Phase 2: Send ClientHello")
        client_nonce = secrets.token_hex(32)
        client_hello = {
            "type": "ClientHello",
            "version": "TLS 1.2",
            "cipher_suites": [
                "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"],
            "nonce_c": client_nonce
        }
        s.sendall(json.dumps(client_hello).encode())
        log(PHASE2, "Sent ClientHello.")

        # Phase 2: Receive ServerHello
        phase_header(PHASE2, "Phase 2: Receive ServerHello")
        data = s.recv(4096)
        server_msg = json.loads(data.decode())
        log(PHASE2, f"Received from Server: {server_msg['type']}")
        log(PHASE2, f"Agreed Protocol: {server_msg.get('version')} | Cipher: {server_msg.get('cipher_suite')}")
        server_nonce = server_msg['nonce_s']
        server_certificate = server_msg['certificate']

        # Phase 3: Authentication
        phase_header(PHASE3, "Phase 3: Server Certificate Authentication")
        log(PHASE3, "Authenticating Server Certificate...")
        plaintext_claim = server_certificate['plaintext_claim']
        signature = server_certificate['signature']

        if not CustomRSA.verify_signature(plaintext_claim, signature, ca_rsa.public_key, ca_rsa.n):
            log(ERROR, "Verification failed")
            s.close()
            return
        log(SUCCESS, "Certificate verified successfully!")

        # Extract Server's public key from the verified certificate claim
        # Format: "Identity=Server,PubKey=<e>,<n>"
        parts = plaintext_claim.split(",")
        server_e = int(parts[1].split("=")[1])
        server_n = int(parts[2])

        # Phase 4: Diffie-Hellman Key Exchange
        phase_header(PHASE4, "Phase 4: Diffie-Hellman Key Exchange")
        log(PHASE4, "Waiting for Server's DH parameters")
        dh_data = s.recv(4096)
        server_dh_msg = json.loads(dh_data.decode())
        log(PHASE4, "Received DH parameters and signature from ServerKeyExchange")

        p, g, Y_s = server_dh_msg['p'], server_dh_msg['g'], server_dh_msg['Y_s']
        dh_claim_str = json.dumps({"p": p, "g": g, "Y_s": Y_s})
        server_signature = server_dh_msg['signature']

        if not CustomRSA.verify_signature(dh_claim_str, server_signature, (server_e, server_n), server_n):
            log(ERROR, "Server DH signature verification failed!")
            s.close()
            return

        log(SUCCESS, "Server DH signature verified successfully!")

        client_dh = DHOakley()
        (p, g, X_c, Y_c) = client_dh.generate_params(2048, p, g)

        client_key_exchange = {
            "type": "ClientKeyExchange",
            "Y_c": Y_c
        }
        s.sendall(json.dumps(client_key_exchange).encode())
        log(PHASE4, "Sent ClientKeyExchange with Y_c.")

        session_key = client_dh.calculate_session_key(Y_s, client_nonce, server_nonce)
        log(SUCCESS, "Session key derived successfully!")

        # Phase 5: Handshake Verification
        phase_header(PHASE5, "Phase 5: Handshake Verification")
        log(PHASE5, "Verifying Handshake Integrity...")

        all_messages = (
            json.dumps(client_hello) +
            json.dumps(server_msg) +
            json.dumps(server_dh_msg) +
            json.dumps(client_key_exchange)
        )
        handshake_hash = hashlib.sha256(all_messages.encode()).hexdigest()

        cipher = AESCipher(session_key)

        client_finished = {
            "type": "ClientFinished",
            "verify_data": cipher.encrypt(handshake_hash)
        }
        s.sendall(json.dumps(client_finished).encode())
        log(PHASE5, "Sent ClientFinished.")

        server_finished_data = s.recv(4096)
        server_finished_msg = json.loads(server_finished_data.decode())

        server_hash = cipher.decrypt(server_finished_msg['verify_data'])
        if server_hash == handshake_hash:
            log(SUCCESS, "Server Handshake Hash Verified Successfully! Secure Tunnel Established.")
        else:
            log(ERROR, "Server Handshake Hash Verification Failed! Man-in-the-Middle detected.")
            s.close()
            return

        # Phase 6: The Secure Tunnel (Data Transfer)
        phase_header(PHASE6, "Phase 6: Secure Tunnel (Data Transfer)")
        log(PHASE6, "Secure Chat started. Type 'exit' to quit.")

        while True:
            secret_message = input("\n[Client] You: ")
            if secret_message.strip().lower() == 'exit':
                s.sendall(cipher.encrypt("exit").encode())
                break

            encrypted_message = cipher.encrypt(secret_message)
            log(CIPHER, f"Sending Ciphertext: {encrypted_message[:50]}...")
            s.sendall(encrypted_message.encode())

            # Wait for Server response
            server_data = s.recv(4096).decode()
            if not server_data:
                break

            log(CIPHER, f"Received Ciphertext: {server_data[:50]}...")
            decrypted_reply = cipher.decrypt(server_data)
            
            if decrypted_reply.strip().lower() == 'exit':
                log(PHASE6, "Server closed the connection.")
                break

            log(SUCCESS, f"[Server] Reply: {decrypted_reply}")

        session_complete()


if __name__ == "__main__":
    start_client()