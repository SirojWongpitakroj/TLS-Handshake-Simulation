import socket
import json
import sys
import os
import secrets

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from crypto_modules.custom_rsa import CustomRSA
from crypto_modules.diffie_hellman import DHOakley

SERVER_HOST = '127.0.0.1'  
SERVER_PORT = 65432        

def start_client():
    print("--- Client Starting ---")
    
    ca_pub_key_path = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')), 'certificate_authority', 'ca_storage', 'ca_public_key.json')
    # TODO: Load the CA's Public Key so the Client can verify the Server later.
    ca_rsa = CustomRSA()

    with open(ca_pub_key_path, 'r') as f:
        key_data = json.load(f)
        ca_rsa.public_key = (key_data['e'], key_data['n'])

    # 1. Connect to the Server's Socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_HOST, SERVER_PORT))

        # 2. Send Phase 2: ClientHello
        # TODO: Generate a true random nonce for the client
        client_nonce = secrets.token_hex(32)
        
        client_hello = {
            "type": "ClientHello",
            "nonce_c": client_nonce
        }
        s.sendall(json.dumps(client_hello).encode())
        print("Sent ClientHello.")

        # 3. Receive Phase 2: ServerHello
        data = s.recv(4096)
        server_msg = json.loads(data.decode())
        print(f"Received from Server: {server_msg['type']}")
        
        server_certificate = server_msg['certificate']

        # 4. Phase 3: Authentication
        print("Authenticating Server Certificate...")
        # TODO: Pass the server_certificate and the CA's public key 
        # into your CustomRSA.verify_signature() method.
        # If it fails, close the socket (s.close()).
        plaintext_claim = server_certificate['plaintext_claim']
        signature = server_certificate['signature']

        if not CustomRSA.verify_signature(plaintext_claim, signature, ca_rsa.public_key, ca_rsa.n):
            print("Verification failed")
            s.close()
            return

        # 5. Phase 4: Diffie-Hellman
        # TODO: If verified, wait for Server to send DH parameters.
        print("Waiting for Server's DH parameters")
        dh_data = s.recv(4096)
        server_dh_msg = json.loads(dh_data.decode())
        print("Received DH parameters and signature from ServerKeyExchange")

        p, g, Y_s = server_dh_msg['p'] , server_dh_msg['g'], server_dh_msg['Y_s']
        # Convert to string to match what the server signed
        dh_claim_str = json.dumps({
            "p": p,
            "g": g,
            "Y_s": Y_s
        })
        server_signature = server_dh_msg['signature'] 

        # Load Server's Public Key from file (Note: In real TLS, you extract this from the server_certificate you verified earlier!)
        server_pub_key_path = os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')), 'server_node', 'server_storage', 'server_public_key.json')
        with open(server_pub_key_path, 'r') as f:
            server_pub_data = json.load(f)
            server_e = server_pub_data['e']
            server_n = server_pub_data['n']

        if not CustomRSA.verify_signature(dh_claim_str, server_signature, (server_e, server_n), server_n):
            print("Server DH signature verification failed!")
            s.close()
            return
        
        print("Server DH signature verified successfully!")

        client_dh = DHOakley()
        (p, g, X_c, Y_c) = client_dh.generate_params(2048, p, g)

        client_key_exchange = {
            "type": "ClientKeyExchange",
            "Y_c": Y_c
        }
        s.sendall(json.dumps(client_key_exchange).encode())
        print("Sent ClientKeyExchange with Y_c.")

        #Calculate session key shared between server and client
        session_key = client_dh.calculate_session_key(Y_s)



if __name__ == "__main__":
    start_client()