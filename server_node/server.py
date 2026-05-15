import socket
import json
import os
import sys
import secrets

#Add root directory for the import crypto_modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))) 
from crypto_modules.custom_rsa import CustomRSA

# Localhost setup for testing on your own machine
SERVER_HOST = '127.0.0.1' 
SERVER_PORT = 65432    

CA_HOST = '127.0.0.1'
CA_PORT = 65431

CERT_PATH = os.path.join(os.path.dirname(__file__), 'server_storage', 'server_certificate.json')

def get_certificate(rsa):
    if os.path.exists(CERT_PATH):
        with open(CERT_PATH, "r") as file:
            return json.load(file)

    # Get CA to sign a certificate
    print("Connecting to CA to request a Digital Certificate...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as ca_sock:
        ca_sock.connect((CA_HOST, CA_PORT))
        
        registration_request = {
            "identity": "Server",
            "public_key": rsa.public_key
        }
        
        ca_sock.sendall(json.dumps(registration_request).encode())
        print("Sent Identity and Public Key to CA.")
        
        # Wait to receive the certificate back from the CA
        cert_data = ca_sock.recv(4096).decode()
        certificate = json.loads(cert_data)
        
        # Save the certificate to server_storage
        with open(CERT_PATH, 'w') as f:
            json.dump(certificate, f, indent=4)
        print("Successfully received and saved Digital Certificate from CA.")
    


def start_server():
    print("--- Server Starting ---")
    
    # Initialize CustomRSA
    rsa = CustomRSA()
    
    # Load or Generate the Server's keys
    priv_key_path = os.path.join(os.path.dirname(__file__), 'server_storage', 'server_private_key.json')
    pub_key_path = os.path.join(os.path.dirname(__file__), 'server_storage', 'server_public_key.json')
    
    try:
        with open(priv_key_path, 'r') as f:
            key_data = json.load(f)
            rsa.private_key = (key_data['d'], key_data['n'])
        with open(pub_key_path, 'r') as f:
            key_data = json.load(f)
            rsa.public_key = (key_data['e'], key_data['n'])
        print("Successfully loaded Server's RSA keys from storage.")
    except FileNotFoundError:
        print("Keys not found. Generating new 1024-bit RSA keys for the Server...")
        rsa.generate_keys(1024)
        
        # Save Private Key
        with open(priv_key_path, 'w') as f:
            json.dump({"d": rsa.private_key[0], "n": rsa.private_key[1]}, f, indent=4)
            
        # Save Public Key
        with open(pub_key_path, 'w') as f:
            json.dump({"e": rsa.public_key[0], "n": rsa.public_key[1]}, f, indent=4)
        print("Successfully generated and saved Server's RSA keys.")
   
    # TODO: Load the Digital Certificate given by the CA.
    certificate = get_certificate(rsa)

    # 1. Boot up the Socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((SERVER_HOST, SERVER_PORT))
        s.listen()
        print(f"Listening for Client connections on {SERVER_HOST}:{SERVER_PORT}...")
        
        conn, addr = s.accept()
        with conn:
            print(f"Connection established with {addr}")

            # 2. Receive Phase 2: ClientHello
            data = conn.recv(4096)
            client_msg = json.loads(data.decode())
            print(f"Received from Client: {client_msg['type']}")
            client_nonce = client_msg['nonce_c']

            # 3. Send Phase 2: ServerHello & Certificate
            # TODO: Generate a true random nonce for the server
            server_nonce = secrets.token_hex(32)
            
            server_hello = {
                "type": "ServerHello",
                "nonce_s": server_nonce,
                "certificate": certificate
            }
            conn.sendall(json.dumps(server_hello).encode())
            print("Sent ServerHello and Digital Certificate.")

            # 4. Phase 4: Diffie-Hellman Key Exchange
            # TODO: Wait for Client to verify the certificate. 
            # Then generate p, g, and Y_S, sign them, and send to Client.
    

if __name__ == "__main__":
    start_server()