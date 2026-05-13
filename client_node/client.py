import socket
import json

HOST = '127.0.0.1'  
PORT = 65432        

def start_client():
    print("--- Client Starting ---")
    
    # TODO: Load the CA's Public Key so the Client can verify the Server later.

    # 1. Connect to the Server's Socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        # 2. Send Phase 2: ClientHello
        # TODO: Generate a true random nonce for the client
        client_nonce = "client_random_nonce_123"
        
        client_hello = {
            "type": "ClientHello",
            "nonce_c": client_nonce
        }
        s.sendall(json.dumps(client_hello).encode())
        print("Sent ClientHello.")

        # 3. Receive Phase 2: ServerHello
        data = s.recv(1024)
        server_msg = json.loads(data.decode())
        print(f"Received from Server: {server_msg['type']}")
        
        server_certificate = server_msg['certificate']

        # 4. Phase 3: Authentication
        print("Authenticating Server Certificate...")
        # TODO: Pass the server_certificate and the CA's public key 
        # into your CustomRSA.verify_signature() method.
        # If it fails, close the socket (s.close()).

        # 5. Phase 4: Diffie-Hellman
        # TODO: If verified, wait for Server to send DH parameters.

if __name__ == "__main__":
    start_client()