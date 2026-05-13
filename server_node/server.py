import socket
import json

# Localhost setup for testing on your own machine
HOST = '127.0.0.1' 
PORT = 65432       

def start_server():
    print("--- Server Starting ---")
    
    # TODO: Initialize CustomRSA, load the Server's private key, 
    # and load the Digital Certificate given by the CA.

    # 1. Boot up the Socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Listening for Client connections on {HOST}:{PORT}...")
        
        conn, addr = s.accept()
        with conn:
            print(f"Connection established with {addr}")

            # 2. Receive Phase 2: ClientHello
            data = conn.recv(1024)
            client_msg = json.loads(data.decode())
            print(f"Received from Client: {client_msg['type']}")
            client_nonce = client_msg['nonce_c']

            # 3. Send Phase 2: ServerHello & Certificate
            # TODO: Generate a true random nonce for the server
            server_nonce = "server_random_nonce_789"
            
            server_hello = {
                "type": "ServerHello",
                "nonce_s": server_nonce,
                "certificate": "TODO_INSERT_REAL_CERTIFICATE_HERE"
            }
            conn.sendall(json.dumps(server_hello).encode())
            print("Sent ServerHello and Digital Certificate.")

            # 4. Phase 4: Diffie-Hellman Key Exchange
            # TODO: Wait for Client to verify the certificate. 
            # Then generate p, g, and Y_S, sign them, and send to Client.

if __name__ == "__main__":
    start_server()