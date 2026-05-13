import socket
import json
import os

# Add the parent directory to the path so we can import crypto_modules
from crypto_modules.custom_rsa import CustomRSA

HOST = '127.0.0.1'
PORT = 65431  # CA listens on a different port than the main Server

class CertificateAuthority:
    def __init__(self):
        print("--- Certificate Authority Starting ---")
        
        self.rsa = CustomRSA()
        # Generate keys for the CA.
        print("Generating 1024-bit RSA keys for the CA...")
        self.rsa.generate_keys(1024)
        
        # Save the CA's public key to a file in ca_storage.
        pub_key_path = os.path.join(os.path.dirname(__file__), 'ca_storage', 'ca_public_key.json')
        with open(pub_key_path, 'w') as f:
            json.dump({
                "e": self.rsa.public_key[0],
                "n": self.rsa.public_key[1]
            }, f, indent=4)
        print(f"CA Public Key successfully saved to: {pub_key_path}")
        
    def generate_certificate(self, server_identity, server_public_key):
        """
        Phase 1: Generates a digital certificate for the requesting server.
        """
        # TODO: 3. Create the "claim" string.
        # Hint: Combine the server_identity and server_public_key into a single verifiable string.

        # TODO: 4. Sign the claim.
        # Hint: Hash the claim and sign it using the CA's private key using your CustomRSA.sign_data() method.
        
        # TODO: 5. Construct the final certificate.
        # Hint: The certificate should probably be a dictionary containing the plaintext claim and the encrypted signature.
        return {}

    def start(self):
        """
        Starts the socket server to listen for registration requests from Servers.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()
            print(f"CA is listening on {HOST}:{PORT}...")
            
            while True:
                conn, addr = s.accept()
                with conn:
                    print(f"Connection established with Server at {addr}")
                    
                    # TODO: 6. Receive the Server's identity and public key via the socket.
                    # Hint: Use conn.recv() and expect a JSON string containing the data.

                    # TODO: 7. Call self.generate_certificate() with the received data.
                    
                    # TODO: 8. Send the completed certificate back to the Server over the socket.
                    # Hint: Convert the certificate to JSON and encode it before sending with conn.sendall().
                    
                    print("Certificate generated and sent to Server.")

if __name__ == "__main__":
    ca = CertificateAuthority()
    ca.start()
