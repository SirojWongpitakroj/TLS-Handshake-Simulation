import hashlib
import secrets
import math
from .crypto_math import *

class CustomRSA:
    def __init__(self):
        # Your generated keys will live here
        self.public_key = None
        self.private_key = None
        self.n = None

    def generate_keys(self, bit_length=1024):
        half_bits = bit_length // 2

        p = generate_prime(half_bits)
        q = generate_prime(half_bits)

        # p may be equal to q
        while p == q:
            q = generate_prime(half_bits)

        self.n = p * q
        totient_n = (p-1)*(q-1)
        
        while True:
            e = secrets.choice(range(2, totient_n))
            if math.gcd(e, totient_n) == 1:
                break
        
        d = multinv(e, totient_n)
        
        self.public_key = (e, self.n)
        self.private_key = (d, self.n)
        
        print(f"Successfully generated {bit_length}-bit RSA Keys!")

    @staticmethod
    def _mod_exp(a, m, n):
        bin_m = bin(m)[2:]

        d = 1
        for bit in bin_m:
            d = (d * d) % n
            if bit == '1':
                d = (d * a) % n
        return d
    
    @staticmethod
    def sign_data(plaintext_claim, private_key, n):
        # Hash the claim
        hash_raw = hashlib.sha256(plaintext_claim.encode()).hexdigest()
        hash_int = int(hash_raw, 16)

        # Encrypt hash with private keys
        encrypted_signature = CustomRSA._mod_exp(hash_int, private_key[0], n)
        return encrypted_signature

    @staticmethod
    def verify_signature(plaintext_claim, signature, public_key, n):
        """
        TODO: Implement Digital Signature verification
        1. Decrypt the signature using the public key: Signature^e mod n
        2. Hash the plaintext_claim yourself.
        3. Compare your hash with the decrypted hash. Return True if they match.
        """
        decrypted_signature = CustomRSA._mod_exp(signature, public_key[0], n)

        hash_claim = hashlib.sha256(plaintext_claim.encode()).hexdigest()
        hash_int = int(hash_claim, 16)

        return True if decrypted_signature == hash_int else False