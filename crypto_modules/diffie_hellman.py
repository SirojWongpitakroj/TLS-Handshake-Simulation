import secrets
from .crypto_math import *

class DHOakley:
    def __init__(self):
        self.p = None
        self.g = None
        self.X = None
        self.Y = None
        self.session_k = None

    def generate_params(self, bit_length=2048, p=None, g=None):

        self.p = generate_prime(bit_length) if not p else p
        totient_p = self.p - 1

        if not g:
            while True:
                g = secrets.choice(range(2, totient_p))
                (gcd, _, _) = ext_euclid_gcd(g, totient_p)
                if gcd == 1:
                    break
        self.g = g
        
        self.X = secrets.randbelow(self.p - 2) + 2

        self.Y = mod_exp(self.g, self.X, self.p)

        return (self.p, self.g, self.X, self.Y)

    def calculate_session_key(self, Y, client_nonce, server_nonce):
        import hashlib
        raw_secret = mod_exp(Y, self.X, self.p)
        combined = str(raw_secret) + client_nonce + server_nonce
        self.session_k = hashlib.sha256(combined.encode()).hexdigest()
        return self.session_k