import hashlib
import secrets
import math

class CustomRSA:
    def __init__(self):
        # Your generated keys will live here
        self.public_key = None
        self.private_key = None
        self.n = None

    def _is_prime(self, n, k=5):
        """Miller-Rabin primality test for checking if a number is likely prime."""
        if n <= 1: return False
        if n <= 3: return True
        if n % 2 == 0: return False

        # Find r and d such that n - 1 = d * 2^r
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        # Run the test k times
        for _ in range(k):
            a = secrets.choice(range(1, n-1))
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def _generate_prime(self, bit_length):
        """Generate a random prime number of a specific bit length."""
        while True:
            # Generate a random integer with the exact bit length
            p = secrets.randbits(bit_length)
            # Ensure the number is odd (lowest bit is 1) and has the correct bit length (highest bit is 1)
            p |= (1 << bit_length - 1) | 1 
            
            # Check if it's prime
            if self._is_prime(p):
                return p

    def _ext_euclid_gcd(self, a, b):
        """Extended Euclideam Algorithm with recursion to find inverse of e"""
        if b == 0:
            return (a, 1, 0)
        (c1, x1, y1) = self._ext_euclid_gcd(b, a%b)
        c = c1
        x = y1
        y = x1 - (a // b) * y1
        return (c, x, y)

    def _multinv(self, e, totient):
        """Multiplicative Inverse to find inverse of e"""
        (c, x, y) = self._ext_euclid_gcd(e, totient)
        return x

    def generate_keys(self, bit_length=1024):
        half_bits = bit_length // 2

        p = self._generate_prime(half_bits)
        q = self._generate_prime(half_bits)

        # p may be equal to q
        while p == q:
            q = self._generate_prime(half_bits)

        self.n = p * q
        totient_n = (p-1)*(q-1)
        
        while True:
            e = secrets.choice(range(2, totient_n))
            if math.gcd(e, totient_n) == 1:
                break
        
        d = self._multinv(e, totient_n)
        
        self.public_key = (e, self.n)
        self.private_key = (d, self.n)
        
        print(f"Successfully generated {bit_length}-bit RSA Keys!")

    @staticmethod
    def _mod_exp(self, a, m, n):
        bin_m = bin(m)[2:]

        d = 1
        for bit in bin_m:
            d = (d * d) % n
            if bit == '1':
                d = (d * a) % n
        return d
    
    @staticmethod
    def sign_data(self, plaintext_claim, private_key, n):
        # Hash the claim
        hash_raw = hashlib.sha256(plaintext_claim.encode()).hexdigest()
        hash_int = int(hash_raw, 16)

        # Encrypt hash with private keys
        encrypted_signature = self._mod_exp(hash_int, private_key[0], n)
        return encrypted_signature

    @staticmethod
    def verify_signature(self, plaintext_claim, signature, public_key, n):
        """
        TODO: Implement Digital Signature verification
        1. Decrypt the signature using the public key: Signature^e mod n
        2. Hash the plaintext_claim yourself.
        3. Compare your hash with the decrypted hash. Return True if they match.
        """
        decrypted_signature = self._mod_exp(signature, public_key[0], n)

        hash_claim = hashlib.sha256(plaintext_claim.encode()).hexdigest()
        hash_int = int(hash_claim, 16)

        return True if decrypted_signature == hash_int else False