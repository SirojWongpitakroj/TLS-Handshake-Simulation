import hashlib
import random
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
            a = random.randrange(2, n - 1)
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
            p = random.getrandbits(bit_length)
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
        """
        TODO: Implement the RSA Key Generation Algorithm (Module 6)
        1. Generate two large prime numbers, p and q.
        2. Calculate n = p * q
        3. Calculate totient = (p-1)*(q-1)
        4. Choose e (relatively prime to totient)
        5. Calculate d (multiplicative inverse of e mod totient)
        """
        half_bits = bit_length // 2

        p = self._generate_prime(half_bits)
        q = self._generate_prime(half_bits)

        # p may be equal to q
        while p == q:
            q = self._generate_prime(half_bits)

        self.n = p * q
        totient_n = (p-1)*(q-1)
        
        while True:
            e = random.randrange(2, totient_n)
            if math.gcd(e, totient_n) == 1:
                break
        
        # 5. Calculate d (multiplicative inverse of e mod totient)
        d = self._multinv(e, totient_n)
        
        # Finally, save the keys to the class instance variables
        self.public_key = (e, self.n)
        self.private_key = (d, self.n)
        
        print(f"Successfully generated {bit_length}-bit RSA Keys!")

    def sign_data(self, plaintext_claim, private_key, n):
        """
        TODO: Implement Digital Signature creation
        1. Hash the plaintext_claim using hashlib.sha256()
        2. Convert the hash to an integer.
        3. Encrypt the integer using the private key: Hash^d mod n
        4. Return the encrypted signature.
        """
        pass

    def verify_signature(self, plaintext_claim, signature, public_key, n):
        """
        TODO: Implement Digital Signature verification
        1. Decrypt the signature using the public key: Signature^e mod n
        2. Hash the plaintext_claim yourself.
        3. Compare your hash with the decrypted hash. Return True if they match.
        """
        pass