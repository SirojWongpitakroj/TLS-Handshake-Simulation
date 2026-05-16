import secrets

def _is_prime(n, k=5):
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
            a = secrets.randbelow(n - 2) + 2
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

def generate_prime(bit_length):
    """Generate a random prime number of a specific bit length."""
    while True:
        # Generate a random integer with the exact bit length
        p = secrets.randbits(bit_length)
        # Ensure the number is odd (lowest bit is 1) and has the correct bit length (highest bit is 1)
        p |= (1 << bit_length - 1) | 1 
        
        # Check if it's prime
        if _is_prime(p):
            return p

def ext_euclid_gcd(a, b):
        """Extended Euclidean Algorithm (Iterative) to avoid RecursionError for large primes"""
        x0, x1, y0, y1 = 1, 0, 0, 1
        while b != 0:
            q, a, b = a // b, b, a % b
            x0, x1 = x1, x0 - q * x1
            y0, y1 = y1, y0 - q * y1
        return (a, x0, y0)

def multinv(e, totient):
    """Multiplicative Inverse to find inverse of e"""
    (c, x, y) = ext_euclid_gcd(e, totient)
    return x

def mod_exp(a, m, n):
        bin_m = bin(m)[2:]

        d = 1
        for bit in bin_m:
            d = (d * d) % n
            if bit == '1':
                d = (d * a) % n
        return d