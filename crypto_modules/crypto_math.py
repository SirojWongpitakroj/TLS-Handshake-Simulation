import secrets

def is_prime(n, k=5):
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

def generate_prime(bit_length):
    """Generate a random prime number of a specific bit length."""
    while True:
        # Generate a random integer with the exact bit length
        p = secrets.randbits(bit_length)
        # Ensure the number is odd (lowest bit is 1) and has the correct bit length (highest bit is 1)
        p |= (1 << bit_length - 1) | 1 
        
        # Check if it's prime
        if is_prime(p):
            return p

def ext_euclid_gcd(a, b):
        """Extended Euclideam Algorithm with recursion to find inverse of e"""
        if b == 0:
            return (a, 1, 0)
        (c1, x1, y1) = ext_euclid_gcd(b, a%b)
        c = c1
        x = y1
        y = x1 - (a // b) * y1
        return (c, x, y)

def multinv(e, totient):
    """Multiplicative Inverse to find inverse of e"""
    (c, x, y) = ext_euclid_gcd(e, totient)
    return x