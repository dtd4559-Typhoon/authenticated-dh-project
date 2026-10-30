"""Steps 2-4: library primes, trial division, and primitive generators."""

import secrets
from Crypto.Util.number import getPrime, isPrime
from modular_math import modular_exponentiation


def validate_bits(bits):
    if type(bits) is not int:
        raise TypeError("prime size must be an integer (not bool)")
    if not 16 <= bits <= 32:
        raise ValueError("prime size must be between 16 and 32 bits")


def generate_prime(bits=16):
    """Generate an exact-size prime; primality algorithms belong to the library."""
    validate_bits(bits)
    p = getPrime(bits, randfunc=secrets.token_bytes)
    if type(p) is not int or p.bit_length() != bits or p % 2 != 1:
        raise ValueError("library returned an unexpected prime size or parity")
    return p


def validate_modulus(p, test_fixture=False):
    """Validate received p before factoring it. Only fixture mode permits p=23."""
    if type(p) is not int:
        raise TypeError("modulus must be an integer (not bool)")
    if not (test_fixture and p == 23) and not 16 <= p.bit_length() <= 32:
        raise ValueError("received modulus must be between 16 and 32 bits")
    if not isPrime(p):
        raise ValueError("received modulus is composite")
    return True


def prime_factors(n):
    """Return every distinct prime factor, dividing out repeated occurrences."""
    if type(n) is not int:
        raise TypeError("n must be an integer (not bool)")
    if n < 1:
        raise ValueError("n must be positive")
    factors = set()
    if n % 2 == 0:
        factors.add(2)
        while n % 2 == 0:
            n = n // 2
    divisor = 3
    while divisor * divisor <= n:
        if n % divisor == 0:
            factors.add(divisor)
            while n % divisor == 0:
                n = n // divisor
        divisor += 2
    if n > 1:
        factors.add(n)
    return factors


def is_generator(g, p, factors=None):
    """Criterion assumes p was validated as prime by validate_modulus()."""
    if type(p) is not int or p < 5 or p.bit_length() > 32:
        raise ValueError("unsupported modulus for generator checking")
    if type(g) is not int or not 2 <= g <= p - 2:
        return False
    complete_factors = prime_factors(p - 1)
    if factors is not None and set(factors) != complete_factors:
        raise ValueError("generator check requires all distinct prime factors")
    for factor in complete_factors:
        if modular_exponentiation(g, (p - 1) // factor, p) == 1:
            return False
    return True


def find_generator(p, factors=None):
    """Search candidates using the complete factor set and custom arithmetic."""
    complete_factors = prime_factors(p - 1)
    if factors is not None and set(factors) != complete_factors:
        raise ValueError("generator search requires all distinct prime factors")
    for g in range(2, p - 1):
        # Factor once above, rather than repeating division for every candidate.
        if all(modular_exponentiation(g, (p - 1) // r, p) != 1
               for r in complete_factors):
            return g
    raise ValueError("no generator found")


def validate_public_value(value, p):
    if type(value) is not int or not 2 <= value <= p - 2:
        raise ValueError("public value must be an integer from 2 through p - 2")


def generate_dh_keypair(p, g):
    """Step 5: retry if the public value is outside the classroom range."""
    while True:
        private_key = secrets.randbelow(p - 3) + 2
        public_value = modular_exponentiation(g, private_key, p)
        if 2 <= public_value <= p - 2:
            return private_key, public_value
