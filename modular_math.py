"""Step 1: square-and-multiply, written without pow() or full powers."""


def modular_exponentiation(base, exponent, modulus):
    """Return base**exponent mod modulus using repeated squaring."""
    if any(type(value) is not int for value in (base, exponent, modulus)):
        raise TypeError("base, exponent, and modulus must be integers (not bool)")
    if exponent < 0 or modulus <= 0:
        raise ValueError("exponent must be nonnegative and modulus must be positive")

    result = 1 % modulus
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent = exponent // 2
    return result
