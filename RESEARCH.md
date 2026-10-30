# Finite-field Diffie-Hellman compared with ECDH

The project's finite-field Diffie-Hellman operates on integers modulo a prime p.
Alice publishes A = g^a mod p, Bob publishes B = g^b mod p, and both compute
g^(ab) mod p. Square-and-multiply makes these exponentiations efficient. Elliptic-curve
Diffie-Hellman instead uses scalar multiplication of curve points: Alice publishes
aG, Bob publishes bG, and both obtain abG. The cryptography library provides ECDH
as a key-agreement primitive and recommends passing its output through a key
derivation function rather than using the raw result directly [1].

This assignment limits primes to 16-32 bits so that generated examples, debugging,
and trial division finish quickly. These sizes are insecure: their tiny groups
allow feasible recovery of private exponents by discrete-log attacks. The bit
length of the modulus also does not directly equal the security strength. Signing
the exchange can detect unauthorized changes, but it does not prevent an attacker
from solving the small group's discrete logarithms.

Factoring p - 1 supplies the distinct prime factors needed to verify a primitive
generator. The implemented trial-division method works well for the small classroom
range, but scales poorly as p grows because candidate divisors can extend toward
the square root of p - 1. This arbitrary-prime workflow is therefore unsuitable
for choosing production-size parameters. ECDH uses established curve parameters
and does not require this project's factorization of a newly generated p - 1.

Ephemeral ECDH, or ECDHE, generates a new key-agreement private value for each
exchange. The library documentation explicitly distinguishes this from reusing a
static private key [1]. With an appropriately authenticated protocol and proper
handling of temporary secrets, fresh ephemeral keys support forward secrecy:
later compromise of a long-term authentication key need not expose past session
keys. RFC 9528's EDHOC is a concrete standardized example of authenticated
ephemeral Diffie-Hellman with mutual authentication and forward secrecy [2].

ECDH still requires authentication. Without a trusted binding between an identity
and its public credential, Eve can substitute public values and negotiate separate
secrets with each participant. Ed25519 in this project signs the transcript; it
is not the ECDH key-exchange operation. Production software combines established
protocols, validated parameters, carefully implemented libraries, and contextual
key derivation. As EDHOC illustrates, session binding and authentication are
protocol responsibilities, not properties supplied by bare key agreement alone [2].

## References

[1] Python Cryptographic Authority, "Elliptic curve cryptography," sections
"Elliptic Curve Key Exchange algorithm" and the ephemeral ECDHE example.
https://cryptography.io/en/stable/hazmat/primitives/asymmetric/ec/#elliptic-curve-key-exchange-algorithm

[2] G. Selander, J. Preuss Mattsson, and F. Palombini, RFC 9528,
"Ephemeral Diffie-Hellman Over COSE (EDHOC)," March 2024, abstract,
sections 2, 4.1.1.1, and 9.1.
https://www.rfc-editor.org/rfc/rfc9528.html

Additional implementation references:

- PyCryptodome, Crypto.Util.number (getPrime and isPrime):
  https://www.pycryptodome.org/src/util/util#module-Crypto.Util.number
- Python, secrets module: https://docs.python.org/3/library/secrets.html
- Python Cryptographic Authority, Ed25519 signing:
  https://cryptography.io/en/stable/hazmat/primitives/asymmetric/ed25519/
