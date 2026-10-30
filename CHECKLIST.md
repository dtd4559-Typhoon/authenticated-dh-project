# Assignment completion checklist

## Steps 1 through 10

| Required step | Implementation | Evidence |
|---|---|---|
| 1. Square-and-multiply | modular_math.py | tests/test_math.py; REPORT section 2 |
| 2. Library prime generation and received-p validation | parameters.py | tests/test_parameters.py; normal sample output |
| 3. Factor p - 1 | parameters.py: prime_factors | Fixed examples 1, 22, 65536 and repeated factors |
| 4. Find and verify g | parameters.py | Accept 5/reject 2 for 23; accept 3 for 65537 |
| 5. Fresh DH private exponents and public values | parameters.py, protocol.py | Range/retry tests; fixture and generated exchanges |
| 6. Trusted Ed25519 identities | participant.py, authentication.py | Trusted-setup and Eve/wrong-key tests |
| 7. Fresh nonces, strict messages, canonical JSON | authentication.py, protocol.py | tests/test_messages.py and nonce tests |
| 8. Signed init, response, finish | protocol.py | Saved public messages and signature results |
| 9. Secret calculation and local equality | protocol.py | Fixture secret 2; generated local comparisons |
| 10. Eve attack and authenticated rejection | eve.py, main.py | results/eve_attacks.txt and protocol tests |

## Remaining handout sections

- Testing: 54 passing methods across four test modules, with additional subtests.
- Performance: nine actual exchanges; three each at 16, 24, 32 bits.
- Environment and timing variation: results/environment.json and performance.md.
- Suggested organization: uses the seven suggested Python modules plus tests.
- Report: REPORT.md and the dark-background report.pdf.
- 300-500-word ECDH research comparison: RESEARCH.md with two authoritative references.
- Deliverables: all source files, pinned requirements, README, tests, samples,
  performance data, and report are included in the project folder.
- Rubric: mathematics, library primes/input limits, factorization/generators,
  DH agreement, trusted signatures/state, attack tests, and documentation covered.
- Optional extensions: safe primes, operation counting, implemented ECDH, sockets,
  and HKDF/HMAC key confirmation are identified as optional and not implemented.
- Security context: small-group insecurity, non-constant-time arithmetic,
  signatures versus possession of the secret, and absence of encryption are
  explicitly explained in the README and report.

## Submission files

Use the contents of this folder for the later GitHub repository. The ZIP is a
portable copy of this same folder. No account login, repository creation, or
GitHub upload has been performed.
