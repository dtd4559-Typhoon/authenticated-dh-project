"""Step 10: local interception/tampering; Eve never gets trusted private keys."""

import json
from authentication import canonical_bytes
from modular_math import modular_exponentiation


def change_field(raw, field, value):
    """Keep the original signature while modifying a signed field."""
    message = json.loads(raw)
    payload = message["payload"]
    target = payload.get("transcript", payload)
    target[field] = value
    return canonical_bytes(message)


def corrupt_signature(raw):
    message = json.loads(raw)
    original = message["signature"]
    message["signature"] = ("0" if original[0] != "0" else "1") + original[1:]
    return canonical_bytes(message)


def unauthenticated_fixture():
    """Fixed classroom fixture; results are local and are NOT network messages."""
    p, g, a, b = 23, 5, 6, 15
    e1, e2 = 3, 7
    A = modular_exponentiation(g, a, p)
    B = modular_exponentiation(g, b, p)
    E1 = modular_exponentiation(g, e1, p)
    E2 = modular_exponentiation(g, e2, p)
    return {"A": A, "B": B, "E1": E1, "E2": E2,
            "alice_secret": modular_exponentiation(E1, a, p),
            "eve_alice_secret": modular_exponentiation(A, e1, p),
            "bob_secret": modular_exponentiation(E2, b, p),
            "eve_bob_secret": modular_exponentiation(B, e2, p)}
