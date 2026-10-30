"""Local participant state and trusted setup (never accepted from the wire)."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def create_participant(name):
    if name not in ("Alice", "Bob", "Eve"):
        raise ValueError("unknown classroom participant")
    return {"name": name, "signing_key": Ed25519PrivateKey.generate(),
            "trusted_keys": {}, "pending": None, "status": "idle",
            "shared_secret": None, "transcript_authenticated": False}


def trusted_setup():
    """Identity keys persist for all exchanges using these participant objects."""
    alice = create_participant("Alice")
    bob = create_participant("Bob")
    alice["trusted_keys"]["Bob"] = bob["signing_key"].public_key()
    bob["trusted_keys"]["Alice"] = alice["signing_key"].public_key()
    return alice, bob


def reset_session(person):
    """Keep identity keys, but discard the previous exchange's usable state."""
    person["pending"] = None
    person["shared_secret"] = None
    person["transcript_authenticated"] = False
    person["status"] = "idle"


def abort_session(person):
    reset_session(person)
    person["status"] = "aborted"
