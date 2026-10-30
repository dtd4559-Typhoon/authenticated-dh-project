"""Steps 8-9: init -> response -> finish, with one active session per person."""

import secrets
from authentication import (PROTOCOL, ProtocolError, decode_message, sign_message,
                            validate_payload, verify_message)
from modular_math import modular_exponentiation
from parameters import (generate_prime, validate_modulus, prime_factors,
                        find_generator, is_generator, generate_dh_keypair,
                        validate_public_value)
from participant import reset_session, abort_session


def _keypair(p, g, fixture_private):
    if fixture_private is None:
        return generate_dh_keypair(p, g)
    if type(fixture_private) is not int or not 2 <= fixture_private <= p - 2:
        raise ProtocolError("invalid fixture exponent")
    public = modular_exponentiation(g, fixture_private, p)
    validate_public_value(public, p)
    return fixture_private, public


def start_exchange(alice, bits=16, test_fixture=False, parameters=None):
    if alice["name"] != "Alice" or alice["status"] in ("waiting_response", "waiting_finish"):
        raise ProtocolError("cannot start an exchange in this state")
    reset_session(alice)
    try:
        if test_fixture:
            p, g = 23, 5
        elif parameters is None:
            p = generate_prime(bits)
            g = find_generator(p)
        else:
            p, g = parameters
        validate_modulus(p, test_fixture)
        if not is_generator(g, p):
            raise ProtocolError("invalid generator")
        private, public = _keypair(p, g, 6 if test_fixture else None)
        payload = {"protocol": PROTOCOL, "message_type": "init",
                   "initiator": "Alice", "responder": "Bob", "p": p,
                   "g": g, "A": public, "nonce_A": secrets.token_bytes(32).hex()}
        alice["pending"] = {"init": payload, "private": private,
                            "test_fixture": test_fixture}
        alice["status"] = "waiting_response"
        return sign_message(payload, alice["signing_key"])
    except (ValueError, TypeError) as error:
        abort_session(alice)
        raise ProtocolError(str(error)) from error


def receive_init(bob, raw, test_fixture=False):
    try:
        if bob["name"] != "Bob" or bob["status"] not in ("idle", "complete", "aborted"):
            raise ProtocolError("unexpected initiation for active session")
        reset_session(bob)
        envelope = decode_message(raw)
        values = validate_payload(envelope["payload"], "init", test_fixture)
        verify_message(envelope, bob["trusted_keys"].get("Alice"))
        p, g = values["p"], values["g"]
        validate_modulus(p, test_fixture)
        factors = prime_factors(p - 1)
        if not is_generator(g, p, factors):
            raise ProtocolError("received generator failed verification")
        validate_public_value(values["A"], p)
        private, public = _keypair(p, g, 15 if test_fixture else None)
        transcript = {key: value for key, value in values.items() if key != "message_type"}
        transcript.update({"B": public, "nonce_B": secrets.token_bytes(32).hex()})
        bob["pending"] = {"transcript": transcript, "private": private,
                          "test_fixture": test_fixture}
        bob["status"] = "waiting_finish"
        return sign_message({"message_type": "response", "transcript": transcript},
                            bob["signing_key"])
    except (ValueError, TypeError) as error:
        abort_session(bob)
        raise ProtocolError(str(error)) from error


def receive_response(alice, raw):
    try:
        if alice["name"] != "Alice" or alice["status"] != "waiting_response":
            raise ProtocolError("unexpected response or wrong message order")
        pending = alice["pending"]
        envelope = decode_message(raw)
        transcript = validate_payload(envelope["payload"], "response", pending["test_fixture"])
        for key, value in pending["init"].items():
            if key != "message_type" and transcript[key] != value:
                raise ProtocolError("response does not match pending session: " + key)
        validate_public_value(transcript["B"], transcript["p"])
        verify_message(envelope, alice["trusted_keys"].get("Bob"))
        finish = sign_message({"message_type": "finish", "transcript": transcript},
                              alice["signing_key"])
        alice["shared_secret"] = modular_exponentiation(
            transcript["B"], pending["private"], transcript["p"])
        alice["transcript_authenticated"] = True
        alice["status"] = "complete"
        alice["pending"] = None
        return finish
    except (ValueError, TypeError) as error:
        abort_session(alice)
        raise ProtocolError(str(error)) from error


def receive_finish(bob, raw):
    try:
        if bob["name"] != "Bob" or bob["status"] != "waiting_finish":
            raise ProtocolError("unexpected finish or session already completed")
        pending = bob["pending"]
        envelope = decode_message(raw)
        transcript = validate_payload(envelope["payload"], "finish", pending["test_fixture"])
        if transcript != pending["transcript"]:
            raise ProtocolError("finish does not match pending transcript")
        verify_message(envelope, bob["trusted_keys"].get("Alice"))
        bob["shared_secret"] = modular_exponentiation(
            transcript["A"], pending["private"], transcript["p"])
        bob["transcript_authenticated"] = True
        bob["status"] = "complete"
        bob["pending"] = None
    except (ValueError, TypeError) as error:
        abort_session(bob)
        raise ProtocolError(str(error)) from error


def complete_exchange(alice, bob, bits=16, test_fixture=False, parameters=None):
    """Coordinator compares local state; secrets are never serialized."""
    init = start_exchange(alice, bits, test_fixture, parameters)
    response = receive_init(bob, init, test_fixture)
    finish = receive_response(alice, response)
    receive_finish(bob, finish)
    return {"messages": [init, response, finish],
            "authenticated": alice["transcript_authenticated"] and bob["transcript_authenticated"],
            "secrets_match": alice["shared_secret"] == bob["shared_secret"]}
