"""Steps 6-7: Ed25519 signatures and strictly validated JSON messages."""

import json
from cryptography.exceptions import InvalidSignature

PROTOCOL = "DH-CLASSROOM-AUTH-v1"
MAX_MESSAGE_BYTES = 4096
INIT_FIELDS = {"protocol", "message_type", "initiator", "responder",
               "p", "g", "A", "nonce_A"}
TRANSCRIPT_FIELDS = {"protocol", "initiator", "responder", "p", "g",
                     "A", "B", "nonce_A", "nonce_B"}


class ProtocolError(ValueError):
    """An invalid message or protocol transition stops the affected session."""


def canonical_bytes(message):
    return json.dumps(message, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def exact_fields(obj, expected):
    if type(obj) is not dict or set(obj) != expected:
        raise ProtocolError("unexpected or missing fields")


def check_hex(value, size):
    if (type(value) is not str or len(value) != size
            or any(c not in "0123456789abcdefABCDEF" for c in value)):
        raise ProtocolError("malformed hexadecimal value")


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value):
    raise ProtocolError("nonstandard JSON numeric constant")


def decode_message(raw):
    """Check byte size before parsing; reject duplicates at every nesting level."""
    if type(raw) is not bytes:
        raise ProtocolError("network message must be bytes")
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ProtocolError("message exceeds 4096 bytes")
    try:
        envelope = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates,
                              parse_constant=_reject_constant)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ProtocolError("malformed JSON: " + str(error)) from error
    exact_fields(envelope, {"payload", "signature"})
    if type(envelope["payload"]) is not dict:
        raise ProtocolError("payload must be an object")
    check_hex(envelope["signature"], 128)
    return envelope


def validate_payload(payload, message_type, test_fixture=False):
    """Cheap schema and integer bounds checks happen before prime arithmetic."""
    if message_type == "init":
        exact_fields(payload, INIT_FIELDS)
        values = payload
    else:
        exact_fields(payload, {"message_type", "transcript"})
        values = payload["transcript"]
        exact_fields(values, TRANSCRIPT_FIELDS)
    if payload["message_type"] != message_type:
        raise ProtocolError("unexpected message type")
    if (values["protocol"] != PROTOCOL or values["initiator"] != "Alice"
            or values["responder"] != "Bob"):
        raise ProtocolError("wrong protocol or expected identities")
    for field in ("p", "g", "A") + (() if message_type == "init" else ("B",)):
        value = values[field]
        if type(value) is not int or value < 0 or value.bit_length() > 32:
            raise ProtocolError("invalid integer type or size: " + field)
    p = values["p"]
    if not (test_fixture and p == 23) and not 16 <= p.bit_length() <= 32:
        raise ProtocolError("modulus outside normal 16-32-bit bounds")
    check_hex(values["nonce_A"], 64)
    if message_type != "init":
        check_hex(values["nonce_B"], 64)
    return values


def sign_message(payload, signing_key):
    signature = signing_key.sign(canonical_bytes(payload))
    raw = canonical_bytes({"payload": payload, "signature": signature.hex()})
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ProtocolError("outgoing message exceeds size limit")
    return raw


def verify_message(envelope, trusted_key):
    if trusted_key is None:
        raise ProtocolError("missing trusted identity key")
    try:
        trusted_key.verify(bytes.fromhex(envelope["signature"]),
                           canonical_bytes(envelope["payload"]))
    except InvalidSignature as error:
        raise ProtocolError("signature INVALID") from error
