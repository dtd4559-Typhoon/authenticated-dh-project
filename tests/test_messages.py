import json
import unittest
from unittest.mock import patch
from authentication import (ProtocolError, canonical_bytes, decode_message,
                            sign_message, validate_payload)
from participant import trusted_setup
from protocol import start_exchange, receive_init


class MessageValidationTests(unittest.TestCase):
    def setUp(self):
        self.alice, self.bob = trusted_setup()
        self.init = start_exchange(self.alice, test_fixture=True)
        self.payload = json.loads(self.init)["payload"]

    def test_deterministic_encoding(self):
        self.assertEqual(canonical_bytes({"p": 23, "A": 8, "g": 5}),
                         b'{"A":8,"g":5,"p":23}')

    def test_duplicate_outer_json_key(self):
        raw = b'{"payload":{},"payload":{},"signature":"' + b"0" * 128 + b'"}'
        with self.assertRaises(ProtocolError):
            decode_message(raw)

    def test_duplicate_nested_json_key(self):
        raw = b'{"payload":{"p":23,"p":23},"signature":"' + b"0" * 128 + b'"}'
        with self.assertRaises(ProtocolError):
            decode_message(raw)

    def test_malformed_oversized_and_wrong_wire_types(self):
        for raw in (b"{", b"x" * 4097, b"\xff", b"[]", b"null", "not bytes"):
            with self.subTest(raw=str(raw)[:30]), self.assertRaises(ProtocolError):
                decode_message(raw)

    def test_nonstandard_constants_rejected(self):
        for constant in (b"NaN", b"Infinity", b"-Infinity"):
            with self.assertRaises(ProtocolError):
                decode_message(b'{"payload":{"p":' + constant + b'},"signature":"' + b"0"*128 + b'"}')

    def test_unexpected_and_missing_fields(self):
        for action in ("extra", "missing"):
            payload = dict(self.payload)
            if action == "extra":
                payload["signing_public_key"] = "untrusted network key"
            else:
                del payload["nonce_A"]
            with self.assertRaises(ProtocolError):
                validate_payload(payload, "init", True)

    def test_wrong_numeric_types_and_size(self):
        for field in ("p", "g", "A"):
            for value in (True, "23", 23.0, -1, 2**100):
                payload = dict(self.payload)
                payload[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ProtocolError):
                    validate_payload(payload, "init", True)

    def test_nonce_and_signature_formats(self):
        for nonce in ("", "0" * 63, "x" * 64, " " * 64, 123, None):
            payload = dict(self.payload)
            payload["nonce_A"] = nonce
            with self.assertRaises(ProtocolError):
                validate_payload(payload, "init", True)
        for signature in ("0" * 127, "g" * 128, 123):
            message = json.loads(self.init)
            message["signature"] = signature
            with self.assertRaises(ProtocolError):
                decode_message(canonical_bytes(message))

    def test_expensive_factorization_not_called_for_bad_modulus(self):
        for p in (True, "32769", 2**100, 32769):
            payload = dict(self.payload)
            payload["p"] = p
            raw = sign_message(payload, self.alice["signing_key"])
            with self.subTest(p=p), patch("protocol.prime_factors") as factor:
                with self.assertRaises(ProtocolError):
                    receive_init(self.bob, raw)
                factor.assert_not_called()

    def test_private_fields_never_in_messages(self):
        forbidden = {"private", "private_key", "signing_key", "shared_secret", "a", "b"}
        def inspect(value):
            if type(value) is dict:
                self.assertFalse(forbidden.intersection(value))
                for child in value.values():
                    inspect(child)
        inspect(json.loads(self.init))
