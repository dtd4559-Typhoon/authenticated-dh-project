import json
import unittest
from unittest.mock import patch
from authentication import ProtocolError, sign_message, decode_message, canonical_bytes
from eve import change_field, corrupt_signature, unauthenticated_fixture
from participant import trusted_setup, create_participant, reset_session
from protocol import (start_exchange, receive_init, receive_response,
                      receive_finish, complete_exchange)


class ExchangeTests(unittest.TestCase):
    def setUp(self):
        self.alice, self.bob = trusted_setup()

    def response_ready(self):
        init = start_exchange(self.alice, test_fixture=True)
        response = receive_init(self.bob, init, test_fixture=True)
        return init, response

    def assert_aborted(self, person):
        self.assertEqual(person["status"], "aborted")
        self.assertIsNone(person["pending"])
        self.assertIsNone(person["shared_secret"])
        self.assertFalse(person["transcript_authenticated"])

    def test_fixed_authenticated_fixture(self):
        result = complete_exchange(self.alice, self.bob, test_fixture=True)
        self.assertTrue(result["authenticated"])
        self.assertTrue(result["secrets_match"])
        self.assertEqual(self.alice["shared_secret"], 2)
        self.assertEqual(self.bob["shared_secret"], 2)
        transcript = json.loads(result["messages"][1])["payload"]["transcript"]
        self.assertEqual((transcript["A"], transcript["B"]), (8, 19))
        for raw in result["messages"]:
            self.assertNotIn('"private"', raw.decode())
            self.assertNotIn('"shared_secret"', raw.decode())

    def test_generated_exchanges_and_retained_identity_keys(self):
        alice_key = self.alice["signing_key"]
        bob_key = self.bob["signing_key"]
        for bits in (16, 24, 32):
            with self.subTest(bits=bits):
                result = complete_exchange(self.alice, self.bob, bits)
                self.assertTrue(result["authenticated"] and result["secrets_match"])
                self.assertIs(self.alice["signing_key"], alice_key)
                self.assertIs(self.bob["signing_key"], bob_key)

    def test_bob_waits_for_finish(self):
        self.response_ready()
        self.assertEqual(self.bob["status"], "waiting_finish")
        self.assertIsNone(self.bob["shared_secret"])
        self.assertFalse(self.bob["transcript_authenticated"])

    def test_init_tampering(self):
        for field, value in (("A", 10), ("p", 29), ("g", 7),
                             ("initiator", "Eve"), ("responder", "Alice"),
                             ("nonce_A", "f" * 64), ("protocol", "other")):
            self.setUp()
            init = start_exchange(self.alice, test_fixture=True)
            with self.subTest(field=field), self.assertRaises(ProtocolError):
                receive_init(self.bob, change_field(init, field, value), test_fixture=True)
            self.assert_aborted(self.bob)

    def test_response_tampering(self):
        for field, value in (("B", 17), ("A", 10), ("p", 29), ("g", 7),
                             ("initiator", "Eve"), ("nonce_B", "f" * 64)):
            self.setUp()
            init, response = self.response_ready()
            with self.subTest(field=field), self.assertRaises(ProtocolError):
                receive_response(self.alice, change_field(response, field, value))
            self.assert_aborted(self.alice)

    def test_corrupt_signature_at_each_stage(self):
        for stage in ("init", "response", "finish"):
            self.setUp()
            init = start_exchange(self.alice, test_fixture=True)
            if stage == "init":
                with self.assertRaises(ProtocolError):
                    receive_init(self.bob, corrupt_signature(init), True)
                self.assert_aborted(self.bob)
                continue
            response = receive_init(self.bob, init, True)
            if stage == "response":
                with self.assertRaises(ProtocolError):
                    receive_response(self.alice, corrupt_signature(response))
                self.assert_aborted(self.alice)
                continue
            finish = receive_response(self.alice, response)
            with self.assertRaises(ProtocolError):
                receive_finish(self.bob, corrupt_signature(finish))
            self.assert_aborted(self.bob)

    def test_eve_cannot_sign_as_alice(self):
        eve = create_participant("Eve")
        init = start_exchange(self.alice, test_fixture=True)
        payload = decode_message(init)["payload"]
        forged = sign_message(payload, eve["signing_key"])
        with self.assertRaises(ProtocolError):
            receive_init(self.bob, forged, True)
        self.assert_aborted(self.bob)

    def test_wrong_or_missing_trusted_key(self):
        for key in (create_participant("Eve")["signing_key"].public_key(), None):
            self.setUp()
            self.bob["trusted_keys"]["Alice"] = key
            init = start_exchange(self.alice, test_fixture=True)
            with self.assertRaises(ProtocolError):
                receive_init(self.bob, init, True)
            self.assert_aborted(self.bob)

    def test_valid_signature_does_not_bypass_parameter_checks(self):
        for field, value in (("p", 32769), ("g", 2), ("A", 1), ("A", 22)):
            self.setUp()
            init = start_exchange(self.alice, test_fixture=True)
            payload = decode_message(init)["payload"]
            payload[field] = value
            signed = sign_message(payload, self.alice["signing_key"])
            with self.subTest(field=field, value=value), self.assertRaises(ProtocolError):
                receive_init(self.bob, signed, True)
            self.assert_aborted(self.bob)

    def test_signed_bad_b_rejected(self):
        for value in (0, 1, 22, 23):
            self.setUp()
            init, response = self.response_ready()
            payload = decode_message(response)["payload"]
            payload["transcript"]["B"] = value
            signed = sign_message(payload, self.bob["signing_key"])
            with self.assertRaises(ProtocolError):
                receive_response(self.alice, signed)
            self.assert_aborted(self.alice)

    def test_old_response_rejected_in_fresh_alice_session(self):
        old = complete_exchange(self.alice, self.bob, test_fixture=True)
        start_exchange(self.alice, test_fixture=True)
        with self.assertRaises(ProtocolError):
            receive_response(self.alice, old["messages"][1])
        self.assert_aborted(self.alice)

    def test_old_finish_rejected_in_fresh_bob_session(self):
        old = complete_exchange(self.alice, self.bob, test_fixture=True)
        self.response_ready()
        with self.assertRaises(ProtocolError):
            receive_finish(self.bob, old["messages"][2])
        self.assert_aborted(self.bob)

    def test_replayed_init_can_prompt_but_not_complete_exchange(self):
        old = complete_exchange(self.alice, self.bob, test_fixture=True)
        response = receive_init(self.bob, old["messages"][0], True)
        self.assertEqual(self.bob["status"], "waiting_finish")
        self.assertIsNone(self.bob["shared_secret"])
        self.assertNotEqual(decode_message(response)["payload"]["transcript"]["nonce_B"],
                            decode_message(old["messages"][1])["payload"]["transcript"]["nonce_B"])
        with self.assertRaises(ProtocolError):
            receive_finish(self.bob, old["messages"][2])
        self.assert_aborted(self.bob)

    def test_duplicate_finish_rejected(self):
        result = complete_exchange(self.alice, self.bob, test_fixture=True)
        with self.assertRaises(ProtocolError):
            receive_finish(self.bob, result["messages"][2])
        self.assert_aborted(self.bob)

    def test_wrong_order_rejected(self):
        with self.assertRaises(ProtocolError):
            receive_response(self.alice, b"{}")
        self.assert_aborted(self.alice)
        with self.assertRaises(ProtocolError):
            receive_finish(self.bob, b"{}")
        self.assert_aborted(self.bob)

    def test_wrong_message_stage_in_valid_session(self):
        init, response = self.response_ready()
        with self.assertRaises(ProtocolError):
            receive_response(self.alice, init)
        self.assert_aborted(self.alice)

    def test_pending_session_rejects_another_init(self):
        init, response = self.response_ready()
        with self.assertRaises(ProtocolError):
            receive_init(self.bob, init, True)
        self.assert_aborted(self.bob)

    def test_unexpected_fields_and_oversized_message_abort(self):
        for raw in (b"{" + b"x" * 4096, b'{"unexpected":true}', b"{bad"):
            self.setUp()
            self.response_ready()
            with self.assertRaises(ProtocolError):
                receive_response(self.alice, raw)
            self.assert_aborted(self.alice)

    def test_finish_requires_exact_pending_transcript(self):
        init, response = self.response_ready()
        finish = receive_response(self.alice, response)
        payload = decode_message(finish)["payload"]
        payload["transcript"]["nonce_B"] = "0" * 64
        # Even a valid Alice signature cannot authorize a different session.
        changed = sign_message(payload, self.alice["signing_key"])
        with self.assertRaises(ProtocolError):
            receive_finish(self.bob, changed)
        self.assert_aborted(self.bob)

    def test_new_nonces_use_secrets_for_each_party(self):
        with patch("protocol.secrets.token_bytes", side_effect=[b"a"*32, b"b"*32]):
            result = complete_exchange(self.alice, self.bob, test_fixture=True)
        transcript = decode_message(result["messages"][1])["payload"]["transcript"]
        self.assertEqual(transcript["nonce_A"], (b"a"*32).hex())
        self.assertEqual(transcript["nonce_B"], (b"b"*32).hex())

    def test_unauthenticated_attack_fixture(self):
        result = unauthenticated_fixture()
        self.assertEqual(result["alice_secret"], result["eve_alice_secret"])
        self.assertEqual(result["bob_secret"], result["eve_bob_secret"])
        self.assertEqual((result["alice_secret"], result["bob_secret"]), (6, 15))
