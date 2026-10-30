import unittest
from unittest.mock import patch
from Crypto.Util.number import isPrime
from parameters import (generate_prime, validate_modulus, prime_factors,
                        is_generator, find_generator, generate_dh_keypair,
                        validate_public_value)


class ParameterUnitTests(unittest.TestCase):
    def test_factors_one(self):
        self.assertEqual(prime_factors(1), set())

    def test_factors_twenty_two(self):
        self.assertEqual(prime_factors(22), {2, 11})

    def test_repeated_factors(self):
        self.assertEqual(prime_factors(65536), {2})
        self.assertEqual(prime_factors(2 * 3 * 3 * 7), {2, 3, 7})

    def test_factorization_invalid(self):
        for n in (0, -1, True, 1.5, "22"):
            with self.subTest(n=n), self.assertRaises((TypeError, ValueError)):
                prime_factors(n)

    def test_generator_fixtures(self):
        self.assertTrue(is_generator(5, 23))
        self.assertFalse(is_generator(2, 23))
        self.assertTrue(is_generator(3, 65537))
        self.assertEqual(find_generator(23), 5)

    def test_incomplete_factors_rejected(self):
        for function in (lambda: is_generator(2, 23, {11}),
                         lambda: find_generator(23, {11})):
            with self.assertRaises(ValueError):
                function()

    def test_generator_range(self):
        for g in (0, 1, 22, 23, True, "5"):
            with self.subTest(g=g):
                self.assertFalse(is_generator(g, 23))

    def test_public_range(self):
        for value in (0, 1, 22, 23, True, "8", 8.0):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_public_value(value, 23)

    def test_retry_out_of_range_generated_public(self):
        # a=11 gives g^a=-1 mod 23; a=2 gives an allowed public value 2.
        with patch("parameters.secrets.randbelow", side_effect=[9, 0]):
            self.assertEqual(generate_dh_keypair(23, 5), (2, 2))

    def test_generate_wrapper_calls_library(self):
        with patch("parameters.getPrime", return_value=65521) as generator:
            self.assertEqual(generate_prime(), 65521)
            self.assertEqual(generator.call_args.args, (16,))
            self.assertIn("randfunc", generator.call_args.kwargs)

    def test_invalid_requested_size_precedes_library(self):
        for bits in (True, False, 15, 33, 16.0, "16", None):
            with self.subTest(bits=bits), patch("parameters.getPrime") as generator:
                with self.assertRaises((TypeError, ValueError)):
                    generate_prime(bits)
                generator.assert_not_called()

    def test_bad_library_shape_rejected(self):
        for value in (23, 32768, True):
            with patch("parameters.getPrime", return_value=value):
                with self.assertRaises(ValueError):
                    generate_prime(16)

    def test_received_composite(self):
        with self.assertRaises(ValueError):
            validate_modulus(32769)

    def test_received_invalid_type_size_precedes_primality(self):
        for value in (True, "65521", 65521.0, 23, -7, 2**40 + 1):
            with self.subTest(value=value), patch("parameters.isPrime") as checker:
                with self.assertRaises((TypeError, ValueError)):
                    validate_modulus(value)
                checker.assert_not_called()

    def test_fixture_path_is_explicit(self):
        self.assertTrue(validate_modulus(23, test_fixture=True))
        with self.assertRaises(ValueError):
            validate_modulus(21, test_fixture=True)
        with self.assertRaises(ValueError):
            validate_modulus(23)


class PrimeGeneratorIntegrationTests(unittest.TestCase):
    def test_all_supported_bit_lengths(self):
        for bits in range(16, 33):
            with self.subTest(bits=bits):
                p = generate_prime(bits)
                self.assertEqual(p.bit_length(), bits)
                self.assertEqual(p % 2, 1)
                self.assertTrue(isPrime(p))
                self.assertTrue(validate_modulus(p))
