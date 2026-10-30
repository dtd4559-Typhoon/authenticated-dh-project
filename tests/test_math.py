import unittest
from modular_math import modular_exponentiation


class ModularMathTests(unittest.TestCase):
    def test_known_result(self):
        self.assertEqual(modular_exponentiation(5, 6, 23), 8)

    def test_zero_exponent(self):
        self.assertEqual(modular_exponentiation(5, 0, 23), 1)

    def test_modulus_one(self):
        self.assertEqual(modular_exponentiation(5, 0, 1), 0)
        self.assertEqual(modular_exponentiation(7, 10, 1), 0)

    def test_negative_base(self):
        self.assertEqual(modular_exponentiation(-5, 3, 23), 13)

    def test_invalid_types(self):
        for args in ((True, 2, 23), (5, False, 23), (5, 2, True),
                     ("5", 2, 23), (5, 2.0, 23), (5, 2, None)):
            with self.subTest(args=args), self.assertRaises(TypeError):
                modular_exponentiation(*args)

    def test_invalid_values(self):
        for args in ((5, -1, 23), (5, 2, 0), (5, 2, -3)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                modular_exponentiation(*args)

    def test_independent_pow_reference(self):
        # pow() is deliberately restricted to tests, per the handout.
        for base in (-100, -1, 0, 1, 5, 123456789):
            for exponent in (0, 1, 2, 15, 31, 65537):
                for modulus in (1, 2, 23, 65537):
                    with self.subTest(base=base, exponent=exponent, modulus=modulus):
                        result = modular_exponentiation(base, exponent, modulus)
                        self.assertEqual(result, pow(base, exponent, modulus))
                        self.assertTrue(0 <= result < modulus)
