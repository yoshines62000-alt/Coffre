"""Tests pour totp.py : implementation TOTP (RFC 6238) en Python pur.

Verifie le calcul contre les vecteurs de test OFFICIELS de l'annexe B de
la RFC 6238 (https://datatracker.ietf.org/doc/html/rfc6238#appendix-B) -
la reference qui fait foi pour toute implementation TOTP - ainsi que la
normalisation base32, la validation, et le compte a rebours."""

import base64
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import totp


# Graines ASCII de la RFC 6238, annexe B. La graine SHA1 est repetee pour
# atteindre la longueur voulue de chaque algorithme.
_SEED_SHA1 = b"12345678901234567890"  # 20 octets
_SEED_SHA256 = b"12345678901234567890123456789012"  # 32 octets
_SEED_SHA512 = b"1234567890123456789012345678901234567890123456789012345678901234"  # 64 octets

# Secret base32 exact cite par l'enonce/la RFC pour la graine SHA1.
_SECRET_SHA1_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

# (timestamp, code SHA1 8 chiffres, code SHA256, code SHA512) - table B.
_RFC_VECTORS = [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]


def _b32(seed: bytes) -> str:
    return base64.b32encode(seed).decode("ascii")


class RfcTestVectorsTestCase(unittest.TestCase):
    def test_the_documented_base32_secret_matches_the_rfc_seed(self):
        # Ancre le secret base32 fixe de l'enonce a la graine ASCII de la RFC.
        self.assertEqual(_b32(_SEED_SHA1), _SECRET_SHA1_B32)

    def test_sha1_eight_digit_codes_match_the_rfc_appendix_b(self):
        for timestamp, expected8, _s256, _s512 in _RFC_VECTORS:
            with self.subTest(timestamp=timestamp):
                code = totp.generate_totp(
                    _SECRET_SHA1_B32, timestamp, digits=8, algorithm="sha1",
                )
                self.assertEqual(code, expected8)

    def test_sha1_six_digit_codes_are_the_last_six_digits_of_the_rfc_vector(self):
        # Le mode par defaut de l'app (6 chiffres, SHA1) : un code a 6
        # chiffres est la troncature aux 6 derniers chiffres du code a 8.
        for timestamp, expected8, _s256, _s512 in _RFC_VECTORS:
            with self.subTest(timestamp=timestamp):
                code = totp.generate_totp(_SECRET_SHA1_B32, timestamp)  # defaut: 6 chiffres, sha1
                self.assertEqual(len(code), 6)
                self.assertEqual(code, expected8[-6:])

    def test_sha256_eight_digit_codes_match_the_rfc_appendix_b(self):
        secret = _b32(_SEED_SHA256)
        for timestamp, _s1, expected8, _s512 in _RFC_VECTORS:
            with self.subTest(timestamp=timestamp):
                code = totp.generate_totp(secret, timestamp, digits=8, algorithm="sha256")
                self.assertEqual(code, expected8)

    def test_sha512_eight_digit_codes_match_the_rfc_appendix_b(self):
        secret = _b32(_SEED_SHA512)
        for timestamp, _s1, _s256, expected8 in _RFC_VECTORS:
            with self.subTest(timestamp=timestamp):
                code = totp.generate_totp(secret, timestamp, digits=8, algorithm="sha512")
                self.assertEqual(code, expected8)


class NormalizationAndValidationTestCase(unittest.TestCase):
    def test_normalize_is_insensitive_to_spaces_and_case(self):
        # Les sites presentent souvent le secret par blocs de 4 en minuscules.
        raw = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq"
        self.assertEqual(totp.normalize_secret(raw), _SECRET_SHA1_B32)

    def test_a_secret_with_spaces_and_lowercase_produces_the_same_code(self):
        spaced = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq"
        self.assertEqual(
            totp.generate_totp(spaced, 59, digits=8),
            totp.generate_totp(_SECRET_SHA1_B32, 59, digits=8),
        )

    def test_padding_is_tolerated(self):
        self.assertTrue(totp.is_valid_secret("JBSWY3DPEHPK3PXP"))
        # Meme secret avec padding explicite.
        self.assertTrue(totp.is_valid_secret("JBSWY3DPEHPK3PX==="))

    def test_valid_and_invalid_secrets(self):
        self.assertTrue(totp.is_valid_secret("JBSWY3DPEHPK3PXP"))
        self.assertFalse(totp.is_valid_secret(""))
        self.assertFalse(totp.is_valid_secret("   "))
        self.assertFalse(totp.is_valid_secret("1234567890"))  # 0,1,8,9 hors alphabet base32
        self.assertFalse(totp.is_valid_secret("not base32!"))

    def test_generate_raises_on_an_invalid_secret(self):
        with self.assertRaises(ValueError):
            totp.generate_totp("pas-du-base32-valide!")

    def test_generate_raises_on_an_empty_secret(self):
        with self.assertRaises(ValueError):
            totp.generate_totp("")

    def test_generate_raises_on_an_unknown_algorithm(self):
        with self.assertRaises(ValueError):
            totp.generate_totp(_SECRET_SHA1_B32, 59, algorithm="md5")


class SecondsRemainingTestCase(unittest.TestCase):
    def test_seconds_remaining_within_a_30s_window(self):
        # Au tout debut d'une fenetre (timestamp multiple de 30) il reste 30 s.
        self.assertEqual(totp.seconds_remaining(0), 30)
        self.assertEqual(totp.seconds_remaining(1), 29)
        self.assertEqual(totp.seconds_remaining(29), 1)
        self.assertEqual(totp.seconds_remaining(30), 30)
        self.assertEqual(totp.seconds_remaining(59), 1)

    def test_seconds_remaining_stays_in_range(self):
        for t in range(0, 120):
            r = totp.seconds_remaining(t)
            self.assertTrue(1 <= r <= 30)


if __name__ == "__main__":
    unittest.main()
