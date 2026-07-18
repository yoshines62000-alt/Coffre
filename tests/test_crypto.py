"""Tests pour crypto.py : derivation de cle et chiffrement authentifie.

Ces tests sont la ligne de defense la plus critique de tout le projet -
un bug ici (nonce reutilise, mauvaise detection d'alteration, derivation
non deterministe) compromettrait la confidentialite de TOUTES les
donnees du coffre, silencieusement."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import crypto


class DeriveKeyTestCase(unittest.TestCase):
    def test_same_password_and_salt_produce_the_same_key(self):
        salt = crypto.generate_salt()
        key1 = crypto.derive_key("mot-de-passe-maitre", salt)
        key2 = crypto.derive_key("mot-de-passe-maitre", salt)
        self.assertEqual(key1, key2)

    def test_different_passwords_produce_different_keys(self):
        salt = crypto.generate_salt()
        key1 = crypto.derive_key("mot-de-passe-maitre", salt)
        key2 = crypto.derive_key("autre-mot-de-passe", salt)
        self.assertNotEqual(key1, key2)

    def test_different_salts_produce_different_keys_for_the_same_password(self):
        key1 = crypto.derive_key("mot-de-passe-maitre", crypto.generate_salt())
        key2 = crypto.derive_key("mot-de-passe-maitre", crypto.generate_salt())
        self.assertNotEqual(key1, key2)

    def test_derived_key_has_the_expected_length_for_aes_256(self):
        key = crypto.derive_key("mot-de-passe-maitre", crypto.generate_salt())
        self.assertEqual(len(key), crypto.KEY_SIZE)

    def test_generate_salt_produces_different_values_each_time(self):
        salts = {crypto.generate_salt() for _ in range(20)}
        self.assertEqual(len(salts), 20)

    def test_generate_salt_has_the_expected_length(self):
        self.assertEqual(len(crypto.generate_salt()), crypto.SALT_SIZE)

    def test_derive_key_handles_non_ascii_passwords(self):
        # Un mot de passe maitre contenant des accents ou emojis doit se
        # comporter exactement comme n'importe quel autre - aucune
        # exception d'encodage, aucune troncature silencieuse.
        salt = crypto.generate_salt()
        key1 = crypto.derive_key("Éléphant🔒Bleu", salt)
        key2 = crypto.derive_key("Éléphant🔒Bleu", salt)
        self.assertEqual(key1, key2)


class EncryptDecryptTestCase(unittest.TestCase):
    def setUp(self):
        self.key = crypto.derive_key("mot-de-passe-maitre", crypto.generate_salt())

    def test_decrypt_recovers_the_exact_original_plaintext(self):
        plaintext = b"donnees secretes du coffre"
        nonce, ciphertext = crypto.encrypt(self.key, plaintext)
        self.assertEqual(crypto.decrypt(self.key, nonce, ciphertext), plaintext)

    def test_ciphertext_never_contains_the_plaintext_in_clear(self):
        plaintext = b"MonMotDePasseSuperSecret123"
        nonce, ciphertext = crypto.encrypt(self.key, plaintext)
        self.assertNotIn(plaintext, ciphertext)

    def test_encrypting_the_same_plaintext_twice_produces_different_ciphertexts(self):
        # Consequence directe d'un nonce aleatoire different a chaque appel -
        # une propriete de securite importante (deux mots de passe identiques
        # stockes dans le coffre ne doivent pas etre reconnaissables entre
        # eux par leur seul ciphertext).
        plaintext = b"meme contenu"
        nonce1, ciphertext1 = crypto.encrypt(self.key, plaintext)
        nonce2, ciphertext2 = crypto.encrypt(self.key, plaintext)
        self.assertNotEqual(nonce1, nonce2)
        self.assertNotEqual(ciphertext1, ciphertext2)

    def test_nonce_has_the_expected_length(self):
        nonce, _ = crypto.encrypt(self.key, b"x")
        self.assertEqual(len(nonce), crypto.NONCE_SIZE)

    def test_decrypting_with_the_wrong_key_raises_decryption_error(self):
        nonce, ciphertext = crypto.encrypt(self.key, b"donnees secretes")
        wrong_key = crypto.derive_key("mauvais-mot-de-passe", crypto.generate_salt())
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt(wrong_key, nonce, ciphertext)

    def test_tampering_with_a_single_byte_of_ciphertext_is_detected(self):
        nonce, ciphertext = crypto.encrypt(self.key, b"donnees secretes du coffre")
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF  # inverse tous les bits du premier octet
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt(self.key, nonce, bytes(tampered))

    def test_tampering_with_the_nonce_is_detected(self):
        nonce, ciphertext = crypto.encrypt(self.key, b"donnees secretes du coffre")
        tampered_nonce = bytearray(nonce)
        tampered_nonce[0] ^= 0xFF
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt(self.key, bytes(tampered_nonce), ciphertext)

    def test_truncated_ciphertext_is_detected_rather_than_silently_accepted(self):
        nonce, ciphertext = crypto.encrypt(self.key, b"donnees secretes du coffre")
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt(self.key, nonce, ciphertext[:-1])

    def test_a_malformed_nonce_length_raises_decryption_error_not_a_bare_value_error(self):
        # Regression trouvee a l'audit : AESGCM.decrypt leve un ValueError
        # brut (pas InvalidTag) pour un nonce de mauvaise longueur - un
        # scenario realiste pour une entree corrompue par edition manuelle
        # de la base. Avant la correction, ce ValueError remontait tel quel
        # hors de decrypt(), non catche par Vault._decrypt_all_entries (qui
        # n'attrapait que crypto.DecryptionError), faisant planter unlock()
        # au lieu de traiter cette entree comme corrompue ordinaire.
        nonce, ciphertext = crypto.encrypt(self.key, b"donnees secretes")
        malformed_nonce = nonce[:-1]  # longueur invalide pour AES-GCM
        with self.assertRaises(crypto.DecryptionError):
            crypto.decrypt(self.key, malformed_nonce, ciphertext)

    def test_empty_plaintext_roundtrips_correctly(self):
        nonce, ciphertext = crypto.encrypt(self.key, b"")
        self.assertEqual(crypto.decrypt(self.key, nonce, ciphertext), b"")

    def test_large_plaintext_roundtrips_correctly(self):
        plaintext = b"x" * 1_000_000
        nonce, ciphertext = crypto.encrypt(self.key, plaintext)
        self.assertEqual(crypto.decrypt(self.key, nonce, ciphertext), plaintext)

    def test_unicode_plaintext_encoded_as_utf8_roundtrips_correctly(self):
        plaintext = "mot de passe avec accents : éàçùî et emoji 🔑".encode("utf-8")
        nonce, ciphertext = crypto.encrypt(self.key, plaintext)
        self.assertEqual(crypto.decrypt(self.key, nonce, ciphertext), plaintext)

    def test_nonces_stay_unique_across_a_large_number_of_encryptions_with_the_same_key(self):
        # Un seul nonce reutilise avec la meme cle romprait totalement la
        # confidentialite d'AES-GCM - un test comparant seulement 2 appels
        # (voir test_encrypting_the_same_plaintext_twice_produces_different_ciphertexts)
        # ne suffit pas a couvrir ce risque a l'echelle reelle d'un coffre
        # contenant des dizaines d'entrees, ni le cas d'un changement de mot
        # de passe maitre qui rechiffre toutes les entrees dans une boucle.
        nonces = {crypto.encrypt(self.key, f"entree {i}".encode())[0] for i in range(500)}
        self.assertEqual(len(nonces), 500)


if __name__ == "__main__":
    unittest.main()
