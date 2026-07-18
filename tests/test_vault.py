"""Tests pour vault.py : logique metier du coffre (creation, deverrouillage,
verrouillage, CRUD des entrees, changement de mot de passe maitre,
generateur de mot de passe) - sur une vraie base SQLite temporaire et de
vraies operations cryptographiques (aucun mock de crypto.py)."""

import string
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vault import Vault, VaultError, generate_password, password_strength


class VaultLifecycleTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.vault = Vault(self.tmp / "coffre.sqlite")
        self.addCleanup(self.vault.close)

    def test_a_new_vault_does_not_exist_before_creation(self):
        self.assertFalse(self.vault.exists())

    def test_create_marks_the_vault_as_existing_and_unlocked(self):
        self.vault.create("mot-de-passe-maitre")
        self.assertTrue(self.vault.exists())
        self.assertTrue(self.vault.is_unlocked)

    def test_create_twice_raises_vault_error(self):
        self.vault.create("mot-de-passe-maitre")
        with self.assertRaises(VaultError):
            self.vault.create("autre-mot-de-passe")

    def test_create_rejects_an_empty_master_password(self):
        with self.assertRaises(VaultError):
            self.vault.create("")

    def test_unlock_with_the_correct_password_succeeds(self):
        self.vault.create("mot-de-passe-maitre")
        self.vault.lock()
        self.assertTrue(self.vault.unlock("mot-de-passe-maitre"))
        self.assertTrue(self.vault.is_unlocked)

    def test_unlock_with_the_wrong_password_returns_false_without_raising(self):
        self.vault.create("mot-de-passe-maitre")
        self.vault.lock()
        self.assertFalse(self.vault.unlock("mauvais-mot-de-passe"))
        self.assertFalse(self.vault.is_unlocked)

    def test_unlock_before_any_vault_was_created_raises_vault_error(self):
        with self.assertRaises(VaultError):
            self.vault.unlock("peu-importe")

    def test_lock_prevents_further_access_to_entries(self):
        self.vault.create("mot-de-passe-maitre")
        self.vault.add_entry("Site X", password="secret")
        self.vault.lock()
        with self.assertRaises(VaultError):
            self.vault.list_entries()

    def test_reopening_the_database_file_and_unlocking_recovers_all_entries(self):
        self.vault.create("mot-de-passe-maitre")
        self.vault.add_entry("Site X", username="alice", password="secret123", url="https://x.example", notes="note")
        path = self.vault.db.path
        self.vault.close()

        reopened = Vault(path)
        self.addCleanup(reopened.close)
        self.assertTrue(reopened.unlock("mot-de-passe-maitre"))
        entries = reopened.list_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["title"], "Site X")
        self.assertEqual(entries[0]["username"], "alice")
        self.assertEqual(entries[0]["password"], "secret123")
        self.assertEqual(entries[0]["url"], "https://x.example")
        self.assertEqual(entries[0]["notes"], "note")

    def test_a_single_corrupted_entry_does_not_prevent_unlocking_the_rest_of_the_vault(self):
        # Trouve a l'audit : une seule entree alteree sur le disque (bit
        # rot, ecriture partielle, edition manuelle de la base) ne doit
        # jamais rendre TOUT le coffre inaccessible.
        self.vault.create("mot-de-passe-maitre")
        good_id = self.vault.add_entry("Site sain", password="secret")
        bad_id = self.vault.add_entry("Site corrompu", password="autre-secret")
        raw = self.vault.db.get_entry(bad_id)
        tampered = bytearray(raw["ciphertext"])
        tampered[0] ^= 0xFF
        self.vault.db.update_entry(bad_id, raw["nonce"], bytes(tampered))
        self.vault.lock()

        self.assertTrue(self.vault.unlock("mot-de-passe-maitre"))
        entries = self.vault.list_entries()
        self.assertEqual([e["id"] for e in entries], [good_id])
        self.assertEqual(self.vault.corrupted_entry_ids, [bad_id])

    def test_corrupted_entry_ids_is_empty_when_nothing_is_corrupted(self):
        self.vault.create("mot-de-passe-maitre")
        self.vault.add_entry("Site sain")
        self.vault.lock()
        self.vault.unlock("mot-de-passe-maitre")
        self.assertEqual(self.vault.corrupted_entry_ids, [])


class EntryCrudTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.vault = Vault(self.tmp / "coffre.sqlite")
        self.addCleanup(self.vault.close)
        self.vault.create("mot-de-passe-maitre")

    def test_add_entry_appears_in_list_entries(self):
        entry_id = self.vault.add_entry("Banque", username="bob", password="hunter2")
        entries = self.vault.list_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["id"], entry_id)
        self.assertEqual(entries[0]["password"], "hunter2")

    def test_add_entry_rejects_an_empty_title(self):
        with self.assertRaises(VaultError):
            self.vault.add_entry("   ")

    def test_get_entry_returns_none_for_an_unknown_id(self):
        self.assertIsNone(self.vault.get_entry(999))

    def test_update_entry_changes_only_the_specified_fields(self):
        entry_id = self.vault.add_entry("Site X", username="alice", password="ancien")
        self.vault.update_entry(entry_id, password="nouveau")
        entry = self.vault.get_entry(entry_id)
        self.assertEqual(entry["username"], "alice")
        self.assertEqual(entry["password"], "nouveau")

    def test_update_entry_on_an_unknown_id_raises_vault_error(self):
        with self.assertRaises(VaultError):
            self.vault.update_entry(999, password="x")

    def test_update_entry_rejects_clearing_the_title(self):
        entry_id = self.vault.add_entry("Site X")
        with self.assertRaises(VaultError):
            self.vault.update_entry(entry_id, title="   ")

    def test_delete_entry_removes_it_from_the_list(self):
        entry_id = self.vault.add_entry("A supprimer")
        self.vault.delete_entry(entry_id)
        self.assertIsNone(self.vault.get_entry(entry_id))
        self.assertEqual(self.vault.list_entries(), [])

    def test_entries_are_actually_encrypted_at_rest_in_the_database(self):
        self.vault.add_entry("Site secret", username="alice", password="MotDePasseTresSecret")
        raw_rows = self.vault.db.list_entries()
        self.assertEqual(len(raw_rows), 1)
        self.assertNotIn(b"MotDePasseTresSecret", raw_rows[0]["ciphertext"])
        self.assertNotIn(b"Site secret", raw_rows[0]["ciphertext"])

    def test_find_reused_passwords_groups_entries_sharing_the_same_password(self):
        self.vault.add_entry("Site A", password="partage123")
        self.vault.add_entry("Site B", password="partage123")
        self.vault.add_entry("Site C", password="unique456")
        groups = self.vault.find_reused_passwords()
        self.assertEqual(len(groups), 1)
        titles = sorted(e["title"] for e in groups[0])
        self.assertEqual(titles, ["Site A", "Site B"])

    def test_find_reused_passwords_returns_empty_when_all_passwords_are_distinct(self):
        self.vault.add_entry("Site A", password="a")
        self.vault.add_entry("Site B", password="b")
        self.assertEqual(self.vault.find_reused_passwords(), [])

    def test_find_reused_passwords_ignores_entries_with_no_password(self):
        self.vault.add_entry("Site A", password="")
        self.vault.add_entry("Site B", password="")
        self.assertEqual(self.vault.find_reused_passwords(), [])

    def test_find_reused_passwords_supports_more_than_two_entries_in_a_group(self):
        self.vault.add_entry("Site A", password="commun")
        self.vault.add_entry("Site B", password="commun")
        self.vault.add_entry("Site C", password="commun")
        groups = self.vault.find_reused_passwords()
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0]), 3)

    def test_find_reused_passwords_detects_multiple_independent_groups(self):
        self.vault.add_entry("Site A", password="groupe1")
        self.vault.add_entry("Site B", password="groupe1")
        self.vault.add_entry("Site C", password="groupe2")
        self.vault.add_entry("Site D", password="groupe2")
        groups = self.vault.find_reused_passwords()
        self.assertEqual(len(groups), 2)


class ChangeMasterPasswordTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.vault = Vault(self.tmp / "coffre.sqlite")
        self.addCleanup(self.vault.close)
        self.vault.create("ancien-mot-de-passe")
        self.entry_id = self.vault.add_entry("Site X", username="alice", password="secret123")

    def test_change_master_password_rejects_an_incorrect_current_password(self):
        with self.assertRaises(VaultError):
            self.vault.change_master_password("mauvais-mot-de-passe", "nouveau-mot-de-passe")

    def test_change_master_password_rejects_an_empty_new_password(self):
        with self.assertRaises(VaultError):
            self.vault.change_master_password("ancien-mot-de-passe", "")

    def test_all_entries_survive_a_master_password_change_intact(self):
        self.vault.change_master_password("ancien-mot-de-passe", "nouveau-mot-de-passe")
        entries = self.vault.list_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["title"], "Site X")
        self.assertEqual(entries[0]["password"], "secret123")

    def test_the_old_master_password_no_longer_unlocks_the_vault(self):
        self.vault.change_master_password("ancien-mot-de-passe", "nouveau-mot-de-passe")
        self.vault.lock()
        self.assertFalse(self.vault.unlock("ancien-mot-de-passe"))

    def test_the_new_master_password_unlocks_the_vault_after_reopening(self):
        self.vault.change_master_password("ancien-mot-de-passe", "nouveau-mot-de-passe")
        path = self.vault.db.path
        self.vault.close()

        reopened = Vault(path)
        self.addCleanup(reopened.close)
        self.assertTrue(reopened.unlock("nouveau-mot-de-passe"))
        entries = reopened.list_entries()
        self.assertEqual(entries[0]["password"], "secret123")

    def test_a_storage_failure_during_change_master_password_leaves_the_old_password_working(self):
        # Simule un echec disque/DB au moment precis ou change_master_password
        # ecrit le resultat (replace_all_entries_and_meta) : le mot de passe
        # ACTUEL doit continuer a fonctionner apres l'echec - jamais d'etat
        # ou ni l'ancien ni le nouveau mot de passe ne marchent.
        from unittest.mock import patch

        with patch.object(self.vault.db, "replace_all_entries_and_meta", side_effect=RuntimeError("disque plein")):
            with self.assertRaises(RuntimeError):
                self.vault.change_master_password("ancien-mot-de-passe", "nouveau-mot-de-passe")

        self.vault.lock()
        self.assertTrue(self.vault.unlock("ancien-mot-de-passe"))
        entries = self.vault.list_entries()
        self.assertEqual(entries[0]["password"], "secret123")


class PasswordStrengthTestCase(unittest.TestCase):
    def test_empty_password_is_very_weak(self):
        result = password_strength("")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["bits"], 0.0)

    def test_short_lowercase_only_password_is_weak(self):
        result = password_strength("abc")
        self.assertLessEqual(result["score"], 1)

    def test_long_single_alphabet_password_scores_lower_than_same_length_mixed(self):
        single_alphabet = password_strength("aaaaaaaaaa")
        mixed = password_strength("aB3!aB3!aB")
        self.assertLess(single_alphabet["bits"], mixed["bits"])

    def test_using_more_character_categories_increases_the_score(self):
        lower_only = password_strength("abcdefghij")
        lower_upper_digits_symbols = password_strength("aB3!cD5@fG")
        self.assertGreater(lower_upper_digits_symbols["score"], lower_only["score"])

    def test_long_random_looking_password_is_scored_very_strong(self):
        result = password_strength("xK9$mQ2#pL7@vN4!")
        self.assertEqual(result["score"], 4)
        self.assertEqual(result["label"], "Tres fort")

    def test_a_generated_password_is_never_rated_very_weak(self):
        pw = generate_password(length=20)
        result = password_strength(pw)
        self.assertGreaterEqual(result["score"], 2)


class GeneratePasswordTestCase(unittest.TestCase):
    def test_generated_password_has_the_requested_length(self):
        self.assertEqual(len(generate_password(length=24)), 24)

    def test_generated_passwords_are_not_all_identical(self):
        passwords = {generate_password() for _ in range(20)}
        self.assertEqual(len(passwords), 20)

    def test_disabling_all_character_types_raises_vault_error(self):
        with self.assertRaises(VaultError):
            generate_password(use_upper=False, use_lower=False, use_digits=False, use_symbols=False)

    def test_digits_only_password_contains_only_digits(self):
        password = generate_password(length=12, use_upper=False, use_lower=False, use_digits=True, use_symbols=False)
        self.assertTrue(all(c in string.digits for c in password))

    def test_avoid_ambiguous_excludes_commonly_confused_characters(self):
        password = generate_password(length=200, avoid_ambiguous=True, use_symbols=False)
        for ambiguous in "0O1lI":
            self.assertNotIn(ambiguous, password)

    def test_password_includes_at_least_one_character_from_every_enabled_category(self):
        password = generate_password(length=30, use_upper=True, use_lower=True, use_digits=True, use_symbols=True)
        self.assertTrue(any(c in string.ascii_uppercase for c in password))
        self.assertTrue(any(c in string.ascii_lowercase for c in password))
        self.assertTrue(any(c in string.digits for c in password))

    def test_length_shorter_than_the_number_of_enabled_categories_raises_vault_error(self):
        with self.assertRaises(VaultError):
            generate_password(length=1, use_upper=True, use_lower=True, use_digits=True, use_symbols=True)


if __name__ == "__main__":
    unittest.main()
