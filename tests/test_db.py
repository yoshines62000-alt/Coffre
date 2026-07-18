"""Tests pour db.py : schema SQLite, CRUD des entrees et des metadonnees
du coffre - tout est stocke/relu comme des blobs opaques ici, la
cryptographie elle-meme est testee separement dans test_crypto.py."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db import Database


class VaultMetaTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.db = Database(self.tmp / "test.sqlite")
        self.addCleanup(self.db.close)

    def test_is_initialized_is_false_before_any_vault_meta_is_set(self):
        self.assertFalse(self.db.is_initialized())

    def test_is_initialized_is_true_after_set_vault_meta(self):
        self.db.set_vault_meta(b"salt", b"nonce", b"ciphertext")
        self.assertTrue(self.db.is_initialized())

    def test_get_vault_meta_returns_the_stored_blobs_unchanged(self):
        self.db.set_vault_meta(b"un-sel-de-16-octets", b"un-nonce-12o", b"un-ciphertext-quelconque")
        meta = self.db.get_vault_meta()
        self.assertEqual(meta["kdf_salt"], b"un-sel-de-16-octets")
        self.assertEqual(meta["verifier_nonce"], b"un-nonce-12o")
        self.assertEqual(meta["verifier_ciphertext"], b"un-ciphertext-quelconque")

    def test_get_vault_meta_returns_none_when_not_initialized(self):
        self.assertIsNone(self.db.get_vault_meta())

    def test_set_vault_meta_a_second_time_replaces_the_previous_values(self):
        # Utilise lors d'un changement de mot de passe maitre : le nouveau
        # sel/verificateur doit entierement remplacer l'ancien, pas
        # s'accumuler dans une seconde ligne.
        self.db.set_vault_meta(b"ancien-sel", b"ancien-nonce", b"ancien-ciphertext")
        self.db.set_vault_meta(b"nouveau-sel", b"nouveau-nonce", b"nouveau-ciphertext")
        meta = self.db.get_vault_meta()
        self.assertEqual(meta["kdf_salt"], b"nouveau-sel")
        row_count = self.db.conn.execute("SELECT COUNT(*) FROM vault_meta").fetchone()[0]
        self.assertEqual(row_count, 1)


class EntriesTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.db = Database(self.tmp / "test.sqlite")
        self.addCleanup(self.db.close)

    def test_add_entry_returns_an_id_and_stores_the_blobs_unchanged(self):
        entry_id = self.db.add_entry(b"un-nonce", b"un-ciphertext")
        entry = self.db.get_entry(entry_id)
        self.assertEqual(entry["nonce"], b"un-nonce")
        self.assertEqual(entry["ciphertext"], b"un-ciphertext")

    def test_get_entry_returns_none_for_an_unknown_id(self):
        self.assertIsNone(self.db.get_entry(999))

    def test_list_entries_returns_all_entries_in_insertion_order(self):
        id1 = self.db.add_entry(b"nonce1", b"cipher1")
        id2 = self.db.add_entry(b"nonce2", b"cipher2")
        entries = self.db.list_entries()
        self.assertEqual([e["id"] for e in entries], [id1, id2])

    def test_update_entry_replaces_nonce_and_ciphertext(self):
        entry_id = self.db.add_entry(b"vieux-nonce", b"vieux-cipher")
        self.db.update_entry(entry_id, b"nouveau-nonce", b"nouveau-cipher")
        entry = self.db.get_entry(entry_id)
        self.assertEqual(entry["nonce"], b"nouveau-nonce")
        self.assertEqual(entry["ciphertext"], b"nouveau-cipher")

    def test_delete_entry_removes_it(self):
        entry_id = self.db.add_entry(b"nonce", b"cipher")
        self.db.delete_entry(entry_id)
        self.assertIsNone(self.db.get_entry(entry_id))
        self.assertEqual(self.db.list_entries(), [])

    def test_replace_all_entries_and_meta_updates_every_entry_preserving_ids(self):
        id1 = self.db.add_entry(b"nonce1", b"cipher1")
        id2 = self.db.add_entry(b"nonce2", b"cipher2")
        self.db.replace_all_entries_and_meta(
            [(id1, b"nouveau-nonce1", b"nouveau-cipher1"), (id2, b"nouveau-nonce2", b"nouveau-cipher2")],
            b"nouveau-sel", b"nouveau-nonce-meta", b"nouveau-cipher-meta",
        )
        entries = {e["id"]: e for e in self.db.list_entries()}
        self.assertEqual(entries[id1]["ciphertext"], b"nouveau-cipher1")
        self.assertEqual(entries[id2]["ciphertext"], b"nouveau-cipher2")

    def test_replace_all_entries_and_meta_also_updates_vault_meta_atomically(self):
        self.db.set_vault_meta(b"ancien-sel", b"ancien-nonce", b"ancien-cipher")
        entry_id = self.db.add_entry(b"nonce", b"cipher")
        self.db.replace_all_entries_and_meta(
            [(entry_id, b"nouveau-nonce", b"nouveau-cipher")],
            b"nouveau-sel", b"nouveau-nonce-meta", b"nouveau-cipher-meta",
        )
        meta = self.db.get_vault_meta()
        self.assertEqual(meta["kdf_salt"], b"nouveau-sel")
        self.assertEqual(meta["verifier_nonce"], b"nouveau-nonce-meta")
        self.assertEqual(self.db.get_entry(entry_id)["ciphertext"], b"nouveau-cipher")

    def test_data_persists_after_closing_and_reopening_the_database_file(self):
        entry_id = self.db.add_entry(b"nonce", b"cipher-persistant")
        self.db.set_vault_meta(b"sel-persistant", b"nonce-meta", b"cipher-meta")
        path = self.db.path
        self.db.close()

        reopened = Database(path)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.get_entry(entry_id)["ciphertext"], b"cipher-persistant")
        self.assertEqual(reopened.get_vault_meta()["kdf_salt"], b"sel-persistant")


if __name__ == "__main__":
    unittest.main()
