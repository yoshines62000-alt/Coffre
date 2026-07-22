"""Tests pour db.py : schema SQLite, CRUD des entrees et des metadonnees
du coffre - tout est stocke/relu comme des blobs opaques ici, la
cryptographie elle-meme est testee separement dans test_crypto.py."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import db
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

    def test_set_vault_meta_without_kdf_params_defaults_to_the_legacy_values(self):
        # Compatibilite des appelants existants (dont ces tests eux-memes)
        # qui n'ont jamais precise kdf_n/kdf_r/kdf_p (audit A2).
        self.db.set_vault_meta(b"sel", b"nonce", b"ciphertext")
        meta = self.db.get_vault_meta()
        self.assertEqual(meta["kdf_n"], 65536)
        self.assertEqual(meta["kdf_r"], 8)
        self.assertEqual(meta["kdf_p"], 1)

    def test_set_vault_meta_stores_explicit_kdf_params(self):
        self.db.set_vault_meta(b"sel", b"nonce", b"ciphertext", kdf_n=131072, kdf_r=8, kdf_p=1)
        meta = self.db.get_vault_meta()
        self.assertEqual(meta["kdf_n"], 131072)


class LegacyKdfColumnsMigrationTestCase(unittest.TestCase):
    """Audit A2 : un fichier .sqlite cree par une version de Coffre
    anterieure a ce correctif n'a pas encore les colonnes
    kdf_n/kdf_r/kdf_p sur `vault_meta`. Database doit les ajouter toute
    seule a l'ouverture, sans toucher aux donnees chiffrees existantes, et
    de facon idempotente (l'ouverture se reproduit a chaque lancement de
    l'application, pas seulement la premiere fois apres la mise a jour)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.path = self.tmp / "legacy.sqlite"
        # Reproduit l'ancien schema (avant ce correctif) directement en
        # sqlite3 brut, sans passer par Database - pour ne pas presupposer
        # que le code de migration fonctionne deja.
        import sqlite3

        conn = sqlite3.connect(str(self.path))
        conn.executescript("""
        CREATE TABLE vault_meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            kdf_salt BLOB NOT NULL,
            verifier_nonce BLOB NOT NULL,
            verifier_ciphertext BLOB NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """)
        conn.execute(
            "INSERT INTO vault_meta (id, kdf_salt, verifier_nonce, verifier_ciphertext, created_at) "
            "VALUES (1, ?, ?, ?, ?)",
            (b"ancien-sel", b"ancien-nonce", b"ancien-ciphertext", "2026-01-01T00:00:00+00:00"),
        )
        conn.execute(
            "INSERT INTO entries (nonce, ciphertext, created_at, updated_at) VALUES (?, ?, ?, ?)",
            (b"nonce-entree", b"cipher-entree", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
        )
        conn.commit()
        conn.close()

    def test_opening_a_legacy_database_adds_the_kdf_columns_with_legacy_defaults(self):
        db = Database(self.path)
        self.addCleanup(db.close)
        meta = db.get_vault_meta()
        self.assertEqual(meta["kdf_n"], 65536)
        self.assertEqual(meta["kdf_r"], 8)
        self.assertEqual(meta["kdf_p"], 1)

    def test_opening_a_legacy_database_does_not_alter_the_existing_encrypted_blobs(self):
        db = Database(self.path)
        self.addCleanup(db.close)
        meta = db.get_vault_meta()
        self.assertEqual(meta["kdf_salt"], b"ancien-sel")
        self.assertEqual(meta["verifier_ciphertext"], b"ancien-ciphertext")
        entries = db.list_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["ciphertext"], b"cipher-entree")

    def test_reopening_a_migrated_database_a_second_time_does_not_raise(self):
        Database(self.path).close()
        db_again = Database(self.path)  # ne doit pas lever "duplicate column name"
        self.addCleanup(db_again.close)
        meta = db_again.get_vault_meta()
        self.assertEqual(meta["kdf_n"], 65536)


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

    def test_replace_all_entries_and_meta_stores_explicit_kdf_params(self):
        # Utilise par Vault._migrate_kdf_params (audit A2) pour mettre a
        # niveau les parametres scrypt d'un coffre existant.
        entry_id = self.db.add_entry(b"nonce", b"cipher")
        self.db.replace_all_entries_and_meta(
            [(entry_id, b"n2", b"c2")], b"sel", b"nonce-meta", b"cipher-meta",
            kdf_n=131072, kdf_r=8, kdf_p=1,
        )
        meta = self.db.get_vault_meta()
        self.assertEqual(meta["kdf_n"], 131072)

    def test_replace_all_entries_and_meta_rolls_back_entirely_on_a_partial_failure(self):
        # Le pire scenario possible pour un changement de mot de passe
        # maitre : une partie des entrees rechiffrees, mais pas les
        # metadonnees (ou l'inverse) - le coffre deviendrait alors
        # irrecuperable avec N'IMPORTE QUEL mot de passe. Force une
        # exception APRES la premiere entree traitee (deuxieme tuple
        # volontairement malforme) pour verifier que le rollback annule
        # bien TOUT, y compris la premiere entree deja "reussie".
        self.db.set_vault_meta(b"ancien-sel", b"ancien-nonce", b"ancien-cipher")
        entry_id_1 = self.db.add_entry(b"nonce1", b"cipher1")
        entry_id_2 = self.db.add_entry(b"nonce2", b"cipher2")

        with self.assertRaises(Exception):
            self.db.replace_all_entries_and_meta(
                [
                    (entry_id_1, b"nouveau-nonce1", b"nouveau-cipher1"),
                    ("id-invalide-pas-un-entier",),  # provoque une erreur au deballage du tuple
                ],
                b"nouveau-sel", b"nouveau-nonce-meta", b"nouveau-cipher-meta",
            )

        # Rien n'a change : ni la premiere entree "reussie", ni la seconde,
        # ni les metadonnees du coffre.
        self.assertEqual(self.db.get_entry(entry_id_1)["ciphertext"], b"cipher1")
        self.assertEqual(self.db.get_entry(entry_id_2)["ciphertext"], b"cipher2")
        meta = self.db.get_vault_meta()
        self.assertEqual(meta["kdf_salt"], b"ancien-sel")
        self.assertEqual(meta["verifier_nonce"], b"ancien-nonce")

    def test_journal_mode_is_wal(self):
        # Le mode WAL est cense etre actif des l'ouverture (optimisation
        # trouvee a l'audit) - verifie que ce n'est pas juste une PRAGMA
        # ignoree silencieusement (SQLite peut refuser WAL dans de rares
        # configurations, ex: systeme de fichiers reseau).
        mode = self.db.conn.execute("PRAGMA journal_mode").fetchone()[0]
        self.assertEqual(mode.lower(), "wal")

    def test_backup_to_produces_a_complete_and_coherent_copy_in_wal_mode(self):
        # Verifie specifiquement qu'activer WAL n'a pas casse backup_to :
        # plusieurs entrees ajoutees SANS fermer/rouvrir la connexion (donc
        # potentiellement encore dans le fichier -wal, pas encore dans le
        # fichier principal) doivent quand meme toutes apparaitre dans la
        # copie - l'API sqlite3.Connection.backup() est documentee comme
        # gerant nativement WAL, verifie-le empiriquement plutot que de
        # simplement s'y fier.
        self.db.set_vault_meta(b"sel-wal", b"nonce-meta", b"cipher-meta")
        entry_ids = [self.db.add_entry(f"nonce{i}".encode(), f"cipher{i}".encode()) for i in range(5)]
        dest = self.tmp / "copie-wal.sqlite"
        self.db.backup_to(dest)

        copy = Database(dest)
        self.addCleanup(copy.close)
        self.assertEqual(copy.get_vault_meta()["kdf_salt"], b"sel-wal")
        for i, entry_id in enumerate(entry_ids):
            self.assertEqual(copy.get_entry(entry_id)["ciphertext"], f"cipher{i}".encode())

    def test_backup_to_copies_meta_and_entries_unchanged(self):
        self.db.set_vault_meta(b"sel", b"nonce-meta", b"cipher-meta")
        entry_id = self.db.add_entry(b"nonce", b"cipher")
        dest = self.tmp / "copie.sqlite"
        self.db.backup_to(dest)

        copy = Database(dest)
        self.addCleanup(copy.close)
        self.assertEqual(copy.get_vault_meta()["kdf_salt"], b"sel")
        self.assertEqual(copy.get_entry(entry_id)["ciphertext"], b"cipher")

    def test_the_backup_is_independent_of_later_changes_to_the_original(self):
        # Verifie que backup_to produit une vraie copie figee au moment de
        # la sauvegarde, pas une vue partagee sur le meme fichier.
        entry_id = self.db.add_entry(b"nonce", b"cipher-original")
        dest = self.tmp / "copie.sqlite"
        self.db.backup_to(dest)
        self.db.update_entry(entry_id, b"nonce2", b"cipher-modifie")

        copy = Database(dest)
        self.addCleanup(copy.close)
        self.assertEqual(copy.get_entry(entry_id)["ciphertext"], b"cipher-original")

    def test_backup_to_the_live_database_path_raises_value_error(self):
        with self.assertRaises(ValueError):
            self.db.backup_to(self.db.path)

    def test_backup_to_the_live_path_spelled_differently_still_raises(self):
        # Le garde-fou compare les chemins RESOLUS : un chemin equivalent
        # mais ecrit autrement (composant "..") ne doit pas permettre a
        # sqlite d'ecraser la base active.
        alias = self.tmp / ".." / self.tmp.name / "test.sqlite"
        with self.assertRaises(ValueError):
            self.db.backup_to(alias)

    def test_data_persists_after_closing_and_reopening_the_database_file(self):
        entry_id = self.db.add_entry(b"nonce", b"cipher-persistant")
        self.db.set_vault_meta(b"sel-persistant", b"nonce-meta", b"cipher-meta")
        path = self.db.path
        self.db.close()

        reopened = Database(path)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.get_entry(entry_id)["ciphertext"], b"cipher-persistant")
        self.assertEqual(reopened.get_vault_meta()["kdf_salt"], b"sel-persistant")


class NetworkPathDetectionTestCase(unittest.TestCase):
    """Audit B2 : le mode WAL de SQLite est documente par SQLite lui-meme
    comme peu fiable sur certains systemes de fichiers reseau - db._is_
    network_path() detecte ce cas pour que Database.__init__ desactive WAL
    en consequence (voir WalDisabledOnNetworkPathTestCase plus bas)."""

    def test_detects_a_direct_unc_path(self):
        self.assertTrue(db._is_network_path(Path(r"\\serveur\partage\coffre.sqlite")))

    def test_detects_an_extended_length_unc_path(self):
        self.assertTrue(db._is_network_path(Path(r"\\?\UNC\serveur\partage\coffre.sqlite")))

    def test_does_not_flag_an_extended_length_local_path(self):
        # Le prefixe \\?\ (chemin "a longueur etendue", pour depasser
        # MAX_PATH) commence lui aussi par un double antislash, mais
        # \\?\C:\... reste un disque local - seul \\?\UNC\... designe un
        # partage reseau.
        self.assertFalse(db._is_network_path(Path(r"\\?\C:\Users\test\coffre.sqlite")))

    def test_does_not_flag_an_ordinary_local_drive_letter_path(self):
        self.assertFalse(db._is_network_path(Path(r"C:\Users\test\coffre.sqlite")))

    def test_does_not_flag_an_ordinary_local_temp_path(self):
        tmp = Path(tempfile.mkdtemp())
        self.assertFalse(db._is_network_path(tmp / "coffre.sqlite"))


class WalDisabledOnNetworkPathTestCase(unittest.TestCase):
    """Audit B2 : sur un chemin detecte comme reseau (profil itinerant
    d'entreprise, ou %APPDATA% est un partage reseau), Database doit
    renoncer au mode WAL plutot que de risquer la corruption documentee
    par SQLite lui-meme sur ce type de systeme de fichiers."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_wal_is_disabled_when_the_path_is_detected_as_a_network_path(self):
        with patch.object(db, "_is_network_path", return_value=True):
            database = Database(self.tmp / "reseau.sqlite")
        self.addCleanup(database.close)
        mode = database.conn.execute("PRAGMA journal_mode").fetchone()[0]
        self.assertNotEqual(mode.lower(), "wal")
        self.assertTrue(database.is_network_storage)

    def test_wal_stays_enabled_for_an_ordinary_local_path(self):
        # Non-regression de B1 : le chemin normal (immense majorite des
        # utilisateurs) doit continuer de beneficier de WAL.
        database = Database(self.tmp / "local.sqlite")
        self.addCleanup(database.close)
        self.assertFalse(database.is_network_storage)
        mode = database.conn.execute("PRAGMA journal_mode").fetchone()[0]
        self.assertEqual(mode.lower(), "wal")

    def test_busy_timeout_stays_active_even_when_wal_is_disabled(self):
        # busy_timeout protege contre un SQLITE_BUSY immediat (ex:
        # backup_to qui ouvre une seconde connexion) independamment du
        # mode journal actif.
        with patch.object(db, "_is_network_path", return_value=True):
            database = Database(self.tmp / "reseau2.sqlite")
        self.addCleanup(database.close)
        timeout = database.conn.execute("PRAGMA busy_timeout").fetchone()[0]
        self.assertEqual(timeout, 5000)

    def test_the_database_still_works_normally_with_wal_disabled(self):
        # Le repli sur le mode journal par defaut ne doit rien casser du
        # cote fonctionnel (CRUD, sauvegarde) - juste desactiver WAL.
        with patch.object(db, "_is_network_path", return_value=True):
            database = Database(self.tmp / "reseau3.sqlite")
        self.addCleanup(database.close)
        database.set_vault_meta(b"sel", b"nonce", b"cipher")
        entry_id = database.add_entry(b"nonce-entree", b"cipher-entree")
        self.assertEqual(database.get_entry(entry_id)["ciphertext"], b"cipher-entree")
        dest = self.tmp / "reseau3-copie.sqlite"
        database.backup_to(dest)
        copy = Database(dest)
        self.addCleanup(copy.close)
        self.assertEqual(copy.get_entry(entry_id)["ciphertext"], b"cipher-entree")


if __name__ == "__main__":
    unittest.main()
