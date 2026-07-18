"""Couche donnees de Coffre (SQLite, sans dependance externe).

Ce module ne connait rien de la cryptographie : il stocke et relit des
blobs binaires opaques (sel, nonces, ciphertexts) tels quels, exactement
comme les autres projets separent la couche donnees de la logique metier.
Le dechiffrement/chiffrement est entierement la responsabilite de vault.py.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    """Enveloppe fine autour de sqlite3 : une connexion, un schema, des
    methodes CRUD explicites. Pas d'ORM."""

    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path))
        self.conn.row_factory = sqlite3.Row
        self._create_schema()

    def close(self) -> None:
        self.conn.close()

    def _create_schema(self) -> None:
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS vault_meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            kdf_salt BLOB NOT NULL,
            verifier_nonce BLOB NOT NULL,
            verifier_ciphertext BLOB NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """)
        self.conn.commit()

    # -- metadonnees du coffre (mot de passe maitre) ---------------------------

    def is_initialized(self) -> bool:
        """Un coffre existe deja (un mot de passe maitre a ete defini)."""
        row = self.conn.execute("SELECT 1 FROM vault_meta WHERE id = 1").fetchone()
        return row is not None

    def get_vault_meta(self) -> Optional[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM vault_meta WHERE id = 1").fetchone()

    def set_vault_meta(self, kdf_salt: bytes, verifier_nonce: bytes, verifier_ciphertext: bytes) -> None:
        """Cree OU remplace entierement les metadonnees du coffre (utilise
        aussi bien a la creation initiale qu'a un changement de mot de passe
        maitre, ou le sel et le verificateur sont entierement regeneres)."""
        self.conn.execute(
            """INSERT INTO vault_meta (id, kdf_salt, verifier_nonce, verifier_ciphertext, created_at)
               VALUES (1, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                   kdf_salt = excluded.kdf_salt,
                   verifier_nonce = excluded.verifier_nonce,
                   verifier_ciphertext = excluded.verifier_ciphertext""",
            (kdf_salt, verifier_nonce, verifier_ciphertext, _now_iso()),
        )
        self.conn.commit()

    # -- entrees (chaque ligne = un blob chiffre opaque) -----------------------

    def add_entry(self, nonce: bytes, ciphertext: bytes) -> int:
        now = _now_iso()
        cur = self.conn.execute(
            "INSERT INTO entries (nonce, ciphertext, created_at, updated_at) VALUES (?, ?, ?, ?)",
            (nonce, ciphertext, now, now),
        )
        self.conn.commit()
        return cur.lastrowid

    def update_entry(self, entry_id: int, nonce: bytes, ciphertext: bytes) -> None:
        self.conn.execute(
            "UPDATE entries SET nonce = ?, ciphertext = ?, updated_at = ? WHERE id = ?",
            (nonce, ciphertext, _now_iso(), entry_id),
        )
        self.conn.commit()

    def delete_entry(self, entry_id: int) -> None:
        self.conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        self.conn.commit()

    def get_entry(self, entry_id: int) -> Optional[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone()

    def list_entries(self) -> list:
        return self.conn.execute("SELECT * FROM entries ORDER BY id").fetchall()

    def replace_all_entries_and_meta(
        self, entries: list, kdf_salt: bytes, verifier_nonce: bytes, verifier_ciphertext: bytes,
    ) -> None:
        """Remplace atomiquement le contenu chiffre de TOUTES les entrees ET
        les metadonnees du coffre (sel, verificateur) en une seule
        transaction - utilise exclusivement lors d'un changement de mot de
        passe maitre. Les deux doivent reussir ou echouer ENSEMBLE : si les
        entrees etaient re-chiffrees avec la nouvelle cle mais que
        vault_meta gardait l'ancien sel/verificateur (ou l'inverse), le
        coffre entier deviendrait irrecuperable (aucun mot de passe,
        ancien ou nouveau, ne permettrait plus de le dechiffrer).
        `entries` : liste de (id, nonce, ciphertext)."""
        try:
            for entry_id, nonce, ciphertext in entries:
                self.conn.execute(
                    "UPDATE entries SET nonce = ?, ciphertext = ?, updated_at = ? WHERE id = ?",
                    (nonce, ciphertext, _now_iso(), entry_id),
                )
            self.conn.execute(
                """INSERT INTO vault_meta (id, kdf_salt, verifier_nonce, verifier_ciphertext, created_at)
                   VALUES (1, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                       kdf_salt = excluded.kdf_salt,
                       verifier_nonce = excluded.verifier_nonce,
                       verifier_ciphertext = excluded.verifier_ciphertext""",
                (kdf_salt, verifier_nonce, verifier_ciphertext, _now_iso()),
            )
        except Exception:
            self.conn.rollback()
            raise
        self.conn.commit()
