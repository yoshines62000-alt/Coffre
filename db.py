"""Couche donnees de Coffre (SQLite, sans dependance externe).

Ce module ne connait rien de la cryptographie : il stocke et relit des
blobs binaires opaques (sel, nonces, ciphertexts) tels quels, exactement
comme les autres projets separent la couche donnees de la logique metier.
Le dechiffrement/chiffrement est entierement la responsabilite de vault.py.
"""

from __future__ import annotations

import os
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
        # Mode WAL : les ecritures (add_entry/update_entry, appelees a
        # chaque frappe validee dans la GUI) commitent dans un fichier
        # journal a part (-wal) plutot que d'ecrire directement dans la
        # base et d'attendre un fsync() disque complet a chaque commit -
        # mesure a l'audit : facteur ~8x sur des insertions unitaires
        # (8.20ms/ligne en mode par defaut contre 1.00ms/ligne en WAL).
        # busy_timeout evite une SQLITE_BUSY immediate si une seconde
        # connexion (ex: backup_to, qui en ouvre une le temps de la copie)
        # detient bien le fichier au meme instant.
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self._create_schema()
        self._migrate_legacy_kdf_columns()

    def close(self) -> None:
        self.conn.close()

    def backup_to(self, dest_path: Path) -> None:
        """Copie la base entiere vers `dest_path` via l'API de sauvegarde
        native de sqlite3, qui garantit une copie coherente meme si des
        ecritures sont en cours - contrairement a une copie brute du
        fichier, qui pourrait capturer un etat intermediaire invalide.
        Refuse la base active comme destination : sqlite s'ecraserait
        lui-meme. Deux verifications : les chemins RESOLUS (pour qu'un
        alias comme "..\\coffre.sqlite" ne contourne pas ce garde-fou) ET,
        si la destination existe deja, l'identite de fichier via
        os.path.samefile (pour attraper un LIEN PHYSIQUE - hard link - vers
        le meme fichier ; bug trouve a l'audit : resolve() ne le detecte
        jamais, puisqu'un lien physique n'est pas un point de reparse a
        suivre, et sans cette verification sqlite3 restait bloque
        indefiniment a tenter d'ouvrir une seconde connexion vers le meme
        fichier physique)."""
        dest_path = Path(dest_path)
        if dest_path.resolve() == self.path.resolve():
            raise ValueError("La destination ne peut pas etre le fichier du coffre en cours d'utilisation.")
        if dest_path.exists():
            try:
                if os.path.samefile(dest_path, self.path):
                    raise ValueError("La destination ne peut pas etre le fichier du coffre en cours d'utilisation.")
            except OSError:
                pass  # comparaison impossible (permissions...) : on laisse la suite echouer normalement
        dest_conn = sqlite3.connect(str(dest_path))
        try:
            self.conn.backup(dest_conn)
        finally:
            dest_conn.close()

    def _create_schema(self) -> None:
        # kdf_n/kdf_r/kdf_p (audit A2) : les parametres scrypt utilises pour
        # CE coffre precis, stockes a cote du sel plutot que fixes en dur
        # cote crypto.py - ce qui permet de faire evoluer les parametres
        # par defaut d'un coffre a l'autre (voir Vault.create) sans jamais
        # rendre un coffre deja cree illisible (voir Vault.unlock, qui lit
        # ces colonnes pour deriver la cle avec les BONS parametres). Le
        # DEFAULT ci-dessous (65536/8/1) ne sert que de filet pour un INSERT
        # qui omettrait ces colonnes - le code applicatif (vault.py) les
        # fournit toujours explicitement. Ce module reste volontairement
        # ignorant de la cryptographie (voir docstring de fichier) : ces
        # valeurs sont donc des litteraux, pas des constantes importees de
        # crypto.py.
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS vault_meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            kdf_salt BLOB NOT NULL,
            verifier_nonce BLOB NOT NULL,
            verifier_ciphertext BLOB NOT NULL,
            created_at TEXT NOT NULL,
            kdf_n INTEGER NOT NULL DEFAULT 65536,
            kdf_r INTEGER NOT NULL DEFAULT 8,
            kdf_p INTEGER NOT NULL DEFAULT 1
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

    def _migrate_legacy_kdf_columns(self) -> None:
        """Coffres crees avant le correctif d'audit A2 (v1.0.9 et
        anterieur) : leur table `vault_meta` n'a pas encore les colonnes
        kdf_n/kdf_r/kdf_p - le `CREATE TABLE IF NOT EXISTS` ci-dessus ne
        les ajoute que pour une base TOUTE NEUVE, il est silencieusement
        ignore si la table existe deja avec l'ancien schema.

        Ajoute ces colonnes ici via `ALTER TABLE ... ADD COLUMN ... DEFAULT
        ...` avec une valeur par defaut EGALE aux anciens parametres scrypt
        qui etaient fixes en dur dans crypto.py avant ce correctif
        (65536/8/1, voir crypto.LEGACY_SCRYPT_N/R/P) : SQLite remplit alors
        automatiquement, sans aucune donnee chiffree a retoucher, la ligne
        `vault_meta` deja existante (il ne peut y en avoir qu'une, voir
        CHECK id = 1) avec ces valeurs - exactement les parametres qui ont
        reellement servi a deriver la cle protegeant ce coffre. C'est ce
        qui garantit qu'un coffre existant continue de s'ouvrir avec
        Vault.unlock apres ce correctif, sans intervention de
        l'utilisateur (voir aussi Vault._migrate_kdf_params pour la mise a
        niveau transparente vers les parametres courants au deverrouillage
        suivant).

        Idempotent : verifie d'abord si les colonnes existent deja (via
        `PRAGMA table_info`) avant de tenter l'ALTER TABLE - indispensable
        puisque `__init__` (et donc cette methode) s'execute a CHAQUE
        ouverture du coffre, pas seulement la toute premiere apres la mise
        a jour ; sans cette verification, la deuxieme ouverture leverait
        une erreur SQLite ("duplicate column name") et empecherait
        totalement le demarrage de l'application."""
        existing_columns = {row["name"] for row in self.conn.execute("PRAGMA table_info(vault_meta)")}
        if "kdf_n" in existing_columns:
            return  # deja migre (ou base toute neuve, deja creee avec ces colonnes) : rien a faire
        for column, default in (("kdf_n", 65536), ("kdf_r", 8), ("kdf_p", 1)):
            self.conn.execute(f"ALTER TABLE vault_meta ADD COLUMN {column} INTEGER NOT NULL DEFAULT {default}")
        self.conn.commit()

    # -- metadonnees du coffre (mot de passe maitre) ---------------------------

    def is_initialized(self) -> bool:
        """Un coffre existe deja (un mot de passe maitre a ete defini)."""
        row = self.conn.execute("SELECT 1 FROM vault_meta WHERE id = 1").fetchone()
        return row is not None

    def get_vault_meta(self) -> Optional[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM vault_meta WHERE id = 1").fetchone()

    def set_vault_meta(
        self, kdf_salt: bytes, verifier_nonce: bytes, verifier_ciphertext: bytes,
        kdf_n: int = 65536, kdf_r: int = 8, kdf_p: int = 1,
    ) -> None:
        """Cree OU remplace entierement les metadonnees du coffre (utilise
        aussi bien a la creation initiale qu'a un changement de mot de passe
        maitre, ou le sel et le verificateur sont entierement regeneres).

        kdf_n/kdf_r/kdf_p (audit A2) : parametres scrypt reellement utilises
        pour deriver la cle de CE coffre - stockes ici plutot que fixes en
        dur cote crypto.py, pour qu'un futur changement des parametres par
        defaut (crypto.SCRYPT_N) ne rende jamais illisible un coffre deja
        cree. Valeurs par defaut = anciens parametres (65536/8/1) pour
        compatibilite avec les appelants qui ne les precisent pas encore ;
        vault.py les fournit toujours explicitement en pratique."""
        self.conn.execute(
            """INSERT INTO vault_meta
                   (id, kdf_salt, verifier_nonce, verifier_ciphertext, created_at, kdf_n, kdf_r, kdf_p)
               VALUES (1, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                   kdf_salt = excluded.kdf_salt,
                   verifier_nonce = excluded.verifier_nonce,
                   verifier_ciphertext = excluded.verifier_ciphertext,
                   kdf_n = excluded.kdf_n,
                   kdf_r = excluded.kdf_r,
                   kdf_p = excluded.kdf_p""",
            (kdf_salt, verifier_nonce, verifier_ciphertext, _now_iso(), kdf_n, kdf_r, kdf_p),
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
        kdf_n: int = 65536, kdf_r: int = 8, kdf_p: int = 1,
    ) -> None:
        """Remplace atomiquement le contenu chiffre de TOUTES les entrees ET
        les metadonnees du coffre (sel, verificateur, parametres KDF) en une
        seule transaction - utilise lors d'un changement de mot de passe
        maitre ET lors de la migration transparente des parametres scrypt
        (audit A2, voir Vault._migrate_kdf_params). Tout doit reussir ou
        echouer ENSEMBLE : si les entrees etaient re-chiffrees avec la
        nouvelle cle mais que vault_meta gardait l'ancien sel/verificateur/
        parametres (ou l'inverse), le coffre entier deviendrait
        irrecuperable (aucun mot de passe, ancien ou nouveau, ne
        permettrait plus de le dechiffrer).
        `entries` : liste de (id, nonce, ciphertext)."""
        try:
            for entry_id, nonce, ciphertext in entries:
                self.conn.execute(
                    "UPDATE entries SET nonce = ?, ciphertext = ?, updated_at = ? WHERE id = ?",
                    (nonce, ciphertext, _now_iso(), entry_id),
                )
            self.conn.execute(
                """INSERT INTO vault_meta
                       (id, kdf_salt, verifier_nonce, verifier_ciphertext, created_at, kdf_n, kdf_r, kdf_p)
                   VALUES (1, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(id) DO UPDATE SET
                       kdf_salt = excluded.kdf_salt,
                       verifier_nonce = excluded.verifier_nonce,
                       verifier_ciphertext = excluded.verifier_ciphertext,
                       kdf_n = excluded.kdf_n,
                       kdf_r = excluded.kdf_r,
                       kdf_p = excluded.kdf_p""",
                (kdf_salt, verifier_nonce, verifier_ciphertext, _now_iso(), kdf_n, kdf_r, kdf_p),
            )
        except Exception:
            self.conn.rollback()
            raise
        self.conn.commit()
