"""Logique metier de Coffre : assemble crypto.py (primitives) et db.py
(stockage) pour presenter une interface en clair a la GUI - creation du
coffre, deverrouillage, verrouillage, et CRUD des entrees.

Toutes les entrees dechiffrees vivent UNIQUEMENT en memoire process, dans
`Vault._entries`, tant que le coffre est deverrouille ; `lock()` supprime
cette reference (et celle de la cle derivee) pour qu'elles deviennent
eligibles au ramasse-miettes plutot que de rester accessibles apres
verrouillage. Note honnete : CPython n'offre aucune garantie d'effacement
memoire immediat/deterministe (contrairement a un `memset` en C) - `lock()`
retire toute reference exploitable par le reste de l'application, ce qui
est la meilleure garantie raisonnable dans un langage a ramasse-miettes,
mais pas une garantie cryptographique d'effacement physique de la RAM."""

from __future__ import annotations

import json
import secrets
import string
from pathlib import Path
from typing import Optional

import crypto
from db import Database

# Texte fixe chiffre a la creation du coffre et rechiffre a chaque
# changement de mot de passe : le dechiffrer avec succes prouve que le mot
# de passe fourni est le bon, sans jamais avoir besoin de stocker le mot de
# passe lui-meme ni un hash direct dessus.
_VERIFIER_PLAINTEXT = b"coffre-verifier-v1"

_ENTRY_FIELDS = ("title", "username", "password", "url", "notes")

AMBIGUOUS_CHARACTERS = "0O1lI"


class VaultError(Exception):
    """Erreur d'utilisation du coffre (deja initialise, verrouille, entree
    introuvable, mot de passe actuel incorrect...) - distincte de
    crypto.DecryptionError, qui signale specifiquement un echec
    cryptographique (mauvais mot de passe maitre ou donnees alterees)."""


class Vault:
    def __init__(self, db_path: Path):
        self.db = Database(db_path)
        self._key: Optional[bytes] = None
        self._entries: Optional[list] = None
        self.corrupted_entry_ids: list = []

    def close(self) -> None:
        self.lock()
        self.db.close()

    @property
    def is_unlocked(self) -> bool:
        return self._key is not None

    def exists(self) -> bool:
        """Un coffre a deja ete cree (un mot de passe maitre est defini)."""
        return self.db.is_initialized()

    def _require_unlocked(self) -> None:
        if not self.is_unlocked:
            raise VaultError("Le coffre est verrouille.")

    # -- creation / deverrouillage / verrouillage ------------------------------

    def create(self, master_password: str) -> None:
        if self.db.is_initialized():
            raise VaultError("Un coffre existe deja pour ce fichier.")
        if not master_password:
            raise VaultError("Le mot de passe maitre ne peut pas etre vide.")
        salt = crypto.generate_salt()
        key = crypto.derive_key(master_password, salt)
        nonce, ciphertext = crypto.encrypt(key, _VERIFIER_PLAINTEXT)
        self.db.set_vault_meta(salt, nonce, ciphertext)
        self._key = key
        self._entries = []

    def unlock(self, master_password: str) -> bool:
        """Tente de deverrouiller le coffre. Renvoie False si le mot de
        passe est incorrect (ne leve jamais d'exception pour ce cas normal
        et attendu - reserve VaultError aux erreurs d'utilisation).

        Une entree individuellement corrompue (alteration disque, edition
        manuelle de la base...) est exclue de la liste plutot que de faire
        remonter DecryptionError et bloquer l'acces a TOUTES les autres
        entrees saines - son id reste consultable via
        `corrupted_entry_ids` pour que l'appelant puisse avertir
        l'utilisateur sans pour autant lui refuser tout le coffre."""
        meta = self.db.get_vault_meta()
        if meta is None:
            raise VaultError("Aucun coffre n'a encore ete cree.")
        key = crypto.derive_key(master_password, meta["kdf_salt"])
        try:
            crypto.decrypt(key, meta["verifier_nonce"], meta["verifier_ciphertext"])
        except crypto.DecryptionError:
            return False
        self._key = key
        self._entries, self.corrupted_entry_ids = self._decrypt_all_entries()
        return True

    def lock(self) -> None:
        self._key = None
        self._entries = None
        self.corrupted_entry_ids = []

    def _decode_entry(self, row) -> dict:
        payload = json.loads(crypto.decrypt(self._key, row["nonce"], row["ciphertext"]).decode("utf-8"))
        payload["id"] = row["id"]
        payload["created_at"] = row["created_at"]
        payload["updated_at"] = row["updated_at"]
        return payload

    def _decrypt_all_entries(self) -> tuple:
        entries = []
        corrupted_ids = []
        for row in self.db.list_entries():
            try:
                entries.append(self._decode_entry(row))
            except crypto.DecryptionError:
                corrupted_ids.append(row["id"])
        return entries, corrupted_ids

    def _encrypt_payload(self, entry: dict) -> tuple:
        payload = {field: entry.get(field, "") for field in _ENTRY_FIELDS}
        return crypto.encrypt(self._key, json.dumps(payload).encode("utf-8"))

    # -- entrees ---------------------------------------------------------------

    def list_entries(self) -> list:
        self._require_unlocked()
        return list(self._entries)

    def get_entry(self, entry_id: int) -> Optional[dict]:
        self._require_unlocked()
        return next((dict(e) for e in self._entries if e["id"] == entry_id), None)

    def add_entry(self, title: str, username: str = "", password: str = "", url: str = "", notes: str = "") -> int:
        self._require_unlocked()
        if not title.strip():
            raise VaultError("Le titre ne peut pas etre vide.")
        entry = {"title": title.strip(), "username": username, "password": password, "url": url, "notes": notes}
        nonce, ciphertext = self._encrypt_payload(entry)
        entry_id = self.db.add_entry(nonce, ciphertext)
        row = self.db.get_entry(entry_id)
        entry.update(id=entry_id, created_at=row["created_at"], updated_at=row["updated_at"])
        self._entries.append(entry)
        return entry_id

    def update_entry(self, entry_id: int, **fields) -> None:
        self._require_unlocked()
        allowed = set(_ENTRY_FIELDS)
        updates = {k: v for k, v in fields.items() if k in allowed}
        index = next((i for i, e in enumerate(self._entries) if e["id"] == entry_id), None)
        if index is None:
            raise VaultError(f"Entree introuvable : {entry_id}")
        updated = dict(self._entries[index])
        updated.update(updates)
        if not updated["title"].strip():
            raise VaultError("Le titre ne peut pas etre vide.")
        nonce, ciphertext = self._encrypt_payload(updated)
        self.db.update_entry(entry_id, nonce, ciphertext)
        row = self.db.get_entry(entry_id)
        updated["updated_at"] = row["updated_at"]
        self._entries[index] = updated

    def delete_entry(self, entry_id: int) -> None:
        self._require_unlocked()
        self.db.delete_entry(entry_id)
        self._entries = [e for e in self._entries if e["id"] != entry_id]

    def find_reused_passwords(self) -> list:
        """Groupe les entrees qui partagent EXACTEMENT le meme mot de passe.
        Ne renvoie que les groupes de 2 entrees ou plus - une entree seule
        n'est jamais un "mot de passe reutilise". Les entrees sans mot de
        passe (champ vide) sont ignorees : un champ vide n'est pas un
        secret partage, juste une absence de valeur. Le mot de passe
        lui-meme n'est jamais renvoye ici (seulement les entrees qui le
        partagent) - cette fonction sert a alerter, pas a afficher les
        secrets en clair dans un rapport."""
        self._require_unlocked()
        groups: dict = {}
        for entry in self._entries:
            password = entry.get("password", "")
            if not password:
                continue
            groups.setdefault(password, []).append(entry)
        return [entries for entries in groups.values() if len(entries) > 1]

    # -- mot de passe maitre ----------------------------------------------------

    def change_master_password(self, current_password: str, new_password: str) -> None:
        self._require_unlocked()
        meta = self.db.get_vault_meta()
        current_key = crypto.derive_key(current_password, meta["kdf_salt"])
        try:
            crypto.decrypt(current_key, meta["verifier_nonce"], meta["verifier_ciphertext"])
        except crypto.DecryptionError:
            raise VaultError("Le mot de passe actuel est incorrect.")
        if not new_password:
            raise VaultError("Le nouveau mot de passe ne peut pas etre vide.")

        new_salt = crypto.generate_salt()
        new_key = crypto.derive_key(new_password, new_salt)

        # Rechiffre TOUTES les entrees avec la nouvelle cle avant d'ecrire
        # quoi que ce soit sur le disque - db.replace_all_entries_and_meta
        # applique ensuite ce resultat et les nouvelles metadonnees en une
        # seule transaction atomique (voir sa docstring : un echec partiel
        # rendrait sinon le coffre entierement irrecuperable).
        re_encrypted = []
        for entry in self._entries:
            nonce, ciphertext = crypto.encrypt(new_key, json.dumps(
                {field: entry.get(field, "") for field in _ENTRY_FIELDS}
            ).encode("utf-8"))
            re_encrypted.append((entry["id"], nonce, ciphertext))

        new_verifier_nonce, new_verifier_ciphertext = crypto.encrypt(new_key, _VERIFIER_PLAINTEXT)
        self.db.replace_all_entries_and_meta(re_encrypted, new_salt, new_verifier_nonce, new_verifier_ciphertext)

        self._key = new_key
        self._entries, self.corrupted_entry_ids = self._decrypt_all_entries()


def generate_password(
    length: int = 20, use_upper: bool = True, use_lower: bool = True,
    use_digits: bool = True, use_symbols: bool = True, avoid_ambiguous: bool = True,
) -> str:
    """Genere un mot de passe aleatoire cryptographiquement sur (module
    `secrets`, jamais `random`). Au moins une categorie de caracteres doit
    etre activee."""
    pools = []
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.?")
    if not pools:
        raise VaultError("Selectionnez au moins un type de caractere.")
    if avoid_ambiguous:
        pools = [
            "".join(c for c in pool if c not in AMBIGUOUS_CHARACTERS) for pool in pools
        ]
        pools = [pool for pool in pools if pool]
    if not pools:
        raise VaultError("Aucun caractere disponible avec ces reglages.")
    if length < len(pools):
        raise VaultError(f"La longueur doit etre d'au moins {len(pools)} pour inclure chaque type selectionne.")

    # Garantit au moins un caractere de chaque categorie activee (sinon un
    # mot de passe "long" pourrait par malchance n'etre que des chiffres),
    # puis complete le reste au hasard sur l'union des categories.
    all_chars = "".join(pools)
    result = [secrets.choice(pool) for pool in pools]
    result += [secrets.choice(all_chars) for _ in range(length - len(pools))]
    # Melange pour que les caracteres "garantis" ne soient pas toujours en tete.
    for i in range(len(result) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        result[i], result[j] = result[j], result[i]
    return "".join(result)
