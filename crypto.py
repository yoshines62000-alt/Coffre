"""Primitives cryptographiques de Coffre : derivation de cle a partir du mot
de passe maitre, et chiffrement authentifie des donnees du coffre.

Choix delibere de s'appuyer entierement sur la bibliotheque `cryptography`
(implementations auditees d'AES-GCM et scrypt) plutot que d'ecrire le moindre
code cryptographique maison - la seule partie "maison" ici est l'assemblage
(format de stockage, gestion des sels/nonces), jamais la primitive elle-meme.

Format de chiffrement : AES-256-GCM (chiffrement authentifie - toute
alteration du texte chiffre, meme d'un seul octet, fait echouer le
dechiffrement au lieu de renvoyer silencieusement des donnees corrompues).
Un nonce de 12 octets, genere aleatoirement, DOIT etre unique par message
chiffre avec une meme cle : reutiliser un nonce avec AES-GCM romprait
completement la confidentialite. Chaque appel a `encrypt()` en genere un
nouveau via `os.urandom`.

Derivation de cle : scrypt (memory-hard, resistant aux attaques par GPU/ASIC
bien mieux que PBKDF2 a nombre d'iterations equivalent), avec un sel de 16
octets propre a chaque coffre, genere une seule fois a sa creation."""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # AES-256

# Parametres scrypt courants : n=2**17 (mesure a l'audit : ~550ms sur une
# machine de developpement moderne, contre ~276ms pour l'ancien n=2**16 -
# toujours largement imperceptible pour l'utilisateur legitime qui ne le
# tape qu'une fois par deverrouillage). Aligne sur la recommandation
# actuelle de l'OWASP Password Storage Cheat Sheet pour scrypt quand
# Argon2id n'est pas utilise (minimum n=2**17, r=8, p=1, soit 128 MiB de
# cout memoire) - l'ancien n=2**16 (64 MiB) etait en dessous de ce minimum
# (audit constat A2).
#
# IMPORTANT - ces constantes ne doivent JAMAIS servir directement a
# DECHIFFRER un coffre existant : les parametres reellement utilises pour
# un coffre donne sont stockes AVEC ce coffre (colonnes kdf_n/kdf_r/kdf_p
# de vault_meta, voir db.py) plutot qu'en dur ici, precisement pour qu'un
# futur changement de ces valeurs ne rende jamais un coffre deja cree
# illisible. Elles ne servent que de valeur par defaut pour un NOUVEAU
# coffre (Vault.create) ou une migration explicite (Vault.unlock /
# Vault.change_master_password), qui passent alors ces parametres a
# derive_key de facon explicite.
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1

# Anciens parametres scrypt, utilises en dur par tout coffre cree avant ce
# correctif d'audit (v1.0.9 et anterieur). Necessaires pour continuer a
# ouvrir un coffre existant qui n'a pas encore ete migre vers ses propres
# colonnes kdf_n/kdf_r/kdf_p en base (voir
# db.py::Database._migrate_legacy_kdf_columns, qui remplit automatiquement
# ces colonnes avec EXACTEMENT ces valeurs pour toute base preexistante -
# ce sont les parametres reellement employes a la creation de ces coffres,
# donc les seuls qui permettent encore de les dechiffrer tant qu'une
# migration transparente n'a pas eu lieu, voir Vault.unlock).
LEGACY_SCRYPT_N = 2**16
LEGACY_SCRYPT_R = 8
LEGACY_SCRYPT_P = 1


class DecryptionError(Exception):
    """Mot de passe maitre incorrect, ou donnees chiffrees alterees/
    corrompues - ces deux cas sont indiscernables par construction (c'est le
    but d'un chiffrement authentifie), et doivent etre traites de la meme
    facon par l'appelant : refuser l'acces, jamais deviner ni recuperer
    partiellement."""


def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def derive_key(
    master_password: str, salt: bytes, n: int = SCRYPT_N, r: int = SCRYPT_R, p: int = SCRYPT_P,
) -> bytes:
    """Derive une cle AES-256 a partir du mot de passe maitre et d'un sel.
    Deterministe (meme mot de passe + meme sel + memes parametres n/r/p =
    meme cle), condition necessaire pour pouvoir redechiffrer le coffre
    plus tard.

    n/r/p sont desormais des parametres explicites (par defaut les valeurs
    courantes SCRYPT_N/R/P ci-dessus) plutot que des constantes figees a
    l'interieur de cette fonction : l'appelant (Vault) doit pouvoir
    deriver une cle avec les parametres REELLEMENT stockes pour un coffre
    donne (qui peuvent etre les anciens LEGACY_SCRYPT_* pour un coffre pas
    encore migre), et pas necessairement les parametres courants -
    correctif de l'audit A2 (compatibilite ascendante : augmenter
    SCRYPT_N ne doit jamais rendre un coffre existant indechiffrable)."""
    kdf = Scrypt(salt=salt, length=KEY_SIZE, n=n, r=r, p=p)
    return kdf.derive(master_password.encode("utf-8"))


def encrypt(key: bytes, plaintext: bytes) -> tuple:
    """Chiffre `plaintext` avec `key` (AES-256-GCM). Renvoie (nonce,
    ciphertext) - le nonce n'est pas secret et doit etre stocke a cote du
    ciphertext pour permettre le dechiffrement ulterieur."""
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Dechiffre et verifie l'integrite de `ciphertext`. Leve DecryptionError
    si la cle est incorrecte OU si les donnees ont ete alterees - jamais de
    distinction entre ces deux cas (voir DecryptionError).

    Attrape aussi ValueError (pas seulement InvalidTag) : un nonce de
    mauvaise longueur - ex : une entree corrompue par edition manuelle de
    la base - fait lever un ValueError brut par AESGCM.decrypt, distinct
    d'InvalidTag, qui remontait auparavant tel quel hors de cette fonction
    et faisait planter unlock() au lieu d'etre traite comme une entree
    corrompue ordinaire (voir Vault._decrypt_all_entries / corrupted_entry_ids,
    bug trouve a l'audit)."""
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except (InvalidTag, ValueError) as exc:
        raise DecryptionError("Mot de passe incorrect ou donnees corrompues.") from exc
