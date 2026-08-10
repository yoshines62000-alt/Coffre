"""Implementation TOTP (RFC 6238) en Python pur, sans aucune dependance
externe (uniquement la bibliotheque standard : hmac, hashlib, base64,
struct, time).

TOTP = HOTP (RFC 4226) applique a un compteur derive du temps :
`counter = floor(temps_unix / period)`. Chaque code est donc valable
pendant une fenetre de `period` secondes (30 s par defaut), puis se
renouvelle. Le secret est une chaine base32 (l'alphabet standard fourni
par les sites lors de l'activation de la 2FA) ; il est ici traite comme
une donnee opaque et n'est JAMAIS journalise ni ecrit en clair - son
stockage chiffre est de la responsabilite de l'appelant (voir vault.py)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

# Alphabet base32 standard (RFC 4648) : A-Z puis 2-7. Le caractere de
# remplissage '=' est gere separement (retire puis recalcule) lors du
# decodage - un secret de 2FA est presque toujours fourni sans padding.
_BASE32_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

_ALGORITHMS = {
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


def normalize_secret(secret: str) -> str:
    """Normalise un secret base32 saisi par l'utilisateur : retire les
    espaces (les sites presentent souvent le secret par blocs de 4, ex.
    "JBSW Y3DP EHPK 3PXP"), retire le padding '=', et met en majuscules
    (base32 est insensible a la casse). Renvoie la chaine normalisee,
    prete a etre decodee.

    Ne valide pas : voir `is_valid_secret`. Une chaine vide reste vide."""
    return "".join(secret.split()).rstrip("=").upper()


def is_valid_secret(secret: str) -> bool:
    """Vrai si `secret`, une fois normalise, est un secret base32 non vide
    et decodable (uniquement des caracteres de l'alphabet base32 standard,
    en quantite formant un nombre entier d'octets). Un secret vide est
    invalide."""
    normalized = normalize_secret(secret)
    if not normalized:
        return False
    if any(c not in _BASE32_ALPHABET for c in normalized):
        return False
    try:
        _decode_secret(normalized)
    except (ValueError, base64.binascii.Error):
        return False
    return True


def _decode_secret(normalized_secret: str) -> bytes:
    """Decode une chaine base32 DEJA normalisee (majuscules, sans espaces
    ni padding) vers les octets bruts de la cle. Recalcule le padding '='
    requis par base64.b32decode (multiples de 8 caracteres). Leve
    ValueError / binascii.Error si la chaine n'est pas un base32 valide."""
    padding = "=" * ((8 - len(normalized_secret) % 8) % 8)
    return base64.b32decode(normalized_secret + padding, casefold=True)


def generate_totp(
    secret: str,
    timestamp: float | None = None,
    *,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "sha1",
) -> str:
    """Calcule le code TOTP courant pour `secret` (chaine base32).

    - `timestamp` : instant Unix (secondes) ; par defaut `time.time()`.
    - `digits` : longueur du code (6 par defaut ; la RFC illustre 8).
    - `period` : duree de validite d'un code en secondes (30 par defaut).
    - `algorithm` : "sha1" (defaut RFC 6238), "sha256" ou "sha512".

    Leve ValueError si le secret n'est pas un base32 valide ou si
    l'algorithme est inconnu. Le resultat est zero-padde a `digits`
    chiffres (ex. "042311")."""
    try:
        digest = _ALGORITHMS[algorithm.lower()]
    except KeyError:
        raise ValueError(f"Algorithme TOTP inconnu : {algorithm}")

    normalized = normalize_secret(secret)
    if not normalized:
        raise ValueError("Le secret TOTP est vide.")
    key = _decode_secret(normalized)  # peut lever ValueError/binascii.Error

    if timestamp is None:
        timestamp = time.time()
    counter = int(timestamp // period)

    # HOTP (RFC 4226) : HMAC du compteur (8 octets, big-endian), puis
    # troncature dynamique guidee par les 4 bits de poids faible du dernier
    # octet du condensat.
    mac = hmac.new(key, struct.pack(">Q", counter), digest).digest()
    offset = mac[-1] & 0x0F
    binary = (
        ((mac[offset] & 0x7F) << 24)
        | ((mac[offset + 1] & 0xFF) << 16)
        | ((mac[offset + 2] & 0xFF) << 8)
        | (mac[offset + 3] & 0xFF)
    )
    code = binary % (10 ** digits)
    return str(code).zfill(digits)


def seconds_remaining(timestamp: float | None = None, *, period: int = 30) -> int:
    """Nombre de secondes restantes avant le renouvellement du code courant
    (entre 1 et `period`). Sert a alimenter le compte a rebours / la barre
    de progression de l'interface."""
    if timestamp is None:
        timestamp = time.time()
    return period - int(timestamp % period)
