#!/usr/bin/env python3
"""Secours : lire un coffre Coffre SANS l'application, avec Python seul.

POURQUOI CE FICHIER EXISTE
--------------------------
Un utilisateur dont l'executable ne se lance plus — Windows qui bloque, un
antivirus zele, une machine changee — perd l'acces a tout son coffre alors que
le fichier chiffre est intact et que l'algorithme est public. Ce script
reprend les primitives avec la bibliotheque standard de Python, et rien
d'autre : pas de `cryptography`, pas de `pip install`. S'il y a un Python sur
la machine, le coffre se lit.

    python secours_coffre.py coffre.sqlite                 (affiche les titres)
    python secours_coffre.py coffre.sqlite --json sortie.json
    python secours_coffre.py coffre.sqlite --csv sortie.csv

Le mot de passe maitre est demande sans echo. Le coffre n'est JAMAIS modifie :
il est ouvert en lecture seule.

CE QU'IL FAIT, EXACTEMENT (et que Coffre fait avec `cryptography`)
------------------------------------------------------------------
1. Lit `vault_meta` : sel, parametres scrypt (n, r, p) REELLEMENT stockes,
   nonce et texte chiffre du verificateur.
2. Derive la cle AES-256 : scrypt(mot de passe, sel, n, r, p, 32 octets) —
   `hashlib.scrypt`, bibliotheque standard.
3. Dechiffre le verificateur en AES-256-GCM : s'il ne rend pas
   `coffre-verifier-v1`, le mot de passe est faux (ou le fichier altere), et
   on s'arrete la — on ne devine pas, on ne recupere pas « partiellement ».
4. Dechiffre chaque entree (JSON) et l'exporte.

AES-256-GCM N'EST PAS DANS LA BIBLIOTHEQUE STANDARD : il est implemente ici
en pur Python (AES + compteur + GHASH), et PROUVE contre `cryptography` par
tests/test_secours_coffre.py sur des vecteurs aleatoires et sur de vrais
coffres crees par l'application. Il est lent (c'est du Python) et non
constant-time : c'est un outil de reprise qu'on lance soi-meme, une fois, sur
sa propre machine — pas une bibliotheque.

ATTENTION : l'export est EN CLAIR. Un fichier JSON ou CSV de mots de passe
se lit par n'importe qui. Exportez, recuperez ce qu'il vous faut, supprimez.
"""
from __future__ import annotations

import argparse
import csv
import getpass
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

VERIFIER = b"coffre-verifier-v1"
CHAMPS = ("id", "title", "username", "password", "url", "notes", "totp", "created_at", "updated_at")


class CoffreIllisible(Exception):
    """Mot de passe faux, fichier altere, ou pas un coffre Coffre."""


# ---------------------------------------------------------------- AES-256
# Implementation scolaire, lisible avant d'etre rapide. Les tables sont
# calculees au chargement plutot que recopiees : une table recopiee peut
# porter une faute de frappe, une table calculee non.

def _construire_sbox():
    sbox = [0] * 256
    p = q = 1
    while True:
        # multiplication par 3 dans GF(2^8)
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        # division par 3
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ (q << 1) ^ (q << 2) ^ (q << 3) ^ (q << 4)
        x = (x ^ (x >> 8) ^ 0x63) & 0xFF
        sbox[p] = x
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


_SBOX = _construire_sbox()


def _xtime(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def _mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _cles_de_tour(cle: bytes) -> list:
    """Expansion de cle AES-256 : 15 cles de tour de 16 octets."""
    if len(cle) != 32:
        raise ValueError("AES-256 attend une cle de 32 octets")
    mots = [list(cle[i:i + 4]) for i in range(0, 32, 4)]
    rcon = 1
    for i in range(8, 60):
        t = list(mots[i - 1])
        if i % 8 == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif i % 8 == 4:
            t = [_SBOX[b] for b in t]
        mots.append([a ^ b for a, b in zip(mots[i - 8], t)])
    return [bytes(sum(mots[4 * r:4 * r + 4], [])) for r in range(15)]


def _chiffrer_bloc(cles: list, bloc: bytes) -> bytes:
    """Un bloc AES de 16 octets, 14 tours (AES-256). Etat en colonnes."""
    s = [b ^ k for b, k in zip(bloc, cles[0])]
    for tour in range(1, 15):
        s = [_SBOX[b] for b in s]                                   # SubBytes
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]           # ShiftRows
        if tour != 14:                                               # MixColumns
            m = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                m += [_mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3],
                      a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3],
                      a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3),
                      _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)]
            s = m
        s = [b ^ k for b, k in zip(s, cles[tour])]                   # AddRoundKey
    return bytes(s)


# ----------------------------------------------------------------- GCM

def _ghash_mul(x: int, h: int) -> int:
    """Multiplication dans GF(2^128) avec le polynome de GCM (bits en ordre
    « reflechi », comme le veut la norme)."""
    r = 0
    for i in range(128):
        if (x >> (127 - i)) & 1:
            r ^= h
        if h & 1:
            h = (h >> 1) ^ (0xE1 << 120)
        else:
            h >>= 1
    return r


def _ghash(h: int, donnees: bytes) -> int:
    y = 0
    for i in range(0, len(donnees), 16):
        bloc = donnees[i:i + 16].ljust(16, b"\x00")
        y = _ghash_mul(y ^ int.from_bytes(bloc, "big"), h)
    return y


def aes_gcm_dechiffrer(cle: bytes, nonce: bytes, texte_chiffre: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM : `texte_chiffre` = chiffre || etiquette (16 octets), comme le
    rend `cryptography.AESGCM.encrypt`. Leve CoffreIllisible si l'etiquette ne
    correspond pas — mot de passe faux ou donnees alterees, indiscernables par
    construction."""
    if len(texte_chiffre) < 16:
        raise CoffreIllisible("texte chiffre trop court pour porter une etiquette")
    cles = _cles_de_tour(cle)
    chiffre, etiquette = texte_chiffre[:-16], texte_chiffre[-16:]
    h = int.from_bytes(_chiffrer_bloc(cles, b"\x00" * 16), "big")
    if len(nonce) == 12:
        j0 = nonce + b"\x00\x00\x00\x01"
    else:
        longueurs = (0).to_bytes(8, "big") + (len(nonce) * 8).to_bytes(8, "big")
        j0 = _ghash(h, nonce.ljust(((len(nonce) + 15) // 16) * 16, b"\x00") + longueurs).to_bytes(16, "big")

    def _compteur(j: bytes, k: int) -> bytes:
        return j[:12] + ((int.from_bytes(j[12:], "big") + k) & 0xFFFFFFFF).to_bytes(4, "big")

    # Verification de l'etiquette AVANT de rendre quoi que ce soit.
    aad_pad = aad.ljust(((len(aad) + 15) // 16) * 16, b"\x00") if aad else b""
    c_pad = chiffre.ljust(((len(chiffre) + 15) // 16) * 16, b"\x00")
    longueurs = (len(aad) * 8).to_bytes(8, "big") + (len(chiffre) * 8).to_bytes(8, "big")
    s = _ghash(h, aad_pad + c_pad + longueurs)
    attendue = (s ^ int.from_bytes(_chiffrer_bloc(cles, j0), "big")).to_bytes(16, "big")
    # Comparaison en temps « constant » au sens de hmac.compare_digest.
    import hmac
    if not hmac.compare_digest(attendue, etiquette):
        raise CoffreIllisible("etiquette d'authentification invalide : mot de passe faux ou donnees alterees")

    clair = bytearray()
    for i in range(0, len(chiffre), 16):
        flux = _chiffrer_bloc(cles, _compteur(j0, i // 16 + 1))
        bloc = chiffre[i:i + 16]
        clair += bytes(a ^ b for a, b in zip(bloc, flux))
    return bytes(clair)


# -------------------------------------------------------------- le coffre

def deriver_cle(mot_de_passe: str, sel: bytes, n: int, r: int, p: int) -> bytes:
    """scrypt, bibliotheque standard. `maxmem` est calcule depuis n et r : la
    valeur par defaut (32 Mio) refuse N = 2^17 (128 Mio) avec une erreur qui
    ne dit pas pourquoi."""
    maxmem = 128 * n * r * 2 + 1024 * 1024
    return hashlib.scrypt(mot_de_passe.encode("utf-8"), salt=sel, n=n, r=r, p=p, maxmem=maxmem, dklen=32)


def lire_coffre(chemin: Path, mot_de_passe: str) -> list:
    """Ouvre le coffre EN LECTURE SEULE et rend la liste des entrees en clair.
    Leve CoffreIllisible si le mot de passe est faux ou le fichier altere."""
    chemin = Path(chemin)
    if not chemin.is_file():
        raise CoffreIllisible(f"fichier introuvable : {chemin}")
    # mode=ro : aucune ecriture, aucun fichier -wal/-journal cree a cote.
    conn = sqlite3.connect(f"file:{chemin.as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        try:
            meta = conn.execute("SELECT * FROM vault_meta WHERE id = 1").fetchone()
        except sqlite3.DatabaseError as exc:
            raise CoffreIllisible(f"ce fichier n'est pas un coffre Coffre ({exc})") from exc
        if meta is None:
            raise CoffreIllisible("coffre sans en-tete : jamais initialise, ou altere")
        cles = meta.keys()
        n = meta["kdf_n"] if "kdf_n" in cles else 2 ** 16
        r = meta["kdf_r"] if "kdf_r" in cles else 8
        p = meta["kdf_p"] if "kdf_p" in cles else 1
        cle = deriver_cle(mot_de_passe, bytes(meta["kdf_salt"]), int(n), int(r), int(p))
        # Un mot de passe faux est deja refuse ICI par l'etiquette GCM (la cle
        # derivee est fausse, l'etiquette ne correspond pas) — et chaque entree
        # est authentifiee de la meme facon. La comparaison au texte du
        # verificateur est une ceinture par-dessus les bretelles, mesuree comme
        # telle par la contre-epreuve : la retirer ne laisse rien passer.
        if aes_gcm_dechiffrer(cle, bytes(meta["verifier_nonce"]), bytes(meta["verifier_ciphertext"])) != VERIFIER:
            raise CoffreIllisible("le verificateur ne correspond pas : mot de passe faux")
        entrees = []
        for ligne in conn.execute("SELECT * FROM entries ORDER BY id"):
            clair = aes_gcm_dechiffrer(cle, bytes(ligne["nonce"]), bytes(ligne["ciphertext"]))
            charge = json.loads(clair.decode("utf-8"))
            entree = {c: charge.get(c, "") for c in CHAMPS if c not in ("id", "created_at", "updated_at")}
            entree["id"] = ligne["id"]
            entree["created_at"] = ligne["created_at"]
            entree["updated_at"] = ligne["updated_at"]
            entrees.append({c: entree.get(c, "") for c in CHAMPS})
        return entrees
    finally:
        conn.close()


def exporter_json(entrees: list, sortie: Path) -> None:
    Path(sortie).write_text(json.dumps(entrees, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def exporter_csv(entrees: list, sortie: Path) -> None:
    with open(sortie, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(CHAMPS))
        w.writeheader()
        for e in entrees:
            w.writerow(e)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Lit un coffre Coffre sans l'application (Python standard seul).")
    p.add_argument("coffre", help="le fichier coffre.sqlite")
    p.add_argument("--json", metavar="FICHIER", help="exporter les entrees en JSON (EN CLAIR)")
    p.add_argument("--csv", metavar="FICHIER", help="exporter les entrees en CSV (EN CLAIR)")
    p.add_argument("--mot-de-passe", help="(tests) le mot de passe maitre ; sinon demande sans echo")
    a = p.parse_args(argv)
    mdp = a.mot_de_passe if a.mot_de_passe is not None else getpass.getpass("Mot de passe maitre : ")
    try:
        entrees = lire_coffre(Path(a.coffre), mdp)
    except CoffreIllisible as exc:
        print(f"secours_coffre : {exc}", file=sys.stderr)
        return 2
    print(f"{len(entrees)} entree(s) dechiffree(s).")
    if a.json:
        exporter_json(entrees, Path(a.json))
        print(f"JSON ecrit EN CLAIR : {a.json} — supprimez-le une fois vos donnees recuperees.")
    if a.csv:
        exporter_csv(entrees, Path(a.csv))
        print(f"CSV ecrit EN CLAIR : {a.csv} — supprimez-le une fois vos donnees recuperees.")
    if not a.json and not a.csv:
        for e in entrees:
            print(f"  {e['id']:>4}  {e['title']}  ({e['username']})")
        print("Pour tout recuperer : --json FICHIER ou --csv FICHIER.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
