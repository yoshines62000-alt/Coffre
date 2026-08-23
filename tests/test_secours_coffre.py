"""Le script de secours lit un VRAI coffre, sans l'application ni `cryptography`.

Ce qui est prouve ici, et dans cet ordre :
  1. l'AES-256-GCM en pur Python rend exactement ce que `cryptography` a
     chiffre — sur des vecteurs aleatoires, toutes longueurs, avec et sans AAD ;
  2. un coffre cree par `vault.Vault` (le code de l'application) se relit a
     l'identique, y compris un coffre aux anciens parametres scrypt ;
  3. un mot de passe faux et un octet altere sont REFUSES, sans rien rendre ;
  4. le coffre n'est jamais modifie (lecture seule, aucun fichier a cote) ;
  5. le script ne depend que de la bibliotheque standard — on le mesure sur
     ses imports, pas sur une affirmation.
"""
import ast
import csv
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import crypto
import secours_coffre as secours
from vault import Vault

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover
    AESGCM = None


class TestAesGcmPurPython(unittest.TestCase):
    @unittest.skipIf(AESGCM is None, "cryptography absente : rien a comparer")
    def test_identique_a_cryptography_sur_des_vecteurs_aleatoires(self):
        for i in range(60):
            k, n = os.urandom(32), os.urandom(12)
            m = os.urandom((i * 13) % 97)          # de 0 a 96 octets : blocs entiers et partiels
            aad = os.urandom(i % 7)
            ct = AESGCM(k).encrypt(n, m, aad or None)
            self.assertEqual(secours.aes_gcm_dechiffrer(k, n, ct, aad), m, f"vecteur {i}")

    @unittest.skipIf(AESGCM is None, "cryptography absente")
    def test_un_nonce_hors_12_octets_est_gere_comme_la_norme(self):
        k, n, m = os.urandom(32), os.urandom(16), b"nonce de 16 octets"
        self.assertEqual(secours.aes_gcm_dechiffrer(k, n, AESGCM(k).encrypt(n, m, None)), m)

    @unittest.skipIf(AESGCM is None, "cryptography absente")
    def test_une_etiquette_ou_un_octet_altere_est_refuse(self):
        k, n = os.urandom(32), os.urandom(12)
        ct = AESGCM(k).encrypt(n, b"secret " * 5, None)
        for position in (0, len(ct) // 2, len(ct) - 1):
            altere = bytearray(ct)
            altere[position] ^= 0x01
            with self.assertRaises(secours.CoffreIllisible, msg=f"octet {position}"):
                secours.aes_gcm_dechiffrer(k, n, bytes(altere))

    def test_un_texte_trop_court_est_refuse(self):
        with self.assertRaises(secours.CoffreIllisible):
            secours.aes_gcm_dechiffrer(b"k" * 32, b"n" * 12, b"court")


class TestScrypt(unittest.TestCase):
    def test_la_cle_derivee_est_celle_de_l_application(self):
        sel = os.urandom(16)
        attendue = crypto.derive_key("mot-de-passe-maitre", sel, n=2 ** 14, r=8, p=1)
        self.assertEqual(secours.deriver_cle("mot-de-passe-maitre", sel, 2 ** 14, 8, 1), attendue)


class TestVraiCoffre(unittest.TestCase):
    """Un coffre cree par l'APPLICATION, relu par le script."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.chemin = Path(self._tmp.name) / "coffre.sqlite"
        self.vault = Vault(self.chemin)
        self.vault.create("mot-de-passe-maitre")
        self.vault.add_entry(title="Banque", username="jean", password="p@ss", url="https://banque.fr", notes="compte courant")
        self.vault.add_entry(title="Mél", username="jean@exemple.fr", password="autre", url="", notes="", totp="JBSWY3DPEHPK3PXP")
        self.vault.lock()

    def tearDown(self):
        # `lock()` ne ferme pas la connexion SQLite ; `close()` oui. Sans elle,
        # Windows refuse de supprimer le dossier temporaire (fichier « utilisé
        # par un autre processus ») et le nettoyage fait echouer le test.
        try:
            self.vault.close()
        except Exception:
            pass
        self._tmp.cleanup()

    def test_relit_toutes_les_entrees_a_l_identique(self):
        entrees = secours.lire_coffre(self.chemin, "mot-de-passe-maitre")
        self.assertEqual([e["title"] for e in entrees], ["Banque", "Mél"])
        self.assertEqual(entrees[0]["password"], "p@ss")
        self.assertEqual(entrees[0]["notes"], "compte courant")
        self.assertEqual(entrees[1]["totp"], "JBSWY3DPEHPK3PXP")
        self.assertEqual(set(entrees[0]), set(secours.CHAMPS))

    def test_un_mot_de_passe_faux_est_refuse_sans_rien_rendre(self):
        with self.assertRaises(secours.CoffreIllisible) as cm:
            secours.lire_coffre(self.chemin, "pas-le-bon")
        self.assertIn("mot de passe", str(cm.exception))

    def test_un_octet_altere_dans_une_entree_est_refuse(self):
        import sqlite3
        conn = sqlite3.connect(self.chemin)
        ct = bytearray(conn.execute("SELECT ciphertext FROM entries WHERE id = 1").fetchone()[0])
        ct[3] ^= 0x01
        conn.execute("UPDATE entries SET ciphertext = ? WHERE id = 1", (bytes(ct),))
        conn.commit()
        conn.close()
        with self.assertRaises(secours.CoffreIllisible):
            secours.lire_coffre(self.chemin, "mot-de-passe-maitre")

    def test_le_coffre_n_est_pas_modifie_et_rien_n_est_cree_a_cote(self):
        avant = hashlib.sha256(self.chemin.read_bytes()).hexdigest()
        fichiers_avant = sorted(p.name for p in self.chemin.parent.iterdir())
        secours.lire_coffre(self.chemin, "mot-de-passe-maitre")
        self.assertEqual(hashlib.sha256(self.chemin.read_bytes()).hexdigest(), avant)
        self.assertEqual(sorted(p.name for p in self.chemin.parent.iterdir()), fichiers_avant,
                         "un -journal ou -wal est apparu : le coffre n'a pas ete ouvert en lecture seule")

    def test_un_coffre_aux_anciens_parametres_scrypt_se_relit(self):
        """Les parametres sont LUS dans vault_meta, jamais supposes : un coffre
        cree avant l'augmentation de N (2^16 -> 2^17) doit s'ouvrir."""
        chemin = Path(self._tmp.name) / "ancien.sqlite"
        v = Vault(chemin)
        # On force les anciens parametres comme l'application les stockait.
        import db as dbmod
        sel = crypto.generate_salt()
        cle = crypto.derive_key("vieux-mdp", sel, n=crypto.LEGACY_SCRYPT_N, r=crypto.LEGACY_SCRYPT_R, p=crypto.LEGACY_SCRYPT_P)
        nonce, ct = crypto.encrypt(cle, b"coffre-verifier-v1")
        v.db.set_vault_meta(sel, nonce, ct, crypto.LEGACY_SCRYPT_N, crypto.LEGACY_SCRYPT_R, crypto.LEGACY_SCRYPT_P)
        n2, c2 = crypto.encrypt(cle, json.dumps({"title": "Ancien", "username": "u", "password": "p", "url": "", "notes": ""}).encode())
        v.db.add_entry(n2, c2)
        v.db.conn.commit() if hasattr(v.db, "conn") else None
        # Fermé ICI, pas en addCleanup : les cleanups passent APRÈS tearDown,
        # qui supprime le dossier — et Windows refuse tant que le fichier est ouvert.
        v.close()
        entrees = secours.lire_coffre(chemin, "vieux-mdp")
        self.assertEqual(entrees[0]["title"], "Ancien")
        self.assertEqual(entrees[0]["totp"], "", "un champ absent du JSON ancien est complete a vide")

    def test_export_json_et_csv(self):
        sortie = Path(self._tmp.name)
        code = secours.main([str(self.chemin), "--mot-de-passe", "mot-de-passe-maitre",
                             "--json", str(sortie / "s.json"), "--csv", str(sortie / "s.csv")])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads((sortie / "s.json").read_text(encoding="utf-8"))[0]["title"], "Banque")
        with open(sortie / "s.csv", encoding="utf-8", newline="") as f:
            lignes = list(csv.DictReader(f))
        self.assertEqual(lignes[1]["totp"], "JBSWY3DPEHPK3PXP")

    def test_un_mauvais_mot_de_passe_en_ligne_de_commande_sort_en_2(self):
        self.assertEqual(secours.main([str(self.chemin), "--mot-de-passe", "faux"]), 2)


class TestAutonomie(unittest.TestCase):
    def test_le_script_n_importe_que_la_bibliotheque_standard(self):
        """Mesure sur l'ARBRE SYNTAXIQUE : un `import cryptography` glisse dans
        une fonction serait vu aussi. `sys.stdlib_module_names` fait foi."""
        source = (Path(__file__).resolve().parent.parent / "secours_coffre.py").read_text(encoding="utf-8")
        modules = set()
        for noeud in ast.walk(ast.parse(source)):
            if isinstance(noeud, ast.Import):
                modules |= {a.name.split(".")[0] for a in noeud.names}
            elif isinstance(noeud, ast.ImportFrom) and noeud.module:
                modules.add(noeud.module.split(".")[0])
        hors_stdlib = sorted(m for m in modules if m not in sys.stdlib_module_names)
        self.assertEqual(hors_stdlib, [], f"dependances hors bibliotheque standard : {hors_stdlib}")


if __name__ == "__main__":
    unittest.main()
