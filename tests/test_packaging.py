"""Tests pour la configuration de packaging (PyInstaller).

Aucun code applicatif ici, mais des regressions silencieuses sont faciles
sur ce genre de fichier de configuration statique : personne ne le
remarque tant que l'executable n'est pas reconstruit puis inspecte
manuellement via les proprietes Windows.

Correctif audit D2 : l'executable distribue n'embarquait aucune metadonnee
de version Windows (FileVersion/ProductVersion/CompanyName/FileDescription/
LegalCopyright... tous vides ou a 0.0.0.0 dans l'onglet "Details" des
proprietes du fichier), reduisant encore la confiance perceptible d'un
utilisateur prudent deja entamee par l'absence de signature Authenticode
(D3, hors perimetre). `version_info.txt` et sa reference dans Coffre.spec
corrigent ca. Ces tests verrouillent la coherence entre APP_VERSION
(gui.py), version_info.txt et Coffre.spec, sans necessiter de reconstruire
l'executable lui-meme (qui reste un exercice manuel, hors CI/tests)."""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gui import APP_VERSION

REPO_ROOT = Path(__file__).resolve().parent.parent


class VersionResourceFileTestCase(unittest.TestCase):
    def setUp(self):
        self.version_info_path = REPO_ROOT / "version_info.txt"
        self.spec_path = REPO_ROOT / "Coffre.spec"

    def test_version_info_file_exists(self):
        self.assertTrue(
            self.version_info_path.exists(),
            "version_info.txt doit exister a la racine du depot (constat d'audit D2)",
        )

    def test_coffre_spec_references_the_version_resource_file(self):
        spec_text = self.spec_path.read_text(encoding="utf-8").replace('"', "'")
        self.assertIn(
            "version='version_info.txt'", spec_text,
            "Coffre.spec doit passer version='version_info.txt' a EXE(...) pour que "
            "le prochain build embarque les metadonnees de version",
        )

    def test_version_info_strings_match_app_version(self):
        text = self.version_info_path.read_text(encoding="utf-8")
        file_versions = re.findall(r"StringStruct\(u?'FileVersion',\s*u?'([^']+)'\)", text)
        product_versions = re.findall(r"StringStruct\(u?'ProductVersion',\s*u?'([^']+)'\)", text)
        self.assertEqual(
            file_versions, [APP_VERSION],
            "FileVersion (version_info.txt) doit rester synchronise avec APP_VERSION (gui.py) a chaque publication",
        )
        self.assertEqual(
            product_versions, [APP_VERSION],
            "ProductVersion (version_info.txt) doit rester synchronise avec APP_VERSION (gui.py) a chaque publication",
        )

    def test_version_info_filevers_and_prodvers_tuples_match_app_version(self):
        text = self.version_info_path.read_text(encoding="utf-8")
        expected = [int(part) for part in APP_VERSION.split(".")] + [0]
        for field in ("filevers", "prodvers"):
            match = re.search(rf"{field}=\(([^)]+)\)", text)
            self.assertIsNotNone(match, f"{field} introuvable dans version_info.txt")
            parts = [int(p.strip()) for p in match.group(1).split(",")]
            self.assertEqual(parts, expected, f"{field} doit correspondre a APP_VERSION={APP_VERSION!r}")

    def test_version_info_declares_the_expected_product_identity(self):
        text = self.version_info_path.read_text(encoding="utf-8")
        self.assertIn("StringStruct(u'ProductName', u'Coffre')", text)
        self.assertIn("StringStruct(u'OriginalFilename', u'Coffre.exe')", text)

    def test_version_info_file_parses_with_pyinstaller_when_available(self):
        # Validation la plus forte possible sans reconstruire l'executable :
        # fait rejouer a PyInstaller lui-meme son propre mini-parseur sur ce
        # fichier, plutot que de se fier uniquement aux regex ci-dessus.
        try:
            from PyInstaller.utils.win32.versioninfo import load_version_info_from_text_file
        except ImportError:
            self.skipTest("PyInstaller n'est pas installe dans cet environnement de test")
        version_info = load_version_info_from_text_file(str(self.version_info_path))
        self.assertIsNotNone(version_info)


if __name__ == "__main__":
    unittest.main()
