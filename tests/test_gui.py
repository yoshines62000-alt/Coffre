"""Tests pour gui.py.

Convention du projet : toute modification touchant gui.py doit etre
verifiee par un smoke test de bout en bout pilotant la VRAIE GUI Tkinter
(vraie Tk(), vrais widgets, vrai Vault sur un fichier temporaire) - seuls
tkinter.messagebox/filedialog/simpledialog sont mockes, jamais tkinter
lui-meme ni vault.py. Les tests ci-dessous couvrent trois correctifs/ajouts
trouves a l'audit :

1. Le Spinbox de longueur du generateur reste editable en texte libre et
   `do_generate` doit rattraper la TclError que leve alors
   `length_var.get()`, en plus d'une validation d'entree a la saisie.
2. Les dialogues "mots de passe reutilises"/"mots de passe faibles"
   doivent permettre d'ouvrir directement une entree listee en edition
   d'un clic.
3. Une banniere d'avertissement non-bloquante doit apparaitre dans les
   AUTO_LOCK_WARNING_SECONDS dernieres secondes avant le verrouillage
   automatique par inactivite, sans jamais retarder ce verrouillage."""

import sys
import tempfile
import time
import tkinter as tk
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import gui
from gui import AUTO_LOCK_SECONDS, AUTO_LOCK_WARNING_SECONDS, CoffreApp, _is_valid_length_input


def _find_widget(widget, predicate):
    """Recherche recursive du premier widget descendant (widget compris)
    qui satisfait `predicate(widget)`, ou None."""
    if predicate(widget):
        return widget
    for child in widget.winfo_children():
        found = _find_widget(child, predicate)
        if found is not None:
            return found
    return None


def _find_button(widget, text):
    return _find_widget(widget, lambda w: w.winfo_class() == "TButton" and w.cget("text") == text)


def _find_spinbox(widget):
    return _find_widget(widget, lambda w: w.winfo_class() == "TSpinbox")


def _find_readonly_entry(widget):
    return _find_widget(widget, lambda w: w.winfo_class() == "TEntry" and str(w.cget("state")) == "readonly")


def _find_label_with_text(widget, text):
    return _find_widget(widget, lambda w: w.winfo_class() == "TLabel" and str(w.cget("text")) == text)


def _is_packed(widget):
    # winfo_ismapped() depend de la visibilite effective a l'ecran de tous
    # les ancetres (donc faux si root est withdraw() dans les tests, meme
    # correctement pack()) - winfo_manager() refllete uniquement l'etat
    # d'enregistrement aupres du gestionnaire de geometrie ("pack" une fois
    # pack() appele, "" apres pack_forget()), independant de la visibilite.
    return widget.winfo_manager() == "pack"


class GuiTestCase(unittest.TestCase):
    """Base commune : construit une vraie CoffreApp sur un coffre neuf dans
    un dossier temporaire (jamais le vrai dossier AppData/Roaming/Coffre de
    l'utilisateur), le cree puis l'ouvre directement sur l'ecran principal -
    equivalent a ce que fait la vraie GUI apres creation/deverrouillage."""

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.root = tk.Tk()
        self.root.withdraw()
        with patch.object(gui, "_data_dir", return_value=self.tmp_dir):
            self.app = CoffreApp(self.root)
        self.app.vault.create("mot-de-passe-maitre-de-test")
        self.app._show_vault_screen()
        self.root.update()
        # _show_vault_screen programme le controle periodique d'auto-lock
        # (root.after(1000, ...)) : annule-le tout de suite, la plupart des
        # tests ne le concernent pas et un test un peu lent pourrait sinon
        # le laisser se declencher (et se reprogrammer) pendant le test,
        # jusqu'a potentiellement chevaucher la destruction de root en fin
        # de test. AutoLockWarningTestCase pilote _check_auto_lock() lui-
        # meme, manuellement, et n'a donc pas besoin de ce minuteur non plus.
        if self.app._auto_lock_job is not None:
            self.root.after_cancel(self.app._auto_lock_job)
            self.app._auto_lock_job = None
        self.addCleanup(self._teardown)

    def _teardown(self):
        # Ferme proprement tout dialogue/thread encore ouvert avant de
        # detruire root : sans ca, un `after()` deja programme (auto-lock,
        # effacement du presse-papier) pourrait s'executer sur un
        # interpreteur Tcl detruit lors du test suivant.
        try:
            if self.app._auto_lock_job is not None:
                self.root.after_cancel(self.app._auto_lock_job)
        except Exception:
            pass
        try:
            self.app._close_all_dialogs()
        except Exception:
            pass
        try:
            self.app.vault.close()
        except Exception:
            pass
        try:
            self.root.destroy()
        except Exception:
            pass


class LengthInputValidationTestCase(unittest.TestCase):
    """_is_valid_length_input est la fonction pure branchee comme
    validatecommand="key" sur le Spinbox - testable independamment de Tk."""

    def test_accepts_digits(self):
        self.assertTrue(_is_valid_length_input("4"))
        self.assertTrue(_is_valid_length_input("128"))

    def test_accepts_the_empty_string_mid_edit(self):
        self.assertTrue(_is_valid_length_input(""))

    def test_rejects_letters(self):
        self.assertFalse(_is_valid_length_input("abc"))
        self.assertFalse(_is_valid_length_input("2a"))

    def test_rejects_a_leading_minus_sign(self):
        self.assertFalse(_is_valid_length_input("-1"))


class GeneratorDialogSmokeTestCase(GuiTestCase):
    def test_the_spinbox_is_wired_to_reject_free_text_at_the_keystroke_level(self):
        self.app._open_generator_dialog()
        dialog = self.app._open_dialogs[-1]
        self.root.update()
        spinbox = _find_spinbox(dialog)
        self.assertEqual(str(spinbox.cget("validate")), "key")
        self.assertTrue(str(spinbox.cget("validatecommand")))

        spinbox.focus_set()
        spinbox.icursor("end")
        spinbox.insert("end", "x")
        self.root.update()
        self.assertNotIn("x", spinbox.get())
        dialog.destroy()

    def test_regenerate_with_a_non_numeric_length_warns_instead_of_crashing(self):
        self.app._open_generator_dialog()
        dialog = self.app._open_dialogs[-1]
        self.root.update()
        spinbox = _find_spinbox(dialog)
        # Contourne volontairement la validation "key" pour reproduire
        # l'etat qui, avant correctif, faisait remonter une TclError non
        # rattrapee hors du callback du bouton "Regenerer" (avale
        # silencieusement par Tkinter dans l'executable package sans
        # console : le bouton semblait ne rien faire).
        spinbox.configure(validate="none")
        spinbox.delete(0, "end")
        spinbox.insert(0, "abc")
        self.root.update()

        regen_button = _find_button(dialog, "Regenerer")
        with patch("gui.messagebox.showwarning") as mock_warn:
            regen_button.invoke()
            self.root.update()

        mock_warn.assert_called_once()
        self.assertTrue(dialog.winfo_exists())
        dialog.destroy()

    def test_regenerate_with_an_empty_length_field_warns_instead_of_crashing(self):
        self.app._open_generator_dialog()
        dialog = self.app._open_dialogs[-1]
        self.root.update()
        spinbox = _find_spinbox(dialog)
        spinbox.delete(0, "end")  # champ vide : autorise par la validation "key"
        self.root.update()

        regen_button = _find_button(dialog, "Regenerer")
        with patch("gui.messagebox.showwarning") as mock_warn:
            regen_button.invoke()
            self.root.update()

        mock_warn.assert_called_once()
        dialog.destroy()

    def test_regenerate_with_a_valid_length_still_produces_a_password(self):
        self.app._open_generator_dialog()
        dialog = self.app._open_dialogs[-1]
        self.root.update()
        spinbox = _find_spinbox(dialog)
        spinbox.delete(0, "end")
        spinbox.insert(0, "12")
        regen_button = _find_button(dialog, "Regenerer")
        with patch("gui.messagebox.showwarning") as mock_warn:
            regen_button.invoke()
            self.root.update()

        mock_warn.assert_not_called()
        result_entry = _find_readonly_entry(dialog)
        self.assertEqual(len(result_entry.get()), 12)
        dialog.destroy()


class ListingDialogsClickableEntriesTestCase(GuiTestCase):
    def test_clicking_a_reused_password_entry_opens_it_for_editing(self):
        self.app.vault.add_entry("Site A", username="alice", password="mot-partage-123")
        self.app.vault.add_entry("Site B", username="bob", password="mot-partage-123")
        self.app._refresh_entries()

        self.app._open_reused_passwords_dialog()
        listing_dialog = self.app._open_dialogs[-1]
        self.root.update()

        label = _find_label_with_text(listing_dialog, "- Site A")
        self.assertIsNotNone(label, "l'entree 'Site A' devrait apparaitre, cliquable, dans le dialogue")
        self.assertEqual(str(label.cget("cursor")), "hand2")

        label.event_generate("<Button-1>")
        self.root.update()

        self.assertFalse(listing_dialog.winfo_exists(), "le dialogue de listing doit se fermer au clic")
        entry_dialog = self.app._open_dialogs[-1]
        self.assertTrue(entry_dialog.winfo_exists())
        self.assertEqual(entry_dialog.title(), "Modifier l'entree")
        title_entry = entry_dialog.grid_slaves(row=0, column=1)[0]
        self.assertEqual(title_entry.get(), "Site A")
        entry_dialog.destroy()

    def test_clicking_a_weak_password_entry_opens_it_for_editing(self):
        self.app.vault.add_entry("Faible", username="carol", password="123")
        self.app._refresh_entries()

        self.app._open_weak_passwords_dialog()
        listing_dialog = self.app._open_dialogs[-1]
        self.root.update()

        label = _find_label_with_text(listing_dialog, "- Faible - Solidite : Tres faible")
        self.assertIsNotNone(label)

        label.event_generate("<Button-1>")
        self.root.update()

        self.assertFalse(listing_dialog.winfo_exists())
        entry_dialog = self.app._open_dialogs[-1]
        self.assertEqual(entry_dialog.title(), "Modifier l'entree")
        title_entry = entry_dialog.grid_slaves(row=0, column=1)[0]
        self.assertEqual(title_entry.get(), "Faible")
        entry_dialog.destroy()

    def test_the_reused_passwords_dialog_still_handles_the_empty_case(self):
        self.app._open_reused_passwords_dialog()
        dialog = self.app._open_dialogs[-1]
        self.root.update()
        self.assertIsNotNone(_find_label_with_text(dialog, "Aucun mot de passe n'est reutilise entre plusieurs entrees."))
        dialog.destroy()


class AutoLockWarningTestCase(GuiTestCase):
    def setUp(self):
        super().setUp()
        # Reprend le controle du minuteur : les tests pilotent
        # manuellement _last_activity et appellent _check_auto_lock() eux-
        # memes plutot que d'attendre le vrai delai de 5 minutes.
        if self.app._auto_lock_job is not None:
            self.root.after_cancel(self.app._auto_lock_job)
            self.app._auto_lock_job = None

    def test_no_warning_when_activity_is_recent(self):
        self.app._last_activity = time.monotonic()
        self.app._check_auto_lock()
        self.root.update()
        self.assertFalse(_is_packed(self.app._auto_lock_warning_label))

    def test_warning_appears_inside_the_warning_window(self):
        self.app._last_activity = time.monotonic() - (AUTO_LOCK_SECONDS - 10)
        self.app._check_auto_lock()
        self.root.update()
        self.assertTrue(_is_packed(self.app._auto_lock_warning_label))
        self.assertIn("verrouiller automatiquement", self.app._auto_lock_warning_var.get())
        self.assertTrue(self.app.vault.is_unlocked, "l'avertissement seul ne doit jamais verrouiller le coffre")

    def test_warning_disappears_again_once_activity_is_detected(self):
        self.app._last_activity = time.monotonic() - (AUTO_LOCK_SECONDS - 10)
        self.app._check_auto_lock()
        self.root.update()
        self.assertTrue(_is_packed(self.app._auto_lock_warning_label))

        self.app._reset_activity_timer()
        self.app._check_auto_lock()
        self.root.update()
        self.assertFalse(_is_packed(self.app._auto_lock_warning_label))

    def test_the_vault_still_locks_unconditionally_once_the_delay_elapses(self):
        self.app._last_activity = time.monotonic() - AUTO_LOCK_SECONDS - 1
        self.app._check_auto_lock()
        self.root.update()
        self.assertFalse(self.app.vault.is_unlocked)
        self.assertFalse(_is_packed(self.app._auto_lock_warning_label))

    def test_an_open_dialog_is_force_closed_when_the_delay_elapses_even_mid_warning(self):
        self.app._open_generator_dialog()
        dialog = self.app._open_dialogs[-1]
        self.root.update()

        self.app._last_activity = time.monotonic() - (AUTO_LOCK_SECONDS - 5)
        self.app._check_auto_lock()
        self.root.update()
        self.assertTrue(dialog.winfo_exists(), "encore dans la fenetre d'avertissement : pas encore verrouille")

        self.app._last_activity = time.monotonic() - AUTO_LOCK_SECONDS - 1
        self.app._check_auto_lock()
        self.root.update()
        self.assertFalse(dialog.winfo_exists(), "le verrouillage reel doit fermer de force les dialogues ouverts")


if __name__ == "__main__":
    unittest.main()
