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

import sqlite3
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


class ToolbarLayoutTestCase(GuiTestCase):
    """Correctif audit Phase 1 (item 1) : a la taille par defaut de la
    fenetre (900x580, fixee dans CoffreApp.__init__), la toolbar du haut
    demandait 1132px de large (mesure reelle a l'audit via
    top.winfo_reqwidth()) contre 900px disponibles - un depassement de
    232px (26%) qui faisait sortir "Verrouiller maintenant" (tronque) et
    "Changer le mot de passe maitre..." (totalement invisible) du cadre
    visible, sans scrollbar ni indication. La toolbar est desormais
    repartie sur deux rangees ; chacune doit tenir dans la largeur par
    defaut de la fenetre, et tous les boutons doivent rester geres par le
    gestionnaire de geometrie (donc effectivement affiches)."""

    ALL_TOOLBAR_BUTTONS = [
        "Generateur...",
        "Mots de passe reutilises...",
        "Mots de passe faibles...",
        "Sauvegarder une copie...",
        "Verrouiller maintenant",
        "Changer le mot de passe maitre...",
    ]

    def test_every_toolbar_button_is_present_and_packed(self):
        self.root.update_idletasks()
        for text in self.ALL_TOOLBAR_BUTTONS:
            button = _find_button(self.app.vault_frame, text)
            self.assertIsNotNone(button, f"bouton introuvable : {text}")
            self.assertEqual(button.winfo_manager(), "pack", f"bouton non affiche : {text}")

    def test_each_toolbar_row_fits_within_the_default_window_width(self):
        self.root.update_idletasks()
        default_width = 900  # gui.CoffreApp.__init__ : self.root.geometry("900x580")

        lock_button = _find_button(self.app.vault_frame, "Verrouiller maintenant")
        change_password_button = _find_button(self.app.vault_frame, "Changer le mot de passe maitre...")
        top_row = lock_button.master
        bottom_row = change_password_button.master
        self.assertIsNot(top_row, bottom_row, "les actions secondaires doivent etre sur une rangee separee")

        top_row_width = top_row.winfo_reqwidth()
        bottom_row_width = bottom_row.winfo_reqwidth()
        self.assertLessEqual(
            top_row_width, default_width,
            f"rangee du haut trop large ({top_row_width}px) pour la fenetre par defaut ({default_width}px)",
        )
        self.assertLessEqual(
            bottom_row_width, default_width,
            f"rangee du bas trop large ({bottom_row_width}px) pour la fenetre par defaut ({default_width}px)",
        )

    def test_verrouiller_maintenant_is_not_visually_truncated(self):
        # Avant correctif, ce bouton s'affichait tronque en "Verrouiller n"
        # car il sortait partiellement du cadre visible de la fenetre.
        self.root.update_idletasks()
        button = _find_button(self.app.vault_frame, "Verrouiller maintenant")
        self.assertEqual(button.cget("text"), "Verrouiller maintenant")


class DiskWriteFailureTestCase(GuiTestCase):
    """Correctif audit Phase 1 (item 2) : un echec d'ecriture disque
    (disque plein -> sqlite3.OperationalError, ou toute autre erreur
    OSError/ValueError/sqlite3.Error) lors de l'ajout, la modification ou
    la suppression d'une entree remontait auparavant totalement non
    intercepte hors du callback Tkinter - invisible dans l'exe package
    sans console (Coffre.spec, console=False). Reproduit ici en cassant
    directement l'ecriture DB sous-jacente, comme le fait deja
    tests/test_vault.py::test_a_storage_failure_during_change_master_password_leaves_the_old_password_working
    pour le changement de mot de passe maitre."""

    def test_add_entry_failure_shows_an_error_instead_of_crashing_silently(self):
        self.app._open_entry_dialog(None)
        dialog = self.app._open_dialogs[-1]
        self.root.update()

        title_entry = _find_widget(dialog, lambda w: w.winfo_class() == "TEntry")
        title_entry.focus_set()
        title_entry.insert(0, "Nouveau site")
        self.root.update()

        save_button = _find_button(dialog, "Enregistrer")
        with patch.object(self.app.vault.db, "add_entry", side_effect=sqlite3.OperationalError("database or disk is full")):
            with patch("gui.messagebox.showerror") as mock_error:
                save_button.invoke()
                self.root.update()

        mock_error.assert_called_once()
        self.assertIn("disk is full", str(mock_error.call_args))
        # Le dialogue reste ouvert (pas de destroy()) : l'utilisateur ne
        # perd pas la saisie deja faite et peut reessayer.
        self.assertTrue(dialog.winfo_exists())
        self.assertEqual(len(self.app.vault.list_entries()), 0, "aucune entree ne doit avoir ete ajoutee")
        dialog.destroy()

    def test_update_entry_failure_shows_an_error_instead_of_crashing_silently(self):
        entry_id = self.app.vault.add_entry("Site existant", username="alice", password="secret")
        self.app._refresh_entries()

        self.app._open_entry_dialog(entry_id)
        dialog = self.app._open_dialogs[-1]
        self.root.update()

        save_button = _find_button(dialog, "Enregistrer")
        with patch.object(self.app.vault.db, "update_entry", side_effect=sqlite3.OperationalError("database or disk is full")):
            with patch("gui.messagebox.showerror") as mock_error:
                save_button.invoke()
                self.root.update()

        mock_error.assert_called_once()
        dialog.destroy()

    def test_delete_entry_failure_shows_an_error_instead_of_crashing_silently(self):
        entry_id = self.app.vault.add_entry("Site a supprimer", username="alice", password="secret")
        self.app._refresh_entries()
        self.app.entries_tree.selection_set(str(entry_id))
        self.root.update()

        with patch.object(self.app.vault.db, "delete_entry", side_effect=sqlite3.OperationalError("database or disk is full")):
            with patch("gui.messagebox.askyesno", return_value=True):
                with patch("gui.messagebox.showerror") as mock_error:
                    self.app._delete_selected_entry()
                    self.root.update()

        mock_error.assert_called_once()
        self.assertIn("disk is full", str(mock_error.call_args))
        self.assertEqual(len(self.app.vault.list_entries()), 1, "l'entree ne doit pas avoir disparu de la liste en memoire")


if __name__ == "__main__":
    unittest.main()
