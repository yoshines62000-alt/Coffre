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

import ctypes
import os
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


def _label_display_text(widget):
    """Texte actuellement affiche par un ttk.Label, qu'il soit fixe
    (option "text", ce que lit deja _find_label_with_text ci-dessus) ou
    dynamique (option "textvariable" - "text" seul ne reflete PAS la
    valeur courante de la variable, il faut la resoudre via Tcl)."""
    var_name = str(widget.cget("textvariable"))
    if var_name:
        return widget.tk.globalgetvar(var_name)
    return str(widget.cget("text"))


def _find_label_with_dynamic_text(widget, text):
    return _find_widget(
        widget, lambda w: w.winfo_class() == "TLabel" and _label_display_text(w) == text,
    )


def _is_packed(widget):
    # winfo_ismapped() depend de la visibilite effective a l'ecran de tous
    # les ancetres (donc faux si root est withdraw() dans les tests, meme
    # correctement pack()) - winfo_manager() refllete uniquement l'etat
    # d'enregistrement aupres du gestionnaire de geometrie ("pack" une fois
    # pack() appele, "" apres pack_forget()), independant de la visibilite.
    return widget.winfo_manager() == "pack"


def _wait_for_real_focus(root, widget, timeout=2.0):
    """Force et attend que `widget` recoive reellement le focus clavier Tk
    (pas seulement l'intention enregistree par focus_set()), ou renvoie
    False au bout de `timeout` secondes.

    Constat de debogage (correctifs C3/C10) : dans cet environnement de
    test (aucune session de bureau interactive reelle derriere le
    processus qui execute les tests), une fenetre root.withdraw()'ee -
    l'etat par defaut de GuiTestCase.setUp - ou une Toplevel qui vient
    d'etre creee ne recoit jamais le "vrai" focus d'entree Tk tant
    qu'aucune fenetre de l'application n'a ete effectivement activee par
    le systeme d'exploitation. focus_set() seul n'y suffit pas : Tk se
    contente alors de MEMORISER le choix (visible via `focus -lastfor`)
    sans jamais l'appliquer puisque la fenetre n'a jamais ete
    mappee/activee - root.focus_get() continue de renvoyer None (ou la
    racine '.') indefiniment, et un event_generate("<Return>") synthetise
    sur le widget vise est alors livre a la fenetre reellement active
    (root, ou rien), jamais au widget attendu - ce qui, avant ce correctif
    de test, faisait echouer silencieusement (sans aucune exception) les
    assertions de EnterKeySubmitsFormsTestCase et de
    test_the_password_field_regains_focus_after_a_wrong_password alors que
    le code produit (gui.py) lui-meme est correct. root.deiconify() (deja
    utilise par ActionsColumnLayoutTestCase._resize_to_minsize pour un
    probleme de geometrie analogue) + focus_force() + un veritable
    ecoulement de temps reel entre plusieurs root.update() (l'activation
    de fenetre par l'OS est asynchrone, un seul root.update() immediatement
    apres focus_force() ne suffit pas de facon fiable) rendent ce
    comportement reproductible."""
    root.deiconify()
    widget.winfo_toplevel().lift()
    widget.focus_force()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        root.update()
        if root.focus_get() is widget:
            return True
        time.sleep(0.02)
    return False


def _press_return(root, widget):
    """Simule une touche Entree reellement recue par `widget` (passe par
    _wait_for_real_focus ci-dessus, sans quoi l'evenement synthetise ne
    serait pas livre au bon widget dans cet environnement de test)."""
    got_focus = _wait_for_real_focus(root, widget)
    assert got_focus, (
        f"{widget} n'a jamais recu le focus clavier reel dans le delai "
        "imparti - environnement de test sans activation de fenetre reelle ?"
    )
    widget.event_generate("<Return>")
    root.update()


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
        # Audit E3 : meme raison que pour _auto_lock_job juste au-dessus -
        # le timer de sondage de mise a jour (_poll_update_check) se
        # reprogramme tant que le thread reseau (jusqu'a 5s de timeout) n'a
        # rien depose dans la file, et survivait donc frequemment a la
        # destruction de root en fin de test (erreurs Tcl "invalid command
        # name" observees a l'audit). Le vrai correctif est cote produit
        # (_on_close), mais l'annuler aussi ici evite le bruit sur CETTE
        # instance de Tk() qui n'est jamais fermee via _on_close.
        if getattr(self.app, "_update_check_job", None) is not None:
            self.root.after_cancel(self.app._update_check_job)
            self.app._update_check_job = None
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
            if getattr(self.app, "_update_check_job", None) is not None:
                self.root.after_cancel(self.app._update_check_job)
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


class ActionsColumnLayoutTestCase(GuiTestCase):
    """Correctif audit C2 : a la taille minimale de fenetre que
    l'application declare elle-meme supporter (root.minsize(750, 450)), le
    gestionnaire de geometrie "pack" de Tk allouait l'espace disponible dans
    l'ORDRE DES APPELS a pack() plutot que par "side" - entries_tree, empa-
    quete en premier avec expand=True, accaparait systematiquement toute sa
    largeur demandee (660px, somme des largeurs de colonnes declarees),
    laissant a la colonne "actions" (empaquetee en dernier, sans expand) les
    quelques pixels restants une fois la fenetre trop etroite. Mesure reelle
    a l'audit : a 750px de large, "actions" ne recevait plus que 40px sur
    131px requis, tronquant simultanement "Copier l'identifiant" ET
    "Copier le mot de passe" au meme libelle affiche "Copie", rendant les
    deux boutons indiscernables - risque concret de copier le mauvais
    secret (identifiant vs mot de passe) au mauvais endroit. Le correctif
    empaquete desormais "actions" et la scrollbar (a droite) AVANT
    entries_tree, qui absorbe seul toute reduction de largeur en dernier."""

    def _resize_to_minsize(self):
        # winfo_width()/winfo_reqwidth() ne refletent la geometrie reelle
        # negociee par le gestionnaire de fenetres que si la fenetre est
        # effectivement mappee a l'ecran - un root.withdraw() (etat par
        # defaut de GuiTestCase, pour ne pas faire clignoter de fenetre
        # visible pendant la suite de tests) fige la largeur a la derniere
        # geometrie appliquee avant le withdraw et root.geometry() n'a alors
        # plus aucun effet mesurable sur winfo_width(). On re-affiche donc
        # temporairement la fenetre pour ce test precis, ce qui reproduit
        # fidelement les conditions de l'audit visuel original (vraie
        # fenetre Tk mappee, redimensionnee a root.minsize()).
        min_width, min_height = self.root.wm_minsize()
        self.root.deiconify()
        self.root.geometry(f"{min_width}x{min_height}")
        self.root.update_idletasks()
        self.root.update()

    def test_actions_column_keeps_its_full_requested_width_at_minsize(self):
        self._resize_to_minsize()
        add_button = _find_button(self.app.vault_frame, "Ajouter...")
        actions = add_button.master
        self.assertGreaterEqual(
            actions.winfo_width(), actions.winfo_reqwidth(),
            "la colonne d'actions est comprimee en dessous de sa largeur "
            "requise a la taille minimale de fenetre declaree par l'application",
        )

    def test_action_buttons_stay_distinguishable_at_minsize(self):
        # Verifie individuellement chaque bouton plutot que la seule frame
        # englobante : c'est bien le texte de CHAQUE bouton qui doit rester
        # entierement affiche, "Copier l'identifiant" et "Copier le mot de
        # passe" en particulier, dont les libelles tronques a 4-5 caracteres
        # ("Copie") devenaient identiques et donc indiscernables a l'ecran.
        self._resize_to_minsize()
        for text in [
            "Ajouter...", "Modifier...", "Supprimer",
            "Copier l'identifiant", "Copier le mot de passe",
        ]:
            button = _find_button(self.app.vault_frame, text)
            self.assertIsNotNone(button, f"bouton introuvable : {text}")
            self.assertGreaterEqual(
                button.winfo_width(), button.winfo_reqwidth(),
                f"bouton tronque a la taille minimale de fenetre : {text!r} "
                f"(largeur allouee {button.winfo_width()}px < largeur requise {button.winfo_reqwidth()}px)",
            )

    def test_copy_username_and_copy_password_buttons_remain_visually_distinct_at_minsize(self):
        # Assertion la plus directe possible sur le risque decrit dans
        # l'audit (copier le mauvais secret) : les deux boutons ne doivent
        # jamais recevoir une largeur si etroite que Tk serait contraint de
        # clipper leur libelle a un prefixe commun ("Copie").
        self._resize_to_minsize()
        copy_username = _find_button(self.app.vault_frame, "Copier l'identifiant")
        copy_password = _find_button(self.app.vault_frame, "Copier le mot de passe")
        self.assertGreaterEqual(copy_username.winfo_width(), copy_username.winfo_reqwidth())
        self.assertGreaterEqual(copy_password.winfo_width(), copy_password.winfo_reqwidth())
        # Le libelle complet (attribut Tk, pas le rendu clippe a l'ecran)
        # doit rester distinct - garde-fou trivial mais bon marche contre
        # une future regression qui renommerait les deux boutons a l'identique.
        self.assertNotEqual(copy_username.cget("text"), copy_password.cget("text"))


class BlockingOperationFeedbackTestCase(unittest.TestCase):
    """Correctif audit Phase 2 : derive_key (scrypt), utilise par
    vault.create()/unlock()/change_master_password(), est mesure a ~550ms
    avec les parametres KDF renforces (constat d'audit G5 - ce chiffre a
    change avec SCRYPT_N, voir crypto.py ; le double pour un changement de
    mot de passe, qui derive l'ancien ET le nouveau) et bloque entierement
    le thread principal Tkinter pendant ce delai. Avant correctif, aucune retroaction visuelle n'accompagnait
    ce gel (l'utilisateur ne peut pas savoir si l'app a plante) et rien
    n'empechait un double-clic accidentel de declencher un second calcul
    scrypt en parallele des que le bouton redevenait reactif entre deux
    clics. Chacun des trois boutons concernes ("Creer le coffre",
    "Deverrouiller", "Enregistrer" du changement de mot de passe maitre)
    doit desormais se desactiver et faire passer le curseur de la fenetre
    en curseur d'attente PENDANT l'appel bloquant, verifie ici en
    interceptant la methode Vault concernee pour observer l'etat du bouton
    et du curseur au milieu meme de l'appel (avant qu'il ne soit reactive
    au retour) - puis revenir a la normale une fois l'appel termine."""

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.root = tk.Tk()
        self.root.withdraw()
        self.addCleanup(self._teardown)

    def _teardown(self):
        try:
            self.root.destroy()
        except Exception:
            pass

    def _new_app(self):
        with patch.object(gui, "_data_dir", return_value=self.tmp_dir):
            app = CoffreApp(self.root)
        # Audit E3 : voir le commentaire equivalent dans GuiTestCase.setUp -
        # cette classe construit ses CoffreApp via sa propre _new_app, sans
        # passer par GuiTestCase, donc le meme nettoyage y est necessaire.
        if getattr(app, "_update_check_job", None) is not None:
            self.root.after_cancel(app._update_check_job)
            app._update_check_job = None
        return app

    def test_create_button_is_disabled_and_cursor_waits_during_vault_create(self):
        app = self._new_app()
        self.root.update()
        button = _find_button(app.unlock_frame, "Creer le coffre")
        app._create_password_var.set("nouveau-mot-de-passe-maitre")
        app._create_confirm_var.set("nouveau-mot-de-passe-maitre")

        observed = {}
        real_create = app.vault.create

        def spying_create(password):
            observed["button_state"] = str(button.cget("state"))
            observed["cursor"] = str(self.root.cget("cursor"))
            return real_create(password)

        with patch.object(app.vault, "create", side_effect=spying_create):
            button.invoke()
            self.root.update()

        self.assertEqual(observed["button_state"], "disabled", "le bouton doit etre desactive PENDANT l'appel bloquant")
        self.assertEqual(observed["cursor"], "wait", "le curseur d'attente doit etre affiche PENDANT l'appel bloquant")
        self.assertEqual(str(button.cget("state")), "normal", "le bouton doit redevenir actif une fois l'appel termine")
        self.assertEqual(str(self.root.cget("cursor")), "", "le curseur doit redevenir normal une fois l'appel termine")
        self.assertTrue(app.vault.is_unlocked, "le coffre doit malgre tout avoir ete cree et ouvert normalement")

    def test_unlock_button_is_disabled_and_cursor_waits_during_vault_unlock(self):
        pre_vault = gui.Vault(self.tmp_dir / "coffre.sqlite")
        pre_vault.create("mon-mot-de-passe-maitre")
        pre_vault.close()

        app = self._new_app()
        self.root.update()
        button = _find_button(app.unlock_frame, "Deverrouiller")
        app._unlock_password_var.set("mon-mot-de-passe-maitre")

        observed = {}
        real_unlock = app.vault.unlock

        def spying_unlock(password):
            observed["button_state"] = str(button.cget("state"))
            observed["cursor"] = str(self.root.cget("cursor"))
            return real_unlock(password)

        with patch.object(app.vault, "unlock", side_effect=spying_unlock):
            button.invoke()
            self.root.update()

        self.assertEqual(observed["button_state"], "disabled", "le bouton doit etre desactive PENDANT l'appel bloquant")
        self.assertEqual(observed["cursor"], "wait", "le curseur d'attente doit etre affiche PENDANT l'appel bloquant")
        self.assertEqual(str(button.cget("state")), "normal", "le bouton doit redevenir actif une fois l'appel termine")
        self.assertEqual(str(self.root.cget("cursor")), "", "le curseur doit redevenir normal une fois l'appel termine")
        self.assertTrue(app.vault.is_unlocked, "le deverrouillage doit malgre tout avoir reussi normalement")

    def test_unlock_button_is_reenabled_even_after_a_wrong_password(self):
        # Le finally doit reactiver le bouton et restaurer le curseur meme
        # quand vault.unlock() renvoie False (mot de passe incorrect) plutot
        # que de lever une exception - chemin distinct du test ci-dessus.
        pre_vault = gui.Vault(self.tmp_dir / "coffre.sqlite")
        pre_vault.create("mon-mot-de-passe-maitre")
        pre_vault.close()

        app = self._new_app()
        self.root.update()
        button = _find_button(app.unlock_frame, "Deverrouiller")
        app._unlock_password_var.set("mot-de-passe-incorrect")

        button.invoke()
        self.root.update()

        self.assertEqual(str(button.cget("state")), "normal")
        self.assertEqual(str(self.root.cget("cursor")), "")
        self.assertFalse(app.vault.is_unlocked)

    def test_the_password_field_regains_focus_after_a_wrong_password(self):
        # Correctif audit C10 : sans focus_set() explicite dans la branche
        # d'echec de on_unlock(), le champ (vide de son contenu incorrect)
        # perdait le focus apres un mot de passe incorrect - l'utilisateur
        # devait recliquer dedans avant de pouvoir retaper.
        pre_vault = gui.Vault(self.tmp_dir / "coffre.sqlite")
        pre_vault.create("mon-mot-de-passe-maitre")
        pre_vault.close()

        app = self._new_app()
        self.root.update()
        button = _find_button(app.unlock_frame, "Deverrouiller")
        app._unlock_password_var.set("mot-de-passe-incorrect")

        # Deplace deliberement le focus ailleurs avant l'echec (sur le
        # bouton lui-meme) : sans ca, le test passerait trivialement si le
        # focus n'avait simplement jamais bouge de son etat initial. Passe
        # par _wait_for_real_focus (pas un simple focus_set()) : voir sa
        # docstring - sans ca root.focus_get() ne refleterait jamais le
        # deplacement de focus dans cet environnement de test, avant meme
        # d'atteindre le code sous test.
        self.assertTrue(
            _wait_for_real_focus(self.root, button),
            "le bouton n'a jamais recu le focus reel - impossible de tester le comportement",
        )

        button.invoke()
        self.root.update()

        self.assertIs(
            self.root.focus_get(), app._focus_unlock_entry,
            "le champ de mot de passe doit reprendre le focus apres un echec de deverrouillage",
        )

    def test_save_button_is_disabled_and_cursor_waits_during_change_master_password(self):
        pre_vault = gui.Vault(self.tmp_dir / "coffre.sqlite")
        pre_vault.create("mot-de-passe-maitre-actuel")
        pre_vault.close()

        app = self._new_app()
        self.root.update()
        app._unlock_password_var.set("mot-de-passe-maitre-actuel")
        _find_button(app.unlock_frame, "Deverrouiller").invoke()
        self.root.update()
        if app._auto_lock_job is not None:
            self.root.after_cancel(app._auto_lock_job)
            app._auto_lock_job = None
        self.addCleanup(lambda: app._close_all_dialogs())

        app._open_change_password_dialog()
        dialog = app._open_dialogs[-1]
        self.root.update()

        current_entry = dialog.grid_slaves(row=0, column=1)[0]
        new_entry = dialog.grid_slaves(row=1, column=1)[0]
        confirm_entry = dialog.grid_slaves(row=2, column=1)[0]
        current_entry.insert(0, "mot-de-passe-maitre-actuel")
        new_entry.insert(0, "nouveau-mot-de-passe-maitre")
        confirm_entry.insert(0, "nouveau-mot-de-passe-maitre")

        button = _find_button(dialog, "Enregistrer")
        observed = {}
        real_change = app.vault.change_master_password

        def spying_change(current, new):
            observed["button_state"] = str(button.cget("state"))
            observed["cursor"] = str(self.root.cget("cursor"))
            return real_change(current, new)

        with patch.object(app.vault, "change_master_password", side_effect=spying_change):
            with patch("gui.messagebox.showinfo") as mock_info:
                button.invoke()
                self.root.update()

        self.assertEqual(observed["button_state"], "disabled", "le bouton doit etre desactive PENDANT l'appel bloquant")
        self.assertEqual(observed["cursor"], "wait", "le curseur d'attente doit etre affiche PENDANT l'appel bloquant")
        # Le dialogue se ferme (dialog.destroy()) une fois le changement
        # reussi : le bouton n'existe donc plus pour verifier son etat
        # apres coup, mais le curseur de la fenetre principale, lui,
        # survit et doit avoir ete restaure a la normale.
        self.assertEqual(str(self.root.cget("cursor")), "", "le curseur doit redevenir normal une fois l'appel termine")
        mock_info.assert_called_once()
        self.assertFalse(dialog.winfo_exists())


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


class MasterPasswordStrengthIndicatorTestCase(unittest.TestCase):
    """Correctif audit A3 : le mot de passe maitre (creation du coffre et
    changement de mot de passe maitre) doit afficher un indicateur de
    solidite, exactement comme les mots de passe d'entrees ordinaires (deja
    couvert par password_strength dans _open_entry_dialog)."""

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.root = tk.Tk()
        self.root.withdraw()
        self.addCleanup(self._teardown)

    def _teardown(self):
        try:
            self.root.destroy()
        except Exception:
            pass

    def _new_app(self):
        with patch.object(gui, "_data_dir", return_value=self.tmp_dir):
            app = CoffreApp(self.root)
        # Audit E3 : voir le commentaire equivalent dans GuiTestCase.setUp -
        # cette classe construit ses CoffreApp via sa propre _new_app, sans
        # passer par GuiTestCase, donc le meme nettoyage y est necessaire.
        if getattr(app, "_update_check_job", None) is not None:
            self.root.after_cancel(app._update_check_job)
            app._update_check_job = None
        return app

    def _unlock_into(self, app, password):
        app._unlock_password_var.set(password)
        _find_button(app.unlock_frame, "Deverrouiller").invoke()
        self.root.update()
        if app._auto_lock_job is not None:
            self.root.after_cancel(app._auto_lock_job)
            app._auto_lock_job = None

    def test_creation_screen_shows_a_hint_when_the_field_is_empty(self):
        app = self._new_app()
        self.root.update()
        label = _find_label_with_dynamic_text(
            app.unlock_frame, f"Au moins {gui.MIN_MASTER_PASSWORD_LENGTH} caracteres.",
        )
        self.assertIsNotNone(label)

    def test_creation_screen_strength_indicator_updates_as_you_type(self):
        app = self._new_app()
        self.root.update()
        app._create_password_var.set("xK9$mQ2#pL7@vN4!")
        self.root.update()
        label = _find_label_with_dynamic_text(app.unlock_frame, "Solidite : Tres fort")
        self.assertIsNotNone(label)

    def test_change_password_dialog_shows_a_strength_indicator_for_the_new_password(self):
        pre_vault = gui.Vault(self.tmp_dir / "coffre.sqlite")
        pre_vault.create("mot-de-passe-maitre-actuel")
        pre_vault.close()

        app = self._new_app()
        self.root.update()
        self._unlock_into(app, "mot-de-passe-maitre-actuel")
        self.addCleanup(lambda: app._close_all_dialogs())

        app._open_change_password_dialog()
        dialog = app._open_dialogs[-1]
        self.root.update()

        new_entry = dialog.grid_slaves(row=1, column=1)[0]
        new_entry.insert(0, "xK9$mQ2#pL7@vN4!")
        self.root.update()

        label = _find_label_with_dynamic_text(dialog, "Solidite : Tres fort")
        self.assertIsNotNone(label)

    def test_change_password_dialog_shows_a_hint_when_the_new_password_field_is_empty(self):
        pre_vault = gui.Vault(self.tmp_dir / "coffre.sqlite")
        pre_vault.create("mot-de-passe-maitre-actuel")
        pre_vault.close()

        app = self._new_app()
        self.root.update()
        self._unlock_into(app, "mot-de-passe-maitre-actuel")
        self.addCleanup(lambda: app._close_all_dialogs())

        app._open_change_password_dialog()
        dialog = app._open_dialogs[-1]
        self.root.update()

        label = _find_label_with_dynamic_text(dialog, f"Au moins {gui.MIN_MASTER_PASSWORD_LENGTH} caracteres.")
        self.assertIsNotNone(label)

    def test_change_password_dialog_removes_the_strength_trace_on_close(self):
        # Meme garde-fou que password_var dans _open_entry_dialog (voir son
        # commentaire) : sans le retrait explicite de la trace au
        # <Destroy> de new_entry, le callback update_strength (et donc
        # new_var, qui contient le nouveau mot de passe maitre en clair)
        # resterait vivant indefiniment dans l'interprete Tcl/Python apres
        # la fermeture du dialogue.
        pre_vault = gui.Vault(self.tmp_dir / "coffre.sqlite")
        pre_vault.create("mot-de-passe-maitre-actuel")
        pre_vault.close()

        app = self._new_app()
        self.root.update()
        self._unlock_into(app, "mot-de-passe-maitre-actuel")

        app._open_change_password_dialog()
        dialog = app._open_dialogs[-1]
        self.root.update()
        new_entry = dialog.grid_slaves(row=1, column=1)[0]
        var_name = str(new_entry.cget("textvariable"))

        traces_while_open = dialog.tk.call("trace", "info", "variable", var_name)
        self.assertEqual(len(traces_while_open), 1)

        dialog.destroy()
        self.root.update()

        try:
            remaining_traces = self.root.tk.call("trace", "info", "variable", var_name)
        except tk.TclError:
            # La variable Tcl elle-meme a disparu avec son dernier
            # referent Python (new_var) - preuve encore plus forte qu'il
            # ne reste aucune trace/callback vivant.
            remaining_traces = ()
        self.assertEqual(len(remaining_traces), 0)


class ClipboardHistoryExclusionTestCase(GuiTestCase):
    """Correctif audit A11 : une valeur copiee par Coffre doit etre exclue
    de l'historique du presse-papier Windows (Win+V) et du Cloud Clipboard
    - l'effacement automatique existant (CLIPBOARD_CLEAR_SECONDS) ne
    protege que le presse-papier "courant", pas la copie que Windows peut
    conserver de son cote independamment."""

    def test_copy_field_marks_the_clipboard_as_excluded_from_history_and_sync(self):
        entry_id = self.app.vault.add_entry("Site X", username="alice", password="secret123")
        self.app._refresh_entries()
        self.app.entries_tree.selection_set(str(entry_id))
        self.root.update()

        with patch("gui._exclude_current_clipboard_from_history_and_sync") as mock_exclude:
            self.app._copy_field("password")
            self.root.update()

        mock_exclude.assert_called_once()

    def test_generator_copy_marks_the_clipboard_as_excluded_from_history_and_sync(self):
        self.app._open_generator_dialog()
        dialog = self.app._open_dialogs[-1]
        self.root.update()
        copy_button = _find_button(dialog, "Copier")

        with patch("gui._exclude_current_clipboard_from_history_and_sync") as mock_exclude:
            copy_button.invoke()
            self.root.update()

        mock_exclude.assert_called_once()
        dialog.destroy()

    def test_the_exclusion_function_never_raises_and_leaves_the_copied_text_intact(self):
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append("autre-valeur-de-test")
        self.root.update()

        gui._exclude_current_clipboard_from_history_and_sync()  # ne doit jamais lever

        self.assertEqual(self.app.root.clipboard_get(), "autre-valeur-de-test")

    @unittest.skipUnless(sys.platform == "win32", "API de presse-papier Windows uniquement")
    def test_the_exclusion_function_marks_the_special_clipboard_formats_as_present(self):
        # Test d'integration reel (sans mock) : verifie via l'API Windows
        # elle-meme que le presse-papier courant est effectivement marque
        # comme exclu, plutot que de se fier uniquement a l'absence
        # d'exception.
        #
        # Le presse-papier Windows est une ressource globale au systeme : la
        # suite de tests complete cree/detruit un tres grand nombre de
        # fenetres Tk en tres peu de temps, et cet environnement de test
        # observe en pratique un autre processus (moniteur de presse-papier)
        # qui peut le detenir de facon prolongee et imprevisible - un
        # phenomene d'infrastructure de test, distinct d'un bug de
        # _exclude_current_clipboard_from_history_and_sync elle-meme
        # (deja verifiee correcte de facon deterministe via un script
        # autonome isole pendant le developpement de ce correctif). Ce test
        # reessaie donc la sequence complete (copie + exclusion + verif
        # sur les DEUX formats) sur une fenetre de temps bornee plutot que
        # de ne tenter sa chance qu'une seule fois contre un concurrent
        # externe hors du controle de Coffre.
        user32 = ctypes.windll.user32
        user32.RegisterClipboardFormatW.restype = ctypes.c_uint
        user32.RegisterClipboardFormatW.argtypes = [ctypes.c_wchar_p]

        deadline = time.monotonic() + 5.0
        formats_present = False
        while time.monotonic() < deadline:
            self.app.root.clipboard_clear()
            self.app.root.clipboard_append("valeur-de-test-sensible")
            self.root.update()

            gui._exclude_current_clipboard_from_history_and_sync()

            formats_present = all(
                user32.IsClipboardFormatAvailable(user32.RegisterClipboardFormatW(format_name))
                for format_name in gui._CLIPBOARD_EXCLUSION_FORMAT_NAMES
            )
            if formats_present:
                break
            time.sleep(0.1)

        self.assertTrue(
            formats_present,
            "les formats d'exclusion ne sont jamais apparus sur le presse-papier "
            "dans le delai imparti, malgre plusieurs tentatives",
        )


class EnterKeySubmitsFormsTestCase(GuiTestCase):
    """Correctif audit C3 : Entree validait deja les ecrans de creation et
    de deverrouillage du coffre - ce comportement etait absent des
    dialogues d'ajout/modification d'entree, de changement de mot de passe
    maitre, et du champ de longueur du generateur, obligeant a repasser par
    la souris pour valider malgre l'habitude prise sur les deux premiers
    ecrans."""

    def test_return_in_the_entry_dialog_saves_and_closes_it(self):
        self.app._open_entry_dialog(None)
        dialog = self.app._open_dialogs[-1]
        self.root.update()

        title_entry = dialog.grid_slaves(row=0, column=1)[0]
        title_entry.insert(0, "Nouveau site")
        self.root.update()

        # _press_return (pas un simple event_generate) : voir la docstring
        # de _wait_for_real_focus - sans passer reellement le focus au
        # widget vise au prealable, l'evenement synthetise est livre a la
        # mauvaise fenetre dans cet environnement de test et le dialogue.bind
        # n'est jamais declenche, independamment du code produit.
        _press_return(self.root, title_entry)

        self.assertFalse(dialog.winfo_exists(), "Entree doit valider et fermer le dialogue comme le bouton Enregistrer")
        entries = self.app.vault.list_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["title"], "Nouveau site")

    def test_return_inside_the_notes_field_does_not_submit_the_form(self):
        # Le widget Notes est un tkinter.Text multi-ligne : Entree doit y
        # rester un simple saut de ligne, jamais valider le formulaire - a
        # la difference du champ Titre teste ci-dessus, dans le meme
        # dialogue.
        self.app._open_entry_dialog(None)
        dialog = self.app._open_dialogs[-1]
        self.root.update()

        title_entry = dialog.grid_slaves(row=0, column=1)[0]
        title_entry.insert(0, "Site avec des notes")
        notes_text = _find_widget(dialog, lambda w: w.winfo_class() == "Text")
        self.assertIsNotNone(notes_text, "le widget Notes (tkinter.Text) devrait exister dans ce dialogue")
        self.root.update()

        _press_return(self.root, notes_text)

        self.assertTrue(dialog.winfo_exists(), "le dialogue ne doit PAS se fermer quand Entree est tapee dans les notes")
        self.assertEqual(len(self.app.vault.list_entries()), 0, "aucune entree ne doit avoir ete enregistree")
        dialog.destroy()

    def test_return_in_the_change_password_dialog_saves_it(self):
        self.app._open_change_password_dialog()
        dialog = self.app._open_dialogs[-1]
        self.root.update()

        current_entry = dialog.grid_slaves(row=0, column=1)[0]
        new_entry = dialog.grid_slaves(row=1, column=1)[0]
        confirm_entry = dialog.grid_slaves(row=2, column=1)[0]
        current_entry.insert(0, "mot-de-passe-maitre-de-test")
        new_entry.insert(0, "nouveau-mot-de-passe-maitre")
        confirm_entry.insert(0, "nouveau-mot-de-passe-maitre")
        self.root.update()

        with patch("gui.messagebox.showinfo") as mock_info:
            _press_return(self.root, confirm_entry)

        mock_info.assert_called_once()
        self.assertFalse(dialog.winfo_exists())
        self.assertTrue(
            self.app.vault.unlock("nouveau-mot-de-passe-maitre"),
            "le nouveau mot de passe doit reellement fonctionner, pas seulement declencher le message de succes",
        )

    def test_return_in_the_generator_length_field_regenerates_the_password(self):
        self.app._open_generator_dialog()
        dialog = self.app._open_dialogs[-1]
        self.root.update()
        spinbox = _find_spinbox(dialog)
        self.assertIsNotNone(spinbox)

        with patch("gui.generate_password", wraps=gui.generate_password) as mock_generate:
            _press_return(self.root, spinbox)

        mock_generate.assert_called_once()
        dialog.destroy()


class UpdateCheckTimerCancelledOnCloseTestCase(unittest.TestCase):
    """Correctif audit E3 : le timer de sondage de mise a jour
    (_poll_update_check, reprogramme via root.after tant que le thread
    reseau n'a rien depose dans la file d'attente) doit etre annule
    explicitement a la fermeture de l'application - exactement comme
    _auto_lock_job l'est deja dans _lock_vault - pour ne pas laisser un
    after() orphelin tenter de s'executer apres root.destroy() (observe a
    l'audit sous forme d'erreurs Tcl "invalid command name" repetees dans
    la sortie de la suite de tests)."""

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.root = tk.Tk()
        self.root.withdraw()
        self.addCleanup(self._safe_destroy)

    def _safe_destroy(self):
        try:
            self.root.destroy()
        except Exception:
            pass

    def _new_app(self):
        with patch.object(gui, "_data_dir", return_value=self.tmp_dir):
            return CoffreApp(self.root)

    def test_the_update_check_job_id_is_tracked_after_startup(self):
        app = self._new_app()
        self.assertIsNotNone(app._update_check_job, "l'id du timer de sondage doit etre conserve des le demarrage")

    def test_on_close_cancels_the_pending_update_check_timer_without_error(self):
        app = self._new_app()
        self.assertIsNotNone(app._update_check_job)

        app._on_close()  # ne doit lever aucune TclError

        self.assertIsNone(app._update_check_job, "l'attribut doit etre remis a None une fois le timer annule")

    def test_processing_a_result_stops_rescheduling_the_timer(self):
        # Verifie l'autre branche de _poll_update_check : une fois qu'un
        # resultat a ete depose dans la file et traite, plus rien ne doit
        # etre reprogramme (sinon le timer ne s'arreterait jamais de tourner
        # tant que l'appli reste ouverte).
        app = self._new_app()
        self.root.after_cancel(app._update_check_job)
        app._update_check_job = None

        app._update_check_queue.put(("up_to_date", None))
        app._poll_update_check()

        self.assertIsNone(app._update_check_job, "aucun nouveau timer ne doit etre programme une fois un resultat traite")


class DataDirResolutionTestCase(unittest.TestCase):
    """Audit B3 : _data_dir() doit resoudre le dossier de donnees via la
    variable d'environnement %APPDATA% explicitement (celle que Windows
    expose lui-meme) plutot qu'en la reconstruisant depuis Path.home()
    (%USERPROFILE%) - les deux peuvent diverger sur une machine geree en
    entreprise ou %APPDATA% est redirige."""

    def test_uses_the_appdata_environment_variable_when_present(self):
        with patch.dict(os.environ, {"APPDATA": r"C:\FakeAppData"}):
            self.assertEqual(gui._data_dir(), Path(r"C:\FakeAppData") / "Coffre")

    def test_reflects_a_redirected_appdata_different_from_the_default_roaming_path(self):
        # Le scenario precis motivant ce correctif : %APPDATA% redirige
        # (environnement gere) vers un chemin different de
        # Path.home()/AppData/Roaming - Coffre doit suivre %APPDATA%, pas
        # deviner un chemin par defaut qui ne correspond plus a rien.
        redirected = r"D:\Redirected\Profiles\utilisateur\AppData\Roaming"
        with patch.dict(os.environ, {"APPDATA": redirected}):
            data_dir = gui._data_dir()
        self.assertEqual(data_dir, Path(redirected) / "Coffre")
        self.assertNotEqual(data_dir, Path.home() / "AppData" / "Roaming" / "Coffre")

    def test_falls_back_to_path_home_when_appdata_is_absent(self):
        env_without_appdata = {k: v for k, v in os.environ.items() if k != "APPDATA"}
        with patch.dict(os.environ, env_without_appdata, clear=True):
            self.assertEqual(gui._data_dir(), Path.home() / "AppData" / "Roaming" / "Coffre")

    def test_always_returns_a_coffre_subfolder(self):
        with patch.dict(os.environ, {"APPDATA": r"C:\FakeAppData"}):
            self.assertEqual(gui._data_dir().name, "Coffre")


class TreeviewColumnRedistributionTestCase(GuiTestCase):
    """Correctif audit C9 : a une largeur de fenetre superieure a la
    largeur par defaut (900x580, ex. 1400x800), les trois colonnes du
    Treeview restaient figees a leur largeur declaree (200/200/260px),
    laissant une bande vide inutilisee a droite avant la scrollbar. Titre
    et Identifiant (contenu generalement court) restent desormais a
    largeur fixe ; Site/URL (contenu qui beneficie le plus d'espace
    supplementaire) absorbe seule tout agrandissement au-dela de la
    largeur par defaut."""

    def _resize_to(self, width, height):
        # Meme raison que ActionsColumnLayoutTestCase._resize_to_minsize :
        # une fenetre withdraw() (etat par defaut de GuiTestCase) fige la
        # largeur mesurable par winfo_width() a la derniere geometrie
        # appliquee avant le withdraw.
        self.root.deiconify()
        self.root.geometry(f"{width}x{height}")
        self.root.update_idletasks()
        self.root.update()

    def test_title_and_username_columns_keep_their_base_width_when_enlarged(self):
        self._resize_to(1400, 800)
        self.assertEqual(self.app.entries_tree.column("title", "width"), 200)
        self.assertEqual(self.app.entries_tree.column("username", "width"), 200)

    def test_url_column_absorbs_the_extra_width_when_the_window_is_enlarged(self):
        self._resize_to(1400, 800)
        url_width = self.app.entries_tree.column("url", "width")
        self.assertGreater(
            url_width, 260,
            "la colonne Site/URL doit s'elargir pour occuper l'espace disponible a une grande taille de fenetre",
        )

    def test_no_significant_empty_gap_remains_before_the_scrollbar_when_enlarged(self):
        self._resize_to(1400, 800)
        tree = self.app.entries_tree
        total_columns_width = sum(tree.column(c, "width") for c in ("title", "username", "url"))
        # Petite marge (bordures internes...) plutot qu'une egalite stricte
        # au pixel pres - l'important est l'ABSENCE d'un ecart large comme
        # celui constate a l'audit (plusieurs centaines de pixels).
        gap = tree.winfo_width() - total_columns_width
        self.assertLessEqual(
            gap, 40,
            f"ecart de {gap}px entre la largeur du Treeview et la somme de ses colonnes : "
            "une bande vide significative reapparait (constat d'audit C9)",
        )

    def test_columns_never_shrink_below_their_base_width_at_the_default_size(self):
        # Non-regression a la taille par defaut (900x580) : aucune colonne
        # ne doit se retrouver reduite en dessous de sa largeur de base.
        self.root.update_idletasks()
        self.assertGreaterEqual(self.app.entries_tree.column("title", "width"), 200)
        self.assertGreaterEqual(self.app.entries_tree.column("username", "width"), 200)
        self.assertGreaterEqual(self.app.entries_tree.column("url", "width"), 260)


class SearchDebounceTestCase(GuiTestCase):
    """Correctif audit J1 : _refresh_entries() (copie de toutes les
    entrees en memoire, tri, vidage+reinsertion complete du Treeview) ne
    doit plus s'executer a CHAQUE caractere tape dans le champ de
    recherche, mais seulement une fois, SEARCH_DEBOUNCE_MS apres la
    DERNIERE frappe d'une rafale."""

    def setUp(self):
        super().setUp()
        self.app.vault.add_entry(title="Exemple Un", username="u1", password="p1", url="")
        self.app.vault.add_entry(title="Autre Titre", username="u2", password="p2", url="")
        self.app._refresh_entries()
        self.root.update()

    def _wait_until(self, predicate, timeout=2.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.root.update()
            if predicate():
                return True
            time.sleep(0.02)
        return False

    def test_setting_the_search_value_does_not_refresh_the_list_immediately(self):
        self.app.search_var.set("exemple")
        # Immediatement apres la frappe (avant qu'aucun after() n'ait eu
        # l'occasion de s'executer), la liste ne doit pas encore avoir ete
        # filtree.
        self.assertEqual(len(self.app.entries_tree.get_children()), 2)

    def test_the_list_is_filtered_once_the_debounce_delay_elapses(self):
        self.app.search_var.set("exemple")
        filtered = self._wait_until(lambda: len(self.app.entries_tree.get_children()) == 1)
        self.assertTrue(filtered, "la liste n'a jamais ete filtree apres le delai d'anti-rebond")

    def test_rapid_successive_keystrokes_only_trigger_a_single_refresh(self):
        refresh_calls = []
        original_refresh = self.app._refresh_entries

        def counting_refresh():
            refresh_calls.append(1)
            original_refresh()

        with patch.object(self.app, "_refresh_entries", side_effect=counting_refresh):
            for partial in ["e", "ex", "exe", "exem", "exemp", "exemple"]:
                self.app.search_var.set(partial)
                self.root.update()  # laisse le timer se (re)programmer sans le laisser expirer
            self._wait_until(lambda: len(refresh_calls) > 0)
            # Laisse une marge apres le premier rafraichissement observe
            # pour s'assurer qu'aucun second ne suit.
            self._wait_until(lambda: False, timeout=0.3)
        self.assertEqual(
            len(refresh_calls), 1,
            f"un seul rafraichissement doit avoir lieu malgre {refresh_calls} frappes rapprochees",
        )

    def test_the_pending_debounce_job_is_cancelled_when_the_vault_locks(self):
        self.app.search_var.set("exemple")
        self.assertIsNotNone(self.app._search_debounce_job)
        self.app._lock_vault()  # ne doit lever aucune erreur
        self.assertIsNone(self.app._search_debounce_job)

    def test_the_pending_debounce_job_is_cancelled_on_close(self):
        self.app.search_var.set("exemple")
        self.assertIsNotNone(self.app._search_debounce_job)
        self.app._on_close()  # ne doit lever aucune erreur
        self.assertIsNone(self.app._search_debounce_job)


if __name__ == "__main__":
    unittest.main()
