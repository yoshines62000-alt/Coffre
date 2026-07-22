"""Interface Tkinter de Coffre : gestionnaire de mots de passe chiffre et
100% local - aucune donnee ne quitte jamais la machine, aucun compte,
aucun cloud, aucune synchronisation."""

from __future__ import annotations

import ctypes
import queue
import sqlite3
import sys
import time
import webbrowser
from datetime import date
from pathlib import Path
from tkinter import (
    BOTH, END, LEFT, RIGHT, TOP, X, Y, VERTICAL,
    BooleanVar, IntVar, StringVar, TclError, Tk, Toplevel, ttk, filedialog, messagebox,
)

import update_checker
from vault import MIN_MASTER_PASSWORD_LENGTH, Vault, VaultError, generate_password, password_strength

APP_TITLE = "Coffre"
DONATE_URL = "https://ko-fi.com/yoshines62000"
APP_VERSION = "1.0.9"
UPDATE_REPO = "yoshines62000-alt/Coffre"
RELEASES_URL = f"https://github.com/{UPDATE_REPO}/releases/latest"
AUTO_LOCK_SECONDS = 300
# Delai (en secondes) avant le verrouillage automatique pendant lequel une
# banniere d'avertissement non-bloquante est affichee dans l'ecran du coffre
# - purement informatif, ne retarde ni n'affaiblit en rien le verrouillage
# reel qui reste declenche par _check_auto_lock au bout de AUTO_LOCK_SECONDS.
AUTO_LOCK_WARNING_SECONDS = 30
CLIPBOARD_CLEAR_SECONDS = 20

# Police explicite pour tout label de texte normal (noir). Constate a la
# verification visuelle et isole en dehors de tout code Coffre : un
# ttk.Label colore (ex: le lien de don ci-dessous) utilisant la police PAR
# DEFAUT (non precisee) fait ensuite s'afficher tout AUTRE label partageant
# cette meme police par defaut dans une couleur fausse (bordeaux au lieu de
# noir) - meme avec foreground="black" defini explicitement dessus. Un
# veritable bug de rendu (contexte graphique de texte partage/corrompu par
# police) sur cet environnement, reproduit en isolation totale, y compris
# avec un tk.Label classique (donc pas specifique a ttk) et quel que soit
# le theme ttk actif. Donner a ces labels une police EXPLICITEMENT
# DIFFERENTE de celle du lien de don (qui reste sur la police par defaut)
# les met dans un contexte graphique distinct et evite le bug.
BODY_FONT = ("Segoe UI", 10)

# Couleur associee a chaque score de password_strength (0 = tres faible, 4
# = tres fort) - partagee entre tous les indicateurs de solidite de
# l'interface (dialogue d'ajout d'entree, creation du coffre, changement
# de mot de passe maitre) plutot que redefinie a chaque endroit.
_STRENGTH_COLORS = {0: "#B00020", 1: "#B00020", 2: "#B37B00", 3: "#1B7A1B", 4: "#1B7A1B"}


def _resource_path(relative: str) -> Path:
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / relative


def _data_dir() -> Path:
    return Path.home() / "AppData" / "Roaming" / "Coffre"


def _is_valid_length_input(value: str) -> bool:
    """validatecommand (validate="key") du Spinbox de longueur du
    generateur : n'autorise que des chiffres, plus la chaine vide (le temps
    d'une saisie en cours, ex. apres un Ctrl+A puis Suppr). Empeche a la
    racine la saisie de texte libre (lettres, symboles) qui ferait sinon
    lever tkinter.TclError plus tard sur length_var.get() - voir aussi le
    filet de securite dans do_generate pour les cas non couverts par cette
    seule validation (ex. champ laisse vide)."""
    return value == "" or value.isdigit()


# Audit A11 : `clipboard_clear()`/`clipboard_append()` (Tk standard) posent
# uniquement CF_UNICODETEXT sur le presse-papier "courant", que Coffre sait
# effacer lui-meme apres CLIPBOARD_CLEAR_SECONDS - mais depuis Windows 10
# 1809, le systeme peut ALSO conserver une copie dans l'historique du
# presse-papier (Win+V) et la synchroniser vers d'autres appareils du meme
# compte Microsoft (Cloud Clipboard), tous deux INDEPENDANTS du contenu
# "courant" que Coffre efface : effacer le presse-papier courant ne les
# efface pas retroactivement. Windows documente deux formats de
# presse-papier speciaux pour qu'une application demande explicitement a
# en etre exclue : "CanIncludeInClipboardHistory" et
# "CanUploadToCloudClipboard", chacun associe a une valeur DWORD 0 -
# pattern utilise par plusieurs gestionnaires de mots de passe Windows.
_CLIPBOARD_EXCLUSION_FORMAT_NAMES = ("CanIncludeInClipboardHistory", "CanUploadToCloudClipboard")
GMEM_MOVEABLE = 0x0002
# OpenClipboard echoue (ERROR_ACCESS_DENIED) si un AUTRE processus le
# detient au meme instant - frequent et attendu : le presse-papier est une
# ressource globale a tout Windows, et d'autres processus (navigateurs,
# gestionnaires de presse-papier tiers, et - ironie du sort - le service
# d'historique du presse-papier lui-meme, qui l'ouvre brievement a CHAQUE
# changement pour l'inspecter) l'ouvrent et le referment en permanence,
# generalement en quelques millisecondes. Constate empiriquement pendant
# le developpement de ce correctif : sans nouvelle tentative, cet echec
# transitoire empechait l'exclusion de fonctionner de facon fiable des que
# le presse-papier changeait frequemment (ex: plusieurs copies rapprochees
# depuis Coffre) - une poignee de tentatives avec une tres courte pause
# suffit dans la pratique.
_OPEN_CLIPBOARD_MAX_ATTEMPTS = 10
_OPEN_CLIPBOARD_RETRY_DELAY_SECONDS = 0.03


def _exclude_current_clipboard_from_history_and_sync() -> None:
    """Marque le contenu ACTUEL du presse-papier Windows (deja pose par un
    appel a root.clipboard_append juste avant) comme exclu de l'historique
    du presse-papier (Win+V) et du Cloud Clipboard, en enregistrant puis en
    posant les deux formats speciaux ci-dessus - sans jamais toucher au
    texte lui-meme (CF_UNICODETEXT), donc sans EmptyClipboard : on
    reouvre le presse-papier deja rempli par Tk pour y AJOUTER ces deux
    formats supplementaires, jamais pour le vider.

    Ne fait rien sur toute plateforme non-Windows. Best-effort et
    entierement silencieux en cas d'echec persistant (API absente sur une
    tres vieille version de Windows...) : un echec ici ne doit jamais
    empecher ni alterer la copie du texte lui-meme, qui reste la garantie
    principale et fonctionne independamment de cette exclusion
    best-effort. Nouvelle tentative en cas d'echec TRANSITOIRE
    d'OpenClipboard (voir _OPEN_CLIPBOARD_MAX_ATTEMPTS)."""
    if sys.platform != "win32":
        return
    try:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        user32.RegisterClipboardFormatW.restype = ctypes.c_uint
        user32.RegisterClipboardFormatW.argtypes = [ctypes.c_wchar_p]
        user32.OpenClipboard.restype = ctypes.c_int
        user32.OpenClipboard.argtypes = [ctypes.c_void_p]
        user32.CloseClipboard.restype = ctypes.c_int
        user32.SetClipboardData.restype = ctypes.c_void_p
        user32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]
        kernel32.GlobalAlloc.restype = ctypes.c_void_p
        kernel32.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
        kernel32.GlobalLock.restype = ctypes.c_void_p
        kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalFree.argtypes = [ctypes.c_void_p]

        opened = False
        for attempt in range(_OPEN_CLIPBOARD_MAX_ATTEMPTS):
            if user32.OpenClipboard(None):
                opened = True
                break
            if attempt < _OPEN_CLIPBOARD_MAX_ATTEMPTS - 1:
                time.sleep(_OPEN_CLIPBOARD_RETRY_DELAY_SECONDS)
        if not opened:
            return
        try:
            for format_name in _CLIPBOARD_EXCLUSION_FORMAT_NAMES:
                fmt = user32.RegisterClipboardFormatW(format_name)
                if not fmt:
                    continue
                handle = kernel32.GlobalAlloc(GMEM_MOVEABLE, ctypes.sizeof(ctypes.c_uint32))
                if not handle:
                    continue
                ptr = kernel32.GlobalLock(handle)
                if not ptr:
                    kernel32.GlobalFree(handle)
                    continue
                zero_dword = ctypes.c_uint32(0)  # DWORD 0 = exclure
                ctypes.memmove(ptr, ctypes.byref(zero_dword), ctypes.sizeof(zero_dword))
                kernel32.GlobalUnlock(handle)
                if not user32.SetClipboardData(fmt, handle):
                    kernel32.GlobalFree(handle)
                    # SetClipboardData a echoue : `handle` n'a PAS ete pris
                    # en charge par le systeme, c'est a nous de le liberer.
                    # Sinon (succes), le systeme devient proprietaire de
                    # `handle` et le liberera lui-meme - ne plus y toucher.
        finally:
            user32.CloseClipboard()
    except Exception:
        pass


class CoffreApp:
    def __init__(self, root: Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("900x580")
        # 750px : la rangee du bas de la toolbar (Generateur/Mots de passe
        # reutilises/Mots de passe faibles/Sauvegarder/Changer le mot de
        # passe maitre) demande environ 711px une fois la fenetre
        # entierement rendue, plus le padding horizontal (10px de chaque
        # cote) de sa frame - verifie empiriquement. 700px (l'ancienne
        # valeur) la faisait deja legerement deborder au redimensionnement
        # minimal, exactement le probleme signale a l'audit pour la rangee
        # unique d'origine (1132px). 750px laisse une marge de securite.
        self.root.minsize(750, 450)

        # "alt" est un theme entierement rendu par Tk (jamais delegue a
        # l'API de theming Windows), visuellement tres proche du rendu
        # natif "vista". Voir aussi BODY_FONT plus haut pour le contexte
        # complet du bug de rendu constate sur cet environnement.
        ttk.Style(self.root).theme_use("alt")

        try:
            self.vault = Vault(_data_dir() / "coffre.sqlite")
        except Exception as exc:
            # Fichier de coffre corrompu (pas un fichier SQLite valide,
            # disque plein en cours d'ecriture precedente...) : un plantage
            # silencieux au demarrage, sans le moindre message, laisserait
            # l'utilisateur croire que l'application est cassee alors que
            # le probleme vient specifiquement du fichier de donnees.
            messagebox.showerror(
                APP_TITLE,
                "Impossible d'ouvrir le fichier du coffre (fichier corrompu ou "
                f"illisible) :\n{exc}",
            )
            self.root.destroy()
            raise SystemExit(1)
        self._clipboard_pending_value = None
        self._auto_lock_job = None
        self._last_activity = time.monotonic()
        self._selected_entry_id = None
        # Tout Toplevel ouvert (edition d'entree, generateur, changement de
        # mot de passe) doit etre ferme de force au verrouillage : sinon un
        # dialogue deja ouvert (ex: mot de passe affiche en clair via
        # "Afficher") resterait visible a l'ecran meme apres que le coffre
        # soit verrouille, contredisant la garantie meme du verrouillage.
        self._open_dialogs: list = []

        icon_path = _resource_path("icon.ico")
        if icon_path.exists():
            try:
                self.root.iconbitmap(str(icon_path))
            except Exception:
                pass

        bottom_bar = ttk.Frame(self.root)
        bottom_bar.pack(fill=X, side="bottom")
        ttk.Label(bottom_bar, text=f"v{APP_VERSION}", foreground="#666").pack(side=LEFT, padx=(8, 0), pady=4)
        self.update_status_var = StringVar(value="")
        self.update_status_label = ttk.Label(bottom_bar, textvariable=self.update_status_var, foreground="#666")
        self.update_status_label.pack(side=LEFT, padx=(6, 0), pady=4)
        donate_label = ttk.Label(bottom_bar, text="☕ Soutenir le projet", foreground="#0645AD", cursor="hand2")
        donate_label.pack(side=RIGHT, padx=8, pady=4)
        donate_label.bind("<Button-1>", lambda event: webbrowser.open(DONATE_URL))

        self._update_check_queue = queue.Queue()
        update_checker.start_update_check(APP_VERSION, UPDATE_REPO, self._update_check_queue)
        self.root.after(500, self._poll_update_check)

        self.container = ttk.Frame(self.root)
        self.container.pack(fill=BOTH, expand=True)

        self.unlock_frame = ttk.Frame(self.container)
        self.vault_frame = ttk.Frame(self.container)

        self.root.bind_all("<Any-KeyPress>", self._reset_activity_timer, add="+")
        self.root.bind_all("<Any-Button>", self._reset_activity_timer, add="+")
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._show_unlock_screen()

    def _poll_update_check(self):
        try:
            status, tag = self._update_check_queue.get_nowait()
        except queue.Empty:
            self.root.after(500, self._poll_update_check)
            return
        if status == "update_available":
            self.update_status_var.set(f"Mise a jour disponible : {tag} - Telecharger")
            self.update_status_label.configure(foreground="#0645AD", cursor="hand2")
            self.update_status_label.bind("<Button-1>", lambda event: webbrowser.open(RELEASES_URL))
        elif status == "up_to_date":
            self.update_status_var.set("A jour")
            self.update_status_label.configure(foreground="#1B7A1B", cursor="")
        # "check_failed" (hors ligne, GitHub inaccessible...) : on ne
        # revendique rien plutot que d'afficher a tort "a jour".

    # -- ecran de creation / deverrouillage -------------------------------------
    #
    # Les deux sous-ecrans (creation du coffre / deverrouillage) sont
    # construits UNE SEULE FOIS puis seulement affiches/masques ensuite via
    # pack()/pack_forget() (jamais detruits) - defense en profondeur, sans
    # rapport direct avec le bug de police documente pres de BODY_FONT.

    def _build_creation_screen(self, center):
        frame = ttk.Frame(center)
        # Deux ttk.Label separes plutot qu'un texte "\n" : plus lisible a
        # composer avec BODY_FONT, sans autre raison particuliere ici.
        ttk.Label(frame, text="Aucun coffre n'existe encore sur cette machine.", foreground="black", font=BODY_FONT).pack()
        ttk.Label(frame, text="Creez un mot de passe maitre pour commencer.", foreground="black", font=BODY_FONT).pack(pady=(0, 15))
        ttk.Label(frame, text="Nouveau mot de passe maitre", foreground="black", font=BODY_FONT).pack(anchor="w")
        self._create_password_var = StringVar()
        entry1 = ttk.Entry(frame, textvariable=self._create_password_var, show="*", width=32)
        entry1.pack(pady=(0, 2))

        # Audit A3 : le mot de passe maitre est l'unique secret protegeant
        # tout le coffre, or aucun indicateur de solidite ne lui etait
        # applique (contrairement aux mots de passe d'entrees ordinaires,
        # voir _open_entry_dialog) - meme pattern ici (trace_add sur la
        # StringVar). Pas de retrait de trace necessaire : ce sous-ecran
        # est construit UNE SEULE FOIS et jamais detruit pour toute la
        # duree de vie de l'application (voir commentaire de section
        # ci-dessus), contrairement au dialogue d'ajout d'entree qui peut
        # etre ouvert/ferme un nombre illimite de fois.
        create_strength_var = StringVar()
        create_strength_label = ttk.Label(frame, textvariable=create_strength_var, font=BODY_FONT)
        create_strength_label.pack(anchor="w", pady=(0, 6))

        def update_create_strength(*_args):
            pw = self._create_password_var.get()
            if not pw:
                create_strength_var.set(f"Au moins {MIN_MASTER_PASSWORD_LENGTH} caracteres.")
                create_strength_label.configure(foreground="#666")
                return
            strength = password_strength(pw)
            create_strength_var.set(f"Solidite : {strength['label']}")
            create_strength_label.configure(foreground=_STRENGTH_COLORS[strength["score"]])

        self._create_password_var.trace_add("write", update_create_strength)
        update_create_strength()

        self._create_confirm_var = StringVar()
        ttk.Label(frame, text="Confirmer le mot de passe maitre", foreground="black", font=BODY_FONT).pack(anchor="w")
        entry2 = ttk.Entry(frame, textvariable=self._create_confirm_var, show="*", width=32)
        entry2.pack(pady=(0, 8))
        ttk.Label(
            frame, text="⚠️ Il n'existe AUCUN moyen de recuperer ce mot de passe s'il est",
            foreground="#B00020",
        ).pack()
        ttk.Label(
            frame, text="oublie : il sert lui-meme a chiffrer le coffre, il n'est stocke nulle part.",
            foreground="#B00020",
        ).pack(pady=(0, 12))

        def on_create():
            if self._create_password_var.get() != self._create_confirm_var.get():
                messagebox.showwarning(APP_TITLE, "Les deux mots de passe ne correspondent pas.")
                return
            # derive_key (scrypt) prend ~360ms mesures et bloque le thread
            # principal Tkinter : desactivation du bouton + curseur d'attente
            # pour donner une retroaction visuelle et empecher un double-clic
            # de lancer un second calcul scrypt en parallele (trouvaille
            # d'audit "Phase 2"). update_idletasks() force le rendu de ces
            # deux changements AVANT l'appel bloquant qui suit.
            create_button.config(state="disabled")
            self.root.config(cursor="wait")
            self.root.update_idletasks()
            try:
                self.vault.create(self._create_password_var.get())
            except VaultError as exc:
                messagebox.showwarning(APP_TITLE, str(exc))
                return
            finally:
                create_button.config(state="normal")
                self.root.config(cursor="")
            self._create_password_var.set("")
            self._create_confirm_var.set("")
            self._show_vault_screen()

        create_button = ttk.Button(frame, text="Creer le coffre", command=on_create)
        create_button.pack()
        self._focus_creation_entry = entry1
        entry1.bind("<Return>", lambda event: entry2.focus_set())
        entry2.bind("<Return>", lambda event: on_create())
        return frame

    def _build_unlock_only_screen(self, center):
        frame = ttk.Frame(center)
        ttk.Label(frame, text="Mot de passe maitre", foreground="black", font=BODY_FONT).pack(anchor="w")
        self._unlock_password_var = StringVar()
        entry = ttk.Entry(frame, textvariable=self._unlock_password_var, show="*", width=32)
        entry.pack(pady=(0, 8))
        self._unlock_status_var = StringVar()
        ttk.Label(frame, textvariable=self._unlock_status_var, foreground="#B00020").pack(pady=(0, 8))

        def on_unlock():
            # Meme raison que sur l'ecran de creation : derive_key (scrypt)
            # bloque le thread Tkinter ~360ms sans retroaction sinon.
            unlock_button.config(state="disabled")
            self.root.config(cursor="wait")
            self.root.update_idletasks()
            try:
                unlocked = self.vault.unlock(self._unlock_password_var.get())
            finally:
                unlock_button.config(state="normal")
                self.root.config(cursor="")
            if unlocked:
                self._unlock_password_var.set("")
                self._unlock_status_var.set("")
                self._show_vault_screen()
                if self.vault.corrupted_entry_ids:
                    messagebox.showwarning(
                        APP_TITLE,
                        f"{len(self.vault.corrupted_entry_ids)} entree(s) n'ont pas pu etre "
                        "dechiffrees (donnees corrompues) et n'apparaissent pas dans la liste. "
                        "Les autres entrees restent accessibles normalement.",
                    )
            else:
                self._unlock_status_var.set("Mot de passe incorrect.")
                self._unlock_password_var.set("")

        unlock_button = ttk.Button(frame, text="Deverrouiller", command=on_unlock)
        unlock_button.pack()
        # Vault.backup_to fonctionne deja coffre verrouille (le fichier est
        # chiffre au repos, aucun dechiffrement n'est necessaire) et c'est
        # meme teste (test_backup_works_while_the_vault_is_locked) - mais
        # le seul bouton "Sauvegarder une copie..." vivait jusqu'ici dans
        # l'ecran POST-deverrouillage, rendant cette capacite pourtant
        # annoncee ("en un clic, y compris coffre verrouille") inatteignable
        # depuis l'ecran de deverrouillage (bug trouve a l'audit).
        ttk.Button(frame, text="Sauvegarder une copie...", command=self._backup_vault).pack(pady=(10, 0))
        self._focus_unlock_entry = entry
        entry.bind("<Return>", lambda event: on_unlock())
        return frame

    def _show_unlock_screen(self):
        self.vault_frame.pack_forget()

        if not hasattr(self, "_unlock_center"):
            self._unlock_center = ttk.Frame(self.unlock_frame)
            self._unlock_center.place(relx=0.5, rely=0.4, anchor="center")
            ttk.Label(
                self._unlock_center, text="🔒 Coffre", font=("Segoe UI", 20, "bold"), foreground="black",
            ).pack(pady=(0, 15))
            self._creation_screen = None
            self._unlock_only_screen = None

        if not self.vault.exists():
            if self._creation_screen is None:
                self._creation_screen = self._build_creation_screen(self._unlock_center)
            if self._unlock_only_screen is not None:
                self._unlock_only_screen.pack_forget()
            self._creation_screen.pack()
            self._focus_creation_entry.focus_set()
        else:
            if self._unlock_only_screen is None:
                self._unlock_only_screen = self._build_unlock_only_screen(self._unlock_center)
            if self._creation_screen is not None:
                self._creation_screen.pack_forget()
            self._unlock_only_screen.pack()
            self._unlock_status_var.set("")
            self._focus_unlock_entry.focus_set()

        self.unlock_frame.pack(fill=BOTH, expand=True)

    # -- ecran principal du coffre ----------------------------------------------

    def _show_vault_screen(self):
        self.unlock_frame.pack_forget()
        for widget in self.vault_frame.winfo_children():
            widget.destroy()
        self._build_vault_screen()
        self.vault_frame.pack(fill=BOTH, expand=True)
        self._refresh_entries()
        self._reset_activity_timer()
        self._schedule_auto_lock_check()

    def _build_vault_screen(self):
        frame = self.vault_frame

        # Repartie sur deux rangees : a 900px de large (taille par defaut de
        # la fenetre), les six boutons plus le champ de recherche tenaient
        # tous sur une seule rangee "top" packee en LEFT/RIGHT, mais leur
        # largeur requise cumulee (mesuree a l'audit via winfo_reqwidth())
        # depassait la largeur reelle de la fenetre de 232px (26%) : les
        # boutons packes a droite (RIGHT) sortaient simplement du cadre
        # visible sans aucune scrollbar ni indication - "Verrouiller
        # maintenant" tronque, "Changer le mot de passe maitre..." (une
        # fonctionnalite de securite) totalement invisible. Aggrave encore
        # par minsize(700, 450) en cas de redimensionnement vers le bas.
        # Rechercher/Verrouiller restent sur la rangee du haut (toujours
        # visibles en premier), les actions secondaires sur la rangee du
        # bas - la somme des largeurs par rangee reste sous la largeur
        # minimale de la fenetre, verifie empiriquement via un smoke test
        # mesurant top.winfo_reqwidth()/top2.winfo_reqwidth() contre
        # root.winfo_width().
        top = ttk.Frame(frame)
        top.pack(fill=X, padx=10, pady=(10, 0))
        ttk.Label(top, text="Rechercher :", foreground="black", font=BODY_FONT).pack(side=LEFT)
        self.search_var = StringVar()
        search_entry = ttk.Entry(top, textvariable=self.search_var, width=30)
        search_entry.pack(side=LEFT, padx=5)
        self.search_var.trace_add("write", lambda *_: self._refresh_entries())
        ttk.Button(top, text="Verrouiller maintenant", command=self._lock_vault).pack(side=RIGHT)

        top2 = ttk.Frame(frame)
        top2.pack(fill=X, padx=10, pady=(6, 10))
        ttk.Button(top2, text="Generateur...", command=self._open_generator_dialog).pack(side=LEFT)
        ttk.Button(top2, text="Mots de passe reutilises...", command=self._open_reused_passwords_dialog).pack(side=LEFT, padx=(10, 0))
        ttk.Button(top2, text="Mots de passe faibles...", command=self._open_weak_passwords_dialog).pack(side=LEFT, padx=(10, 0))
        ttk.Button(top2, text="Sauvegarder une copie...", command=self._backup_vault).pack(side=LEFT, padx=(10, 0))
        ttk.Button(top2, text="Changer le mot de passe maitre...", command=self._open_change_password_dialog).pack(side=RIGHT)

        # Banniere d'avertissement avant verrouillage automatique par
        # inactivite - non affichee par defaut (pack_forget), voir
        # _check_auto_lock/_show_auto_lock_warning/_hide_auto_lock_warning.
        # Purement informative : le verrouillage reel a AUTO_LOCK_SECONDS
        # n'en depend pas et se produit inconditionnellement.
        self._auto_lock_warning_var = StringVar()
        self._auto_lock_warning_label = ttk.Label(
            frame, textvariable=self._auto_lock_warning_var, foreground="#B00020", font=BODY_FONT,
        )

        body = ttk.Frame(frame)
        body.pack(fill=BOTH, expand=True, padx=10, pady=(0, 5))
        self._vault_body_frame = body

        columns = ("title", "username", "url")
        self.entries_tree = ttk.Treeview(body, columns=columns, show="headings", height=18)
        for col, label, width in [("title", "Titre", 200), ("username", "Identifiant", 200), ("url", "Site / URL", 260)]:
            self.entries_tree.heading(col, text=label)
            self.entries_tree.column(col, width=width, anchor="w")
        self.entries_tree.bind("<Double-1>", lambda event: self._open_entry_dialog(self._selected_entry_id_from_tree()))
        self.entries_tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        scrollbar = ttk.Scrollbar(body, orient=VERTICAL, command=self.entries_tree.yview)
        self.entries_tree.configure(yscrollcommand=scrollbar.set)

        actions = ttk.Frame(body)
        ttk.Button(actions, text="Ajouter...", command=lambda: self._open_entry_dialog(None)).pack(fill=X, pady=2)
        ttk.Button(actions, text="Modifier...", command=lambda: self._open_entry_dialog(self._selected_entry_id_from_tree())).pack(fill=X, pady=2)
        ttk.Button(actions, text="Supprimer", command=self._delete_selected_entry).pack(fill=X, pady=2)
        ttk.Separator(actions, orient="horizontal").pack(fill=X, pady=6)
        ttk.Button(actions, text="Copier l'identifiant", command=lambda: self._copy_field("username")).pack(fill=X, pady=2)
        ttk.Button(actions, text="Copier le mot de passe", command=lambda: self._copy_field("password")).pack(fill=X, pady=2)

        # Ordre de pack() volontairement inverse de l'ordre visuel (correctif
        # audit C2) : le gestionnaire "pack" de Tk alloue l'espace du cavity
        # dans l'ordre des APPELS a pack(), pas dans l'ordre visuel ni selon
        # "side" - le premier widget empaquete recoit sa largeur demandee en
        # entier avant que les suivants ne voient le moindre pixel restant.
        # Avec l'ancien ordre (tree, scrollbar, actions, tous les trois
        # pack()-es dans cet ordre), entries_tree - empaquete en premier avec
        # expand=True - accaparait systematiquement la totalite de sa largeur
        # demandee (660px, la somme des largeurs de colonnes declarees),
        # laissant "actions" (empaquete en dernier, sans expand) recevoir
        # seulement les pixels restants une fois la fenetre trop etroite : a
        # minsize() (750x450), il ne restait que 40px pour les 5 boutons,
        # tronquant "Copier l'identifiant" ET "Copier le mot de passe" au
        # meme libelle illisible "Copie" - mesure exacte a l'audit via
        # winfo_reqwidth()/winfo_width(). En empaquetant "actions" (a droite,
        # side=RIGHT) puis "scrollbar" (a droite, donc juste a gauche de
        # actions) AVANT entries_tree, ce sont eux qui recoivent leur largeur
        # demandee en priorite, et entries_tree (toujours expand=True,
        # fill=BOTH, empaquete en dernier) absorbe seul toute reduction de
        # largeur de la fenetre - un Treeview reste lisible avec des colonnes
        # plus etroites, contrairement a des libelles de bouton tronques et
        # rendus indiscernables. Verrouille par
        # ActionsColumnLayoutTestCase.test_action_buttons_stay_distinguishable_at_minsize
        # dans tests/test_gui.py, sur le modele de ToolbarLayoutTestCase.
        actions.pack(side=RIGHT, fill=Y, padx=(10, 0))
        scrollbar.pack(side=RIGHT, fill=Y)
        self.entries_tree.pack(side=LEFT, fill=BOTH, expand=True)

        ttk.Label(
            frame, text="Double-cliquez sur une ligne pour la modifier. Le presse-papier est efface "
            f"automatiquement {CLIPBOARD_CLEAR_SECONDS} secondes apres une copie.",
            foreground="#666",
        ).pack(anchor="w", padx=10, pady=(0, 8))

    def _selected_entry_id_from_tree(self):
        selection = self.entries_tree.selection()
        return int(selection[0]) if selection else None

    def _on_tree_select(self, event=None):
        self._selected_entry_id = self._selected_entry_id_from_tree()

    def _refresh_entries(self):
        self.entries_tree.delete(*self.entries_tree.get_children())
        query = self.search_var.get().strip().lower() if hasattr(self, "search_var") else ""
        for entry in sorted(self.vault.list_entries(), key=lambda e: e["title"].lower()):
            if query and query not in entry["title"].lower() and query not in entry["username"].lower() and query not in entry["url"].lower():
                continue
            self.entries_tree.insert("", END, iid=str(entry["id"]), values=(entry["title"], entry["username"], entry["url"]))

    # -- ajout / edition d'une entree --------------------------------------------

    def _open_entry_dialog(self, entry_id):
        entry = self.vault.get_entry(entry_id) if entry_id is not None else None

        dialog = Toplevel(self.root)
        self._open_dialogs.append(dialog)
        dialog.title("Modifier l'entree" if entry else "Ajouter une entree")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)

        title_var = StringVar(value=entry["title"] if entry else "")
        username_var = StringVar(value=entry["username"] if entry else "")
        password_var = StringVar(value=entry["password"] if entry else "")
        url_var = StringVar(value=entry["url"] if entry else "")
        show_password = BooleanVar(value=False)

        ttk.Label(dialog, text="Titre", foreground="black", font=BODY_FONT).grid(row=0, column=0, sticky="w", padx=10, pady=(10, 0))
        title_entry = ttk.Entry(dialog, textvariable=title_var, width=40)
        title_entry.grid(row=0, column=1, columnspan=2, padx=10, pady=(10, 0), sticky="we")

        ttk.Label(dialog, text="Identifiant", foreground="black", font=BODY_FONT).grid(row=1, column=0, sticky="w", padx=10, pady=(5, 0))
        ttk.Entry(dialog, textvariable=username_var, width=40).grid(row=1, column=1, columnspan=2, padx=10, pady=(5, 0), sticky="we")

        ttk.Label(dialog, text="Mot de passe", foreground="black", font=BODY_FONT).grid(row=2, column=0, sticky="w", padx=10, pady=(5, 0))
        password_entry = ttk.Entry(dialog, textvariable=password_var, show="*", width=30)
        password_entry.grid(row=2, column=1, padx=(10, 0), pady=(5, 0), sticky="we")

        def toggle_show():
            password_entry.configure(show="" if show_password.get() else "*")

        ttk.Checkbutton(dialog, text="Afficher", variable=show_password, command=toggle_show).grid(row=2, column=2, padx=(5, 10), pady=(5, 0))

        strength_var = StringVar()
        strength_label = ttk.Label(dialog, textvariable=strength_var, font=BODY_FONT)
        strength_label.grid(row=3, column=2, sticky="w", padx=(5, 10), pady=(2, 0))

        def update_strength(*_args):
            strength = password_strength(password_var.get())
            strength_var.set(f"Solidite : {strength['label']}" if password_var.get() else "")
            strength_label.configure(foreground=_STRENGTH_COLORS[strength["score"]])

        strength_trace_id = password_var.trace_add("write", update_strength)
        update_strength()

        def remove_strength_trace(event=None):
            # Sans ce retrait explicite, la fermeture Tcl garde le callback
            # (et donc `password_var`, qui contient le mot de passe en
            # clair) vivant indefiniment dans l'interprete - meme apres
            # dialog.destroy(), meme apres un verrouillage du coffre (bug
            # trouve a l'audit : ceci contredisait la garantie documentee
            # dans vault.py selon laquelle lock() rend tout le materiel
            # dechiffre eligible au ramasse-miettes). Lie a <Destroy> plutot
            # qu'aux seuls boutons Enregistrer/Annuler : <Destroy> se
            # declenche aussi si la fenetre est fermee par sa croix, ou si
            # _close_all_dialogs() la ferme de force au verrouillage.
            #
            # Lie sur password_entry (le widget qui possede reellement le
            # lien -textvariable), PAS sur dialog : un widget herite de son
            # toplevel une balise de liaison partagee (bindtags), si bien
            # qu'un bind sur `dialog` se declenche aussi pour CHAQUE enfant
            # detruit (labels, boutons...), bien avant password_entry
            # lui-meme - Tk a alors deja nettoye la trace en meme temps que
            # le lien -textvariable de password_entry, et notre propre appel
            # explicite echoue silencieusement (leve puis avale une
            # TclError) sans jamais avoir vraiment supprime quoi que ce
            # soit d'utile, laissant `password_var` (et le mot de passe en
            # clair qu'elle contient) vivant via la fermeture de
            # update_strength (bug constate en testant le correctif
            # initial). Lie directement sur password_entry, ce
            # <Destroy> se declenche une seule fois, au bon moment.
            password_var.trace_remove("write", strength_trace_id)

        password_entry.bind("<Destroy>", remove_strength_trace, add="+")

        ttk.Button(
            dialog, text="Generer...",
            command=lambda: self._open_generator_dialog(target_var=password_var, parent=dialog),
        ).grid(row=3, column=1, sticky="w", padx=10, pady=(2, 0))

        ttk.Label(dialog, text="Site / URL", foreground="black", font=BODY_FONT).grid(row=4, column=0, sticky="w", padx=10, pady=(5, 0))
        ttk.Entry(dialog, textvariable=url_var, width=40).grid(row=4, column=1, columnspan=2, padx=10, pady=(5, 0), sticky="we")

        ttk.Label(dialog, text="Notes", foreground="black", font=BODY_FONT).grid(row=5, column=0, sticky="nw", padx=10, pady=(5, 0))
        from tkinter import Text
        notes_text = Text(dialog, width=40, height=5, wrap="word")
        notes_text.insert("1.0", entry["notes"] if entry else "")
        notes_text.grid(row=5, column=1, columnspan=2, padx=10, pady=(5, 0), sticky="we")

        def on_save():
            title = title_var.get().strip()
            if not title:
                messagebox.showwarning(APP_TITLE, "Le titre ne peut pas etre vide.", parent=dialog)
                return
            fields = dict(
                title=title, username=username_var.get(), password=password_var.get(),
                url=url_var.get(), notes=notes_text.get("1.0", END).strip(),
            )
            try:
                if entry:
                    self.vault.update_entry(entry_id, **fields)
                else:
                    self.vault.add_entry(**fields)
            except VaultError as exc:
                messagebox.showwarning(APP_TITLE, str(exc), parent=dialog)
                return
            except (OSError, ValueError, sqlite3.Error) as exc:
                # sqlite3.Error/OSError en plus de VaultError : un echec
                # d'ecriture disque (disque plein, erreur SQLite) remontait
                # ici totalement non intercepte - invisible dans l'exe
                # package sans console (console=False), l'utilisateur
                # voyait juste le bouton "Enregistrer" ne rien faire.
                messagebox.showerror(APP_TITLE, f"L'enregistrement a echoue :\n{exc}", parent=dialog)
                return
            dialog.destroy()
            self._refresh_entries()

        buttons = ttk.Frame(dialog)
        buttons.grid(row=6, column=0, columnspan=3, pady=10)
        ttk.Button(buttons, text="Enregistrer", command=on_save).pack(side=LEFT, padx=5)
        ttk.Button(buttons, text="Annuler", command=dialog.destroy).pack(side=LEFT, padx=5)

        title_entry.focus_set()

    def _delete_selected_entry(self):
        entry_id = self._selected_entry_id_from_tree()
        if entry_id is None:
            messagebox.showinfo(APP_TITLE, "Selectionnez une entree d'abord.")
            return
        entry = self.vault.get_entry(entry_id)
        if entry is None:
            return
        if not messagebox.askyesno(APP_TITLE, f"Supprimer l'entree '{entry['title']}' ?"):
            return
        try:
            self.vault.delete_entry(entry_id)
        except (OSError, ValueError, sqlite3.Error) as exc:
            # Meme filet que sur on_save/_backup_vault : sans lui, un echec
            # d'ecriture disque remontait ici totalement non intercepte
            # (aucune gestion d'exception n'entourait _delete_selected_entry
            # avant ce correctif), et le bouton "Supprimer" ne faisait
            # simplement rien de visible.
            messagebox.showerror(APP_TITLE, f"La suppression a echoue :\n{exc}")
            return
        self._refresh_entries()

    # -- copie presse-papier avec effacement automatique -------------------------

    def _copy_field(self, field: str):
        entry_id = self._selected_entry_id_from_tree()
        if entry_id is None:
            messagebox.showinfo(APP_TITLE, "Selectionnez une entree d'abord.")
            return
        entry = self.vault.get_entry(entry_id)
        if entry is None:
            return
        value = entry[field]
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        # Audit A11 : exclut ce contenu de l'historique du presse-papier
        # Windows (Win+V) et du Cloud Clipboard - sans cette exclusion,
        # l'effacement automatique CLIPBOARD_CLEAR_SECONDS plus bas ne
        # protege que le presse-papier "courant", pas la copie que Windows
        # peut avoir conservee de son cote.
        _exclude_current_clipboard_from_history_and_sync()
        self._clipboard_pending_value = value
        self.root.after(CLIPBOARD_CLEAR_SECONDS * 1000, lambda: self._maybe_clear_clipboard(value))

    def _maybe_clear_clipboard(self, expected_value: str):
        # Ne vide le presse-papier que s'il contient toujours EXACTEMENT ce
        # qu'on y a copie - sinon l'utilisateur aurait deja copie autre
        # chose entre-temps, et on effacerait ce nouveau contenu par erreur.
        try:
            current = self.root.clipboard_get()
        except Exception:
            current = None
        if current == expected_value:
            self.root.clipboard_clear()
        if self._clipboard_pending_value == expected_value:
            self._clipboard_pending_value = None

    # -- generateur de mot de passe -----------------------------------------------

    def _open_generator_dialog(self, target_var=None, parent=None):
        dialog = Toplevel(parent or self.root)
        self._open_dialogs.append(dialog)
        dialog.title("Generateur de mot de passe")
        dialog.transient(parent or self.root)
        dialog.grab_set()
        dialog.resizable(False, False)

        length_var = IntVar(value=20)
        use_upper = BooleanVar(value=True)
        use_lower = BooleanVar(value=True)
        use_digits = BooleanVar(value=True)
        use_symbols = BooleanVar(value=True)
        avoid_ambiguous = BooleanVar(value=True)
        result_var = StringVar()

        ttk.Label(dialog, text="Longueur", foreground="black", font=BODY_FONT).grid(row=0, column=0, sticky="w", padx=10, pady=(10, 0))
        # validate="key" + validatecommand : empeche la saisie clavier de
        # texte libre (le Spinbox reste sinon editable comme un Entry
        # ordinaire, from_/to n'etant appliques qu'aux fleches). Voir
        # _is_valid_length_input et le filet de securite dans do_generate.
        length_vcmd = (dialog.register(_is_valid_length_input), "%P")
        ttk.Spinbox(
            dialog, from_=4, to=128, textvariable=length_var, width=6,
            validate="key", validatecommand=length_vcmd,
        ).grid(row=0, column=1, sticky="w", padx=10, pady=(10, 0))

        ttk.Checkbutton(dialog, text="Majuscules (A-Z)", variable=use_upper).grid(row=1, column=0, columnspan=2, sticky="w", padx=10)
        ttk.Checkbutton(dialog, text="Minuscules (a-z)", variable=use_lower).grid(row=2, column=0, columnspan=2, sticky="w", padx=10)
        ttk.Checkbutton(dialog, text="Chiffres (0-9)", variable=use_digits).grid(row=3, column=0, columnspan=2, sticky="w", padx=10)
        ttk.Checkbutton(dialog, text="Symboles (!@#...)", variable=use_symbols).grid(row=4, column=0, columnspan=2, sticky="w", padx=10)
        ttk.Checkbutton(dialog, text="Eviter les caracteres ambigus (0/O, 1/l/I...)", variable=avoid_ambiguous).grid(row=5, column=0, columnspan=2, sticky="w", padx=10, pady=(0, 5))

        result_entry = ttk.Entry(dialog, textvariable=result_var, width=36, state="readonly", font=("Consolas", 10))
        result_entry.grid(row=6, column=0, columnspan=2, padx=10, pady=(5, 5), sticky="we")

        def do_generate():
            try:
                length = length_var.get()
            except TclError:
                # length_var (IntVar) ne peut pas etre convertie en entier -
                # champ laisse vide, ou (avant le validatecommand ci-dessus,
                # ou sur un cas qu'il ne couvrirait pas) texte non numerique
                # saisi au clavier. Sans ce filet, la TclError remontait hors
                # du callback du bouton "Regenerer" : dans l'executable
                # package (sans console), Tkinter l'avale silencieusement et
                # le bouton semble ne rien faire, sans aucun message.
                messagebox.showwarning(
                    APP_TITLE, "La longueur doit etre un nombre entier (entre 4 et 128).", parent=dialog,
                )
                return
            try:
                result_var.set(generate_password(
                    length=length, use_upper=use_upper.get(), use_lower=use_lower.get(),
                    use_digits=use_digits.get(), use_symbols=use_symbols.get(), avoid_ambiguous=avoid_ambiguous.get(),
                ))
            except VaultError as exc:
                messagebox.showwarning(APP_TITLE, str(exc), parent=dialog)

        def do_copy():
            if not result_var.get():
                return
            self.root.clipboard_clear()
            self.root.clipboard_append(result_var.get())
            _exclude_current_clipboard_from_history_and_sync()  # voir _copy_field, audit A11
            self._clipboard_pending_value = result_var.get()
            self.root.after(CLIPBOARD_CLEAR_SECONDS * 1000, lambda v=result_var.get(): self._maybe_clear_clipboard(v))

        def do_use():
            if target_var is not None and result_var.get():
                target_var.set(result_var.get())
            dialog.destroy()

        buttons = ttk.Frame(dialog)
        buttons.grid(row=7, column=0, columnspan=2, pady=10)
        ttk.Button(buttons, text="Regenerer", command=do_generate).pack(side=LEFT, padx=5)
        ttk.Button(buttons, text="Copier", command=do_copy).pack(side=LEFT, padx=5)
        if target_var is not None:
            ttk.Button(buttons, text="Utiliser ce mot de passe", command=do_use).pack(side=LEFT, padx=5)
        else:
            ttk.Button(buttons, text="Fermer", command=dialog.destroy).pack(side=LEFT, padx=5)

        do_generate()

    # -- mots de passe reutilises -------------------------------------------------

    def _open_entry_from_listing_dialog(self, dialog, entry_id):
        """Ferme un dialogue de listing (mots de passe reutilises/faibles) et
        ouvre directement l'entree correspondante en edition - sans ca,
        l'utilisateur devait fermer le dialogue, retrouver l'entree a la
        main dans la liste principale puis double-cliquer dessus, alors que
        ces listings sont justement l'endroit ou il veut agir."""
        dialog.destroy()
        self._open_entry_dialog(entry_id)

    def _make_clickable_entry_label(self, parent, text, entry_id):
        label = ttk.Label(
            parent, text=text, foreground="#0645AD", cursor="hand2", font=BODY_FONT,
            wraplength=380, justify="left",
        )
        label.bind("<Button-1>", lambda event, eid=entry_id: self._open_entry_from_listing_dialog(parent.winfo_toplevel(), eid))
        return label

    def _open_reused_passwords_dialog(self):
        groups = self.vault.find_reused_passwords()

        dialog = Toplevel(self.root)
        self._open_dialogs.append(dialog)
        dialog.title("Mots de passe reutilises")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)

        if not groups:
            ttk.Label(
                dialog, text="Aucun mot de passe n'est reutilise entre plusieurs entrees.",
                foreground="black", font=BODY_FONT,
            ).pack(padx=15, pady=15)
        else:
            plural = "s" if len(groups) > 1 else ""
            ttk.Label(
                dialog,
                text=f"{len(groups)} mot{plural} de passe partage{plural} entre plusieurs entrees "
                "(le mot de passe lui-meme n'est jamais affiche ici) - cliquez sur une entree "
                "pour l'ouvrir en edition :",
                foreground="black", font=BODY_FONT, wraplength=380, justify="left",
            ).pack(anchor="w", padx=15, pady=(15, 5))
            for group_index, entries in enumerate(groups):
                for entry in sorted(entries, key=lambda e: e["title"].lower()):
                    self._make_clickable_entry_label(dialog, f"- {entry['title']}", entry["id"]).pack(anchor="w", padx=25)
                if group_index < len(groups) - 1:
                    ttk.Separator(dialog, orient="horizontal").pack(fill=X, padx=15, pady=4)

        ttk.Button(dialog, text="Fermer", command=dialog.destroy).pack(pady=15)

    def _open_weak_passwords_dialog(self):
        weak = self.vault.find_weak_passwords()

        dialog = Toplevel(self.root)
        self._open_dialogs.append(dialog)
        dialog.title("Mots de passe faibles")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)

        if not weak:
            ttk.Label(
                dialog, text="Aucun mot de passe faible detecte.",
                foreground="black", font=BODY_FONT,
            ).pack(padx=15, pady=15)
        else:
            plural = "s" if len(weak) > 1 else ""
            ttk.Label(
                dialog,
                text=f"{len(weak)} mot{plural} de passe juge{plural} faible ou tres faible "
                "(le mot de passe lui-meme n'est jamais affiche ici) - cliquez sur une entree "
                "pour l'ouvrir en edition :",
                foreground="black", font=BODY_FONT, wraplength=380, justify="left",
            ).pack(anchor="w", padx=15, pady=(15, 5))
            for entry in weak:
                self._make_clickable_entry_label(
                    dialog, f"- {entry['title']} - Solidite : {entry['label']}", entry["id"],
                ).pack(anchor="w", padx=25)

        ttk.Button(dialog, text="Fermer", command=dialog.destroy).pack(pady=15)

    # -- sauvegarde du coffre -----------------------------------------------------

    def _backup_vault(self):
        dest = filedialog.asksaveasfilename(
            parent=self.root,
            title="Sauvegarder une copie du coffre",
            defaultextension=".sqlite",
            initialfile=f"coffre-sauvegarde-{date.today().isoformat()}.sqlite",
            filetypes=[("Base SQLite", "*.sqlite"), ("Tous les fichiers", "*.*")],
        )
        if not dest:
            return
        try:
            self.vault.backup_to(Path(dest))
        except (OSError, ValueError, sqlite3.Error) as exc:
            # sqlite3.Error en plus d'OSError : une destination inaccessible
            # (cle USB retiree, dossier en lecture seule) remonte en
            # OperationalError depuis sqlite3.connect, pas en OSError.
            messagebox.showerror(APP_TITLE, f"La sauvegarde a echoue :\n{exc}")
            return
        messagebox.showinfo(
            APP_TITLE,
            f"Copie du coffre enregistree :\n{dest}\n\n"
            "Cette copie est chiffree et reste protegee par le meme mot de "
            "passe maitre que le coffre actuel.",
        )

    # -- changement de mot de passe maitre ---------------------------------------

    def _open_change_password_dialog(self):
        dialog = Toplevel(self.root)
        self._open_dialogs.append(dialog)
        dialog.title("Changer le mot de passe maitre")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)

        current_var = StringVar()
        new_var = StringVar()
        confirm_var = StringVar()

        ttk.Label(dialog, text="Mot de passe actuel", foreground="black", font=BODY_FONT).grid(row=0, column=0, sticky="w", padx=10, pady=(10, 0))
        ttk.Entry(dialog, textvariable=current_var, show="*", width=32).grid(row=0, column=1, padx=10, pady=(10, 0))
        ttk.Label(dialog, text="Nouveau mot de passe", foreground="black", font=BODY_FONT).grid(row=1, column=0, sticky="w", padx=10, pady=(5, 0))
        new_entry = ttk.Entry(dialog, textvariable=new_var, show="*", width=32)
        new_entry.grid(row=1, column=1, padx=10, pady=(5, 0))
        ttk.Label(dialog, text="Confirmer le nouveau", foreground="black", font=BODY_FONT).grid(row=2, column=0, sticky="w", padx=10, pady=(5, 0))
        ttk.Entry(dialog, textvariable=confirm_var, show="*", width=32).grid(row=2, column=1, padx=10, pady=(5, 0))

        # Audit A3 : meme indicateur de solidite que sur l'ecran de
        # creation du coffre et le dialogue d'ajout d'entree, applique ici
        # au NOUVEAU mot de passe maitre. Contrairement a l'ecran de
        # creation (construit une seule fois, jamais detruit), ce dialogue
        # est un Toplevel qu'on peut ouvrir/fermer un nombre illimite de
        # fois : le retrait de la trace au <Destroy> de new_entry est donc
        # necessaire, exactement comme pour password_var dans
        # _open_entry_dialog (voir son commentaire detaille), pour ne pas
        # garder le nouveau mot de passe en clair vivant indefiniment dans
        # l'interprete apres la fermeture du dialogue.
        strength_var = StringVar()
        strength_label = ttk.Label(dialog, textvariable=strength_var, font=BODY_FONT)
        strength_label.grid(row=1, column=2, sticky="w", padx=(5, 10), pady=(5, 0))

        def update_strength(*_args):
            pw = new_var.get()
            if not pw:
                strength_var.set(f"Au moins {MIN_MASTER_PASSWORD_LENGTH} caracteres.")
                strength_label.configure(foreground="#666")
                return
            strength = password_strength(pw)
            strength_var.set(f"Solidite : {strength['label']}")
            strength_label.configure(foreground=_STRENGTH_COLORS[strength["score"]])

        strength_trace_id = new_var.trace_add("write", update_strength)
        update_strength()

        def remove_strength_trace(event=None):
            new_var.trace_remove("write", strength_trace_id)

        new_entry.bind("<Destroy>", remove_strength_trace, add="+")

        def on_save():
            if new_var.get() != confirm_var.get():
                messagebox.showwarning(APP_TITLE, "Les deux nouveaux mots de passe ne correspondent pas.", parent=dialog)
                return
            # change_master_password derive DEUX cles scrypt (ancien puis
            # nouveau mot de passe), donc ~2x360ms mesures ici - retroaction
            # visuelle d'autant plus necessaire que sur les deux autres
            # ecrans (creation/deverrouillage).
            save_button.config(state="disabled")
            self.root.config(cursor="wait")
            self.root.update_idletasks()
            try:
                self.vault.change_master_password(current_var.get(), new_var.get())
            except VaultError as exc:
                messagebox.showwarning(APP_TITLE, str(exc), parent=dialog)
                return
            finally:
                save_button.config(state="normal")
                self.root.config(cursor="")
            dialog.destroy()
            messagebox.showinfo(APP_TITLE, "Mot de passe maitre change avec succes.")

        buttons = ttk.Frame(dialog)
        buttons.grid(row=3, column=0, columnspan=2, pady=10)
        save_button = ttk.Button(buttons, text="Enregistrer", command=on_save)
        save_button.pack(side=LEFT, padx=5)
        ttk.Button(buttons, text="Annuler", command=dialog.destroy).pack(side=LEFT, padx=5)

    # -- verrouillage automatique par inactivite ---------------------------------

    def _reset_activity_timer(self, event=None):
        self._last_activity = time.monotonic()

    def _schedule_auto_lock_check(self):
        self._auto_lock_job = self.root.after(1000, self._check_auto_lock)

    def _check_auto_lock(self):
        if not self.vault.is_unlocked:
            return
        remaining = AUTO_LOCK_SECONDS - (time.monotonic() - self._last_activity)
        if remaining <= 0:
            # Le verrouillage reel : inconditionnel, independant de la
            # banniere d'avertissement ci-dessous (purement informative).
            self._hide_auto_lock_warning()
            self._lock_vault()
            return
        if remaining <= AUTO_LOCK_WARNING_SECONDS:
            self._show_auto_lock_warning(remaining)
        else:
            self._hide_auto_lock_warning()
        self._auto_lock_job = self.root.after(1000, self._check_auto_lock)

    def _show_auto_lock_warning(self, remaining_seconds):
        # Avertissement non-bloquant (simple banniere, pas de messagebox
        # qui interromprait l'utilisateur ni ne retarderait le compte a
        # rebours) affiche dans les derniere secondes avant le
        # verrouillage automatique - disparait de lui-meme (voir
        # _hide_auto_lock_warning) des que _check_auto_lock constate qu'une
        # activite a repousse l'echeance de plus de AUTO_LOCK_WARNING_SECONDS.
        if not hasattr(self, "_auto_lock_warning_label") or not self._auto_lock_warning_label.winfo_exists():
            return
        seconds = max(1, round(remaining_seconds))
        plural = "s" if seconds > 1 else ""
        self._auto_lock_warning_var.set(
            f"Le coffre va se verrouiller automatiquement dans {seconds} seconde{plural} par inactivite."
        )
        if not self._auto_lock_warning_label.winfo_ismapped():
            self._auto_lock_warning_label.pack(anchor="w", padx=10, pady=(0, 6), before=self._vault_body_frame)

    def _hide_auto_lock_warning(self):
        if hasattr(self, "_auto_lock_warning_label") and self._auto_lock_warning_label.winfo_exists():
            self._auto_lock_warning_label.pack_forget()

    def _close_all_dialogs(self):
        """Detruit de force tout Toplevel encore ouvert (edition, generateur,
        changement de mot de passe) - indispensable au verrouillage : un
        dialogue laisse ouvert pourrait encore afficher un mot de passe
        dechiffre en clair (case "Afficher" cochee) meme apres que le
        coffre soit verrouille."""
        for dialog in self._open_dialogs:
            try:
                if dialog.winfo_exists():
                    dialog.destroy()
            except Exception:
                pass
        self._open_dialogs = []

    def _lock_vault(self):
        if self._auto_lock_job is not None:
            self.root.after_cancel(self._auto_lock_job)
            self._auto_lock_job = None
        self._close_all_dialogs()
        if hasattr(self, "entries_tree"):
            # Vide la liste affichee (titres/identifiants/URL dechiffres)
            # plutot que de la laisser en memoire jusqu'au prochain
            # deverrouillage reussi.
            self.entries_tree.delete(*self.entries_tree.get_children())
        self.vault.lock()
        self._selected_entry_id = None
        self._show_unlock_screen()

    # -- fermeture ----------------------------------------------------------------

    def _on_close(self):
        # root.destroy() arrete la boucle Tkinter : tout root.after(...)
        # deja programme pour effacer le presse-papier (voir _copy_field)
        # ne s'executera donc jamais si l'app se ferme avant son delai -
        # sans ce nettoyage explicite ici, un mot de passe copie juste
        # avant de quitter resterait indefiniment dans le presse-papier
        # Windows apres la fermeture de l'application.
        if self._clipboard_pending_value is not None:
            try:
                if self.root.clipboard_get() == self._clipboard_pending_value:
                    self.root.clipboard_clear()
            except Exception:
                pass
        self.vault.close()
        self.root.destroy()


def main():
    root = Tk()
    app = CoffreApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
