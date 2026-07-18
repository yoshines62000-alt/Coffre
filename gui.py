"""Interface Tkinter de Coffre : gestionnaire de mots de passe chiffre et
100% local - aucune donnee ne quitte jamais la machine, aucun compte,
aucun cloud, aucune synchronisation."""

from __future__ import annotations

import sys
import time
import webbrowser
from pathlib import Path
from tkinter import (
    BOTH, END, LEFT, RIGHT, TOP, X, Y, VERTICAL,
    BooleanVar, IntVar, StringVar, Tk, Toplevel, ttk, messagebox,
)

from vault import Vault, VaultError, generate_password

APP_TITLE = "Coffre"
DONATE_URL = "https://ko-fi.com/yoshines62000"
AUTO_LOCK_SECONDS = 300
CLIPBOARD_CLEAR_SECONDS = 20


def _resource_path(relative: str) -> Path:
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / relative


def _data_dir() -> Path:
    return Path.home() / "AppData" / "Roaming" / "Coffre"


class CoffreApp:
    def __init__(self, root: Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("900x580")
        self.root.minsize(700, 450)

        self.vault = Vault(_data_dir() / "coffre.sqlite")
        self._clipboard_pending_value = None
        self._auto_lock_job = None
        self._last_activity = time.monotonic()
        self._selected_entry_id = None

        icon_path = _resource_path("icon.ico")
        if icon_path.exists():
            try:
                self.root.iconbitmap(str(icon_path))
            except Exception:
                pass

        bottom_bar = ttk.Frame(self.root)
        bottom_bar.pack(fill=X, side="bottom")
        donate_label = ttk.Label(bottom_bar, text="☕ Soutenir le projet", foreground="#0645AD", cursor="hand2")
        donate_label.pack(side=RIGHT, padx=8, pady=4)
        donate_label.bind("<Button-1>", lambda event: webbrowser.open(DONATE_URL))

        self.container = ttk.Frame(self.root)
        self.container.pack(fill=BOTH, expand=True)

        self.unlock_frame = ttk.Frame(self.container)
        self.vault_frame = ttk.Frame(self.container)

        self.root.bind_all("<Any-KeyPress>", self._reset_activity_timer, add="+")
        self.root.bind_all("<Any-Button>", self._reset_activity_timer, add="+")
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._show_unlock_screen()

    # -- ecran de creation / deverrouillage -------------------------------------

    def _show_unlock_screen(self):
        self.vault_frame.pack_forget()
        for widget in self.unlock_frame.winfo_children():
            widget.destroy()

        center = ttk.Frame(self.unlock_frame)
        center.place(relx=0.5, rely=0.4, anchor="center")

        ttk.Label(center, text="🔒 Coffre", font=("Segoe UI", 20, "bold")).pack(pady=(0, 15))

        password_var = StringVar()

        if not self.vault.exists():
            ttk.Label(
                center, text="Aucun coffre n'existe encore sur cette machine.\nCreez un mot de passe maitre pour commencer.",
                justify="center",
            ).pack(pady=(0, 15))
            ttk.Label(center, text="Nouveau mot de passe maitre").pack(anchor="w")
            entry1 = ttk.Entry(center, textvariable=password_var, show="*", width=32)
            entry1.pack(pady=(0, 8))
            confirm_var = StringVar()
            ttk.Label(center, text="Confirmer le mot de passe maitre").pack(anchor="w")
            entry2 = ttk.Entry(center, textvariable=confirm_var, show="*", width=32)
            entry2.pack(pady=(0, 8))
            ttk.Label(
                center,
                text="⚠️ Il n'existe AUCUN moyen de recuperer ce mot de passe s'il est\n"
                "oublie : il sert lui-meme a chiffrer le coffre, il n'est stocke nulle part.",
                foreground="#B00020", justify="center", wraplength=380,
            ).pack(pady=(0, 12))

            def on_create():
                if password_var.get() != confirm_var.get():
                    messagebox.showwarning(APP_TITLE, "Les deux mots de passe ne correspondent pas.")
                    return
                try:
                    self.vault.create(password_var.get())
                except VaultError as exc:
                    messagebox.showwarning(APP_TITLE, str(exc))
                    return
                self._show_vault_screen()

            ttk.Button(center, text="Creer le coffre", command=on_create).pack()
            entry1.focus_set()
            entry1.bind("<Return>", lambda event: entry2.focus_set())
            entry2.bind("<Return>", lambda event: on_create())
        else:
            ttk.Label(center, text="Mot de passe maitre").pack(anchor="w")
            entry = ttk.Entry(center, textvariable=password_var, show="*", width=32)
            entry.pack(pady=(0, 8))
            status_var = StringVar()
            ttk.Label(center, textvariable=status_var, foreground="#B00020").pack(pady=(0, 8))

            def on_unlock():
                if self.vault.unlock(password_var.get()):
                    self._show_vault_screen()
                else:
                    status_var.set("Mot de passe incorrect.")
                    password_var.set("")

            ttk.Button(center, text="Deverrouiller", command=on_unlock).pack()
            entry.focus_set()
            entry.bind("<Return>", lambda event: on_unlock())

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

        top = ttk.Frame(frame)
        top.pack(fill=X, padx=10, pady=10)
        ttk.Label(top, text="Rechercher :").pack(side=LEFT)
        self.search_var = StringVar()
        search_entry = ttk.Entry(top, textvariable=self.search_var, width=30)
        search_entry.pack(side=LEFT, padx=5)
        self.search_var.trace_add("write", lambda *_: self._refresh_entries())
        ttk.Button(top, text="Generateur...", command=self._open_generator_dialog).pack(side=LEFT, padx=(10, 0))
        ttk.Button(top, text="Verrouiller maintenant", command=self._lock_vault).pack(side=RIGHT)
        ttk.Button(top, text="Changer le mot de passe maitre...", command=self._open_change_password_dialog).pack(side=RIGHT, padx=(0, 10))

        body = ttk.Frame(frame)
        body.pack(fill=BOTH, expand=True, padx=10, pady=(0, 5))

        columns = ("title", "username", "url")
        self.entries_tree = ttk.Treeview(body, columns=columns, show="headings", height=18)
        for col, label, width in [("title", "Titre", 200), ("username", "Identifiant", 200), ("url", "Site / URL", 260)]:
            self.entries_tree.heading(col, text=label)
            self.entries_tree.column(col, width=width, anchor="w")
        self.entries_tree.pack(side=LEFT, fill=BOTH, expand=True)
        self.entries_tree.bind("<Double-1>", lambda event: self._open_entry_dialog(self._selected_entry_id_from_tree()))
        self.entries_tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        scrollbar = ttk.Scrollbar(body, orient=VERTICAL, command=self.entries_tree.yview)
        scrollbar.pack(side=LEFT, fill=Y)
        self.entries_tree.configure(yscrollcommand=scrollbar.set)

        actions = ttk.Frame(body)
        actions.pack(side=LEFT, fill=Y, padx=(10, 0))
        ttk.Button(actions, text="Ajouter...", command=lambda: self._open_entry_dialog(None)).pack(fill=X, pady=2)
        ttk.Button(actions, text="Modifier...", command=lambda: self._open_entry_dialog(self._selected_entry_id_from_tree())).pack(fill=X, pady=2)
        ttk.Button(actions, text="Supprimer", command=self._delete_selected_entry).pack(fill=X, pady=2)
        ttk.Separator(actions, orient="horizontal").pack(fill=X, pady=6)
        ttk.Button(actions, text="Copier l'identifiant", command=lambda: self._copy_field("username")).pack(fill=X, pady=2)
        ttk.Button(actions, text="Copier le mot de passe", command=lambda: self._copy_field("password")).pack(fill=X, pady=2)

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
        dialog.title("Modifier l'entree" if entry else "Ajouter une entree")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)

        title_var = StringVar(value=entry["title"] if entry else "")
        username_var = StringVar(value=entry["username"] if entry else "")
        password_var = StringVar(value=entry["password"] if entry else "")
        url_var = StringVar(value=entry["url"] if entry else "")
        show_password = BooleanVar(value=False)

        ttk.Label(dialog, text="Titre").grid(row=0, column=0, sticky="w", padx=10, pady=(10, 0))
        title_entry = ttk.Entry(dialog, textvariable=title_var, width=40)
        title_entry.grid(row=0, column=1, columnspan=2, padx=10, pady=(10, 0), sticky="we")

        ttk.Label(dialog, text="Identifiant").grid(row=1, column=0, sticky="w", padx=10, pady=(5, 0))
        ttk.Entry(dialog, textvariable=username_var, width=40).grid(row=1, column=1, columnspan=2, padx=10, pady=(5, 0), sticky="we")

        ttk.Label(dialog, text="Mot de passe").grid(row=2, column=0, sticky="w", padx=10, pady=(5, 0))
        password_entry = ttk.Entry(dialog, textvariable=password_var, show="*", width=30)
        password_entry.grid(row=2, column=1, padx=(10, 0), pady=(5, 0), sticky="we")

        def toggle_show():
            password_entry.configure(show="" if show_password.get() else "*")

        ttk.Checkbutton(dialog, text="Afficher", variable=show_password, command=toggle_show).grid(row=2, column=2, padx=(5, 10), pady=(5, 0))

        ttk.Button(
            dialog, text="Generer...",
            command=lambda: self._open_generator_dialog(target_var=password_var, parent=dialog),
        ).grid(row=3, column=1, sticky="w", padx=10, pady=(2, 0))

        ttk.Label(dialog, text="Site / URL").grid(row=4, column=0, sticky="w", padx=10, pady=(5, 0))
        ttk.Entry(dialog, textvariable=url_var, width=40).grid(row=4, column=1, columnspan=2, padx=10, pady=(5, 0), sticky="we")

        ttk.Label(dialog, text="Notes").grid(row=5, column=0, sticky="nw", padx=10, pady=(5, 0))
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
        self.vault.delete_entry(entry_id)
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

        ttk.Label(dialog, text="Longueur").grid(row=0, column=0, sticky="w", padx=10, pady=(10, 0))
        ttk.Spinbox(dialog, from_=4, to=128, textvariable=length_var, width=6).grid(row=0, column=1, sticky="w", padx=10, pady=(10, 0))

        ttk.Checkbutton(dialog, text="Majuscules (A-Z)", variable=use_upper).grid(row=1, column=0, columnspan=2, sticky="w", padx=10)
        ttk.Checkbutton(dialog, text="Minuscules (a-z)", variable=use_lower).grid(row=2, column=0, columnspan=2, sticky="w", padx=10)
        ttk.Checkbutton(dialog, text="Chiffres (0-9)", variable=use_digits).grid(row=3, column=0, columnspan=2, sticky="w", padx=10)
        ttk.Checkbutton(dialog, text="Symboles (!@#...)", variable=use_symbols).grid(row=4, column=0, columnspan=2, sticky="w", padx=10)
        ttk.Checkbutton(dialog, text="Eviter les caracteres ambigus (0/O, 1/l/I...)", variable=avoid_ambiguous).grid(row=5, column=0, columnspan=2, sticky="w", padx=10, pady=(0, 5))

        result_entry = ttk.Entry(dialog, textvariable=result_var, width=36, state="readonly", font=("Consolas", 10))
        result_entry.grid(row=6, column=0, columnspan=2, padx=10, pady=(5, 5), sticky="we")

        def do_generate():
            try:
                result_var.set(generate_password(
                    length=length_var.get(), use_upper=use_upper.get(), use_lower=use_lower.get(),
                    use_digits=use_digits.get(), use_symbols=use_symbols.get(), avoid_ambiguous=avoid_ambiguous.get(),
                ))
            except VaultError as exc:
                messagebox.showwarning(APP_TITLE, str(exc), parent=dialog)

        def do_copy():
            if not result_var.get():
                return
            self.root.clipboard_clear()
            self.root.clipboard_append(result_var.get())
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

    # -- changement de mot de passe maitre ---------------------------------------

    def _open_change_password_dialog(self):
        dialog = Toplevel(self.root)
        dialog.title("Changer le mot de passe maitre")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)

        current_var = StringVar()
        new_var = StringVar()
        confirm_var = StringVar()

        ttk.Label(dialog, text="Mot de passe actuel").grid(row=0, column=0, sticky="w", padx=10, pady=(10, 0))
        ttk.Entry(dialog, textvariable=current_var, show="*", width=32).grid(row=0, column=1, padx=10, pady=(10, 0))
        ttk.Label(dialog, text="Nouveau mot de passe").grid(row=1, column=0, sticky="w", padx=10, pady=(5, 0))
        ttk.Entry(dialog, textvariable=new_var, show="*", width=32).grid(row=1, column=1, padx=10, pady=(5, 0))
        ttk.Label(dialog, text="Confirmer le nouveau").grid(row=2, column=0, sticky="w", padx=10, pady=(5, 0))
        ttk.Entry(dialog, textvariable=confirm_var, show="*", width=32).grid(row=2, column=1, padx=10, pady=(5, 0))

        def on_save():
            if new_var.get() != confirm_var.get():
                messagebox.showwarning(APP_TITLE, "Les deux nouveaux mots de passe ne correspondent pas.", parent=dialog)
                return
            try:
                self.vault.change_master_password(current_var.get(), new_var.get())
            except VaultError as exc:
                messagebox.showwarning(APP_TITLE, str(exc), parent=dialog)
                return
            dialog.destroy()
            messagebox.showinfo(APP_TITLE, "Mot de passe maitre change avec succes.")

        buttons = ttk.Frame(dialog)
        buttons.grid(row=3, column=0, columnspan=2, pady=10)
        ttk.Button(buttons, text="Enregistrer", command=on_save).pack(side=LEFT, padx=5)
        ttk.Button(buttons, text="Annuler", command=dialog.destroy).pack(side=LEFT, padx=5)

    # -- verrouillage automatique par inactivite ---------------------------------

    def _reset_activity_timer(self, event=None):
        self._last_activity = time.monotonic()

    def _schedule_auto_lock_check(self):
        self._auto_lock_job = self.root.after(1000, self._check_auto_lock)

    def _check_auto_lock(self):
        if not self.vault.is_unlocked:
            return
        if time.monotonic() - self._last_activity >= AUTO_LOCK_SECONDS:
            self._lock_vault()
            return
        self._auto_lock_job = self.root.after(1000, self._check_auto_lock)

    def _lock_vault(self):
        if self._auto_lock_job is not None:
            self.root.after_cancel(self._auto_lock_job)
            self._auto_lock_job = None
        self.vault.lock()
        self._selected_entry_id = None
        self._show_unlock_screen()

    # -- fermeture ----------------------------------------------------------------

    def _on_close(self):
        self.vault.close()
        self.root.destroy()


def main():
    root = Tk()
    app = CoffreApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
