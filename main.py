"""
main.py - Advanced Random Password Generator (CustomTkinter GUI).

Run with:   python main.py

Keyboard shortcuts
    Enter ........ generate a password       Ctrl+Shift+C .. copy password
    Ctrl+Shift+H . show / hide password      Ctrl+R ........ reset options
    Ctrl+Shift+D . light / dark mode         Ctrl+Shift+X .. clear history
"""

import sys
from tkinter import TclError

try:
    import customtkinter as ctk
except ImportError:  
    print("CustomTkinter is not installed. Run:  pip install -r requirements.txt")
    sys.exit(1)

from clipboard_manager import ClipboardError, ClipboardManager, PyperclipBackend
from history_manager import MAX_HISTORY, HistoryManager
from password_generator import (DEFAULT_LENGTH, MAX_LENGTH, MIN_LENGTH, PasswordError,
                                PasswordOptions, generate_password)
from password_strength import evaluate_password

BG = ("#f1f5f9", "#0f172a")
CARD = ("#ffffff", "#1e293b")
TEXT = ("#0f172a", "#e2e8f0")
MUTED = ("#64748b", "#94a3b8")
PRIMARY = ("#2563eb", "#3b82f6")
PRIMARY_HOVER = ("#1d4ed8", "#2563eb")
NEUTRAL = ("#e2e8f0", "#334155")
NEUTRAL_HOVER = ("#cbd5e1", "#475569")
DANGER = ("#dc2626", "#f87171")
SUCCESS = ("#16a34a", "#22c55e")
FONT = "Segoe UI"
MONO = "Consolas"
CLEAR_CLIPBOARD_AFTER_MS = 30_000


class TkClipboardBackend:
    """Fallback clipboard that uses Tkinter itself (used if pyperclip fails)."""

    def __init__(self, widget):
        self.widget = widget

    def copy(self, text):
        self.widget.clipboard_clear()
        self.widget.clipboard_append(text)
        self.widget.update()

    def paste(self):
        return self.widget.clipboard_get()


def font(size=13, weight="normal", family=FONT):
    return ctk.CTkFont(family=family, size=size, weight=weight)


class PasswordApp(ctk.CTk):
    def __init__(self):
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")
        super().__init__()
        self.title("Advanced Password Generator")
        self.geometry("1020x760")
        self.minsize(860, 640)
        self.configure(fg_color=BG)

        self.history = HistoryManager(MAX_HISTORY)
        self.clipboard_manager = ClipboardManager([PyperclipBackend(), TkClipboardBackend(self)])
        self.current_password = ""
        self.password_visible = False
        self._clear_job = None
        self._copied_password = None

        self._build_ui()
        self._bind_shortcuts()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.reset_options()

    
    def _card(self, parent, title):
        card = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=16)
        ctk.CTkLabel(card, text=title, font=font(15, "bold"), text_color=TEXT
                     ).pack(anchor="w", padx=20, pady=(16, 8))
        return card

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=24, pady=(18, 6))
        header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text="\U0001F510  Password Generator", font=font(26, "bold"),
                     text_color=TEXT).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(header, text="Cryptographically secure passwords using Python's secrets module",
                     font=font(12), text_color=MUTED).grid(row=1, column=0, sticky="w")
        self.theme_switch = ctk.CTkSwitch(header, text="Dark mode", command=self.toggle_theme,
                                          text_color=TEXT)
        self.theme_switch.grid(row=0, column=1, rowspan=2, sticky="e")
        if ctk.get_appearance_mode() == "Dark":
            self.theme_switch.select()

        body = ctk.CTkScrollableFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 4))
        body.grid_columnconfigure(0, weight=2, uniform="cols")
        body.grid_columnconfigure(1, weight=3, uniform="cols")

        settings = self._card(body, "Settings")
        settings.grid(row=0, column=0, sticky="nsew", padx=(12, 8), pady=(0, 12))

        length_row = ctk.CTkFrame(settings, fg_color="transparent")
        length_row.pack(fill="x", padx=20)
        ctk.CTkLabel(length_row, text="Password length", font=font(13, "bold"), text_color=TEXT
                     ).pack(side="left")
        self.length_entry = ctk.CTkEntry(length_row, width=64, justify="center", font=font(13, "bold"))
        self.length_entry.pack(side="right")
        self.length_entry.bind("<Return>", lambda _e: self._apply_length_and_generate())
        self.length_entry.bind("<FocusOut>", lambda _e: self._sync_slider_from_entry())

        self.length_slider = ctk.CTkSlider(settings, from_=MIN_LENGTH, to=MAX_LENGTH,
                                           number_of_steps=MAX_LENGTH - MIN_LENGTH,
                                           command=self._on_slider)
        self.length_slider.pack(fill="x", padx=20, pady=(8, 0))
        ctk.CTkLabel(settings, text=f"{MIN_LENGTH} - {MAX_LENGTH} characters", font=font(11),
                     text_color=MUTED).pack(anchor="w", padx=20, pady=(0, 12))

        ctk.CTkLabel(settings, text="Characters to include", font=font(13, "bold"), text_color=TEXT
                     ).pack(anchor="w", padx=20, pady=(4, 6))
        self.type_boxes = {}
        for key, label in (("uppercase", "Uppercase letters (A-Z)"), ("lowercase", "Lowercase letters (a-z)"),
                           ("digits", "Numbers (0-9)"), ("symbols", "Symbols (!@#$%...)")):
            box = ctk.CTkCheckBox(settings, text=label, command=self._on_option_changed, text_color=TEXT)
            box.pack(anchor="w", padx=20, pady=4)
            self.type_boxes[key] = box

        ctk.CTkLabel(settings, text="Extra options", font=font(13, "bold"), text_color=TEXT
                     ).pack(anchor="w", padx=20, pady=(14, 6))
        self.ambiguous_box = ctk.CTkCheckBox(settings, text="Exclude ambiguous characters (0 O l 1)",
                                             text_color=TEXT)
        self.ambiguous_box.pack(anchor="w", padx=20, pady=4)
        self.auto_copy_box = ctk.CTkCheckBox(settings, text="Copy automatically when generated",
                                             text_color=TEXT)
        self.auto_copy_box.pack(anchor="w", padx=20, pady=4)
        self.auto_clear_box = ctk.CTkCheckBox(settings, text="Clear clipboard after 30 seconds",
                                              text_color=TEXT)
        self.auto_clear_box.pack(anchor="w", padx=20, pady=4)

        self.settings_message = ctk.CTkLabel(settings, text="", font=font(12), text_color=DANGER,
                                             wraplength=300, justify="left")
        self.settings_message.pack(anchor="w", padx=20, pady=(10, 0))
        buttons = ctk.CTkFrame(settings, fg_color="transparent")
        buttons.pack(fill="x", padx=20, pady=(10, 20))
        buttons.grid_columnconfigure(0, weight=1)
        ctk.CTkButton(buttons, text="Generate Password", height=42, corner_radius=21,
                      fg_color=PRIMARY, hover_color=PRIMARY_HOVER, font=font(13, "bold"),
                      command=self.generate).grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ctk.CTkButton(buttons, text="Reset", height=42, corner_radius=21, width=80,
                      fg_color=NEUTRAL, hover_color=NEUTRAL_HOVER, text_color=TEXT,
                      command=self.reset_options).grid(row=0, column=1)

        right = ctk.CTkFrame(body, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 12), pady=(0, 12))
        right.grid_columnconfigure(0, weight=1)

        output = self._card(right, "Your Password")
        output.grid(row=0, column=0, sticky="ew")
        self.password_entry = ctk.CTkEntry(output, height=52, font=font(18, "bold", MONO),
                                           justify="center", state="readonly")
        self.password_entry.pack(fill="x", padx=20)
        actions = ctk.CTkFrame(output, fg_color="transparent")
        actions.pack(fill="x", padx=20, pady=(12, 4))
        actions.grid_columnconfigure((0, 1), weight=1, uniform="actions")
        ctk.CTkButton(actions, text="Copy Password", height=38, corner_radius=19, fg_color=PRIMARY,
                      hover_color=PRIMARY_HOVER, command=self.copy_current
                      ).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(actions, text="Generate Again", height=38, corner_radius=19, fg_color=NEUTRAL,
                      hover_color=NEUTRAL_HOVER, text_color=TEXT, command=self.generate
                      ).grid(row=0, column=1, sticky="ew", padx=(6, 0))
        self.show_switch = ctk.CTkSwitch(output, text="Show password", command=self.toggle_visibility,
                                         text_color=TEXT)
        self.show_switch.pack(anchor="w", padx=20, pady=(10, 0))

        self.strength_label = ctk.CTkLabel(output, text="Strength: --", font=font(14, "bold"), text_color=MUTED)
        self.strength_label.pack(anchor="w", padx=20, pady=(12, 4))
        self.strength_bar = ctk.CTkProgressBar(output, height=14, corner_radius=7)
        self.strength_bar.pack(fill="x", padx=20)
        self.strength_bar.set(0)
        self.strength_details = ctk.CTkLabel(output, text="", font=font(11), text_color=MUTED)
        self.strength_details.pack(anchor="w", padx=20, pady=(4, 0))
        self.status_label = ctk.CTkLabel(output, text="Press Generate or hit Enter.", font=font(12),
                                         text_color=MUTED, wraplength=520, justify="left")
        self.status_label.pack(anchor="w", padx=20, pady=(10, 18))

        history = self._card(right, f"Recent Passwords (last {MAX_HISTORY}, this session only)")
        history.grid(row=1, column=0, sticky="ew", pady=(12, 0))
        self.history_frame = ctk.CTkFrame(history, fg_color="transparent")
        self.history_frame.pack(fill="x", padx=14)
        ctk.CTkButton(history, text="Clear History", height=34, corner_radius=17, fg_color=NEUTRAL,
                      hover_color=NEUTRAL_HOVER, text_color=TEXT, command=self.clear_history
                      ).pack(anchor="w", padx=20, pady=(8, 16))

        ctk.CTkLabel(self, text="Enter: generate  \u2022  Ctrl+Shift+C: copy  \u2022  Ctrl+Shift+H: show/hide  "
                                "\u2022  Ctrl+R: reset  \u2022  Ctrl+Shift+D: dark mode  \u2022  Ctrl+Shift+X: clear history",
                     font=font(11), text_color=MUTED).grid(row=2, column=0, pady=(0, 10))

    def _bind_shortcuts(self):
        shortcuts = {"<Return>": self.generate, "<Control-r>": self.reset_options,
                     "<Control-R>": self.reset_options}
        for combo, action in (("Control-Shift-C", self.copy_current), ("Control-Shift-H", self.toggle_visibility_key),
                              ("Control-Shift-D", self.toggle_theme_key), ("Control-Shift-X", self.clear_history)):
            shortcuts[f"<{combo}>"] = action
            shortcuts[f"<{combo[:-1]}{combo[-1].lower()}>"] = action
        for sequence, action in shortcuts.items():
            self.bind(sequence, lambda _event, act=action: (act(), "break")[1])

    def _on_slider(self, value):
        self._set_length_text(int(round(value)))

    def _set_length_text(self, length):
        self.length_entry.delete(0, "end")
        self.length_entry.insert(0, str(length))

    def _sync_slider_from_entry(self):
        """Move the slider when the typed length is valid (otherwise leave the text for the error message)."""
        text = self.length_entry.get().strip()
        if text.isdigit() and MIN_LENGTH <= int(text) <= MAX_LENGTH:
            self.length_slider.set(int(text))

    def _apply_length_and_generate(self):
        self._sync_slider_from_entry()
        self.generate()
        return "break"

    def _on_option_changed(self):
        """Live warning when fewer than two character types are ticked."""
        if sum(box.get() for box in self.type_boxes.values()) < 2:
            self._show_error("Select at least 2 character types.")
        else:
            self.settings_message.configure(text="")

    def _read_options(self):
        """Build PasswordOptions from the form. Raises PasswordError for a bad length."""
        text = self.length_entry.get().strip()
        if not text:
            raise PasswordError("Please enter a password length.")
        try:
            length = int(text)
        except ValueError:
            raise PasswordError(f"Length must be a whole number between {MIN_LENGTH} and {MAX_LENGTH}.") from None
        return PasswordOptions(
            length=length,
            use_uppercase=bool(self.type_boxes["uppercase"].get()),
            use_lowercase=bool(self.type_boxes["lowercase"].get()),
            use_digits=bool(self.type_boxes["digits"].get()),
            use_symbols=bool(self.type_boxes["symbols"].get()),
            exclude_ambiguous=bool(self.ambiguous_box.get()))

    def _show_error(self, message):
        self.settings_message.configure(text="\u26A0 " + message, text_color=DANGER)

    def _set_status(self, message, ok=True):
        self.status_label.configure(text=message, text_color=SUCCESS if ok else DANGER)

    def generate(self):
        self.settings_message.configure(text="")
        try:
            options = self._read_options()
            password = generate_password(options)
        except PasswordError as exc:
            self._show_error(str(exc))
            self._set_status("No password generated. Fix the settings and try again.", ok=False)
            return
        self._sync_slider_from_entry()
        self.current_password = password
        self.history.add(password)
        self._display_password()
        self._update_strength(password)
        self._refresh_history()
        if self.auto_copy_box.get():
            self.copy_password(password, "Password generated and copied to the clipboard.")
        else:
            self._set_status("\u2713 Password generated.")

    def copy_current(self):
        self.copy_password(self.current_password)

    def copy_password(self, password, success_message="\u2713 Password copied to the clipboard."):
        try:
            self.clipboard_manager.copy(password)
        except ClipboardError as exc:
            self._set_status(f"\u26A0 {exc}", ok=False)
            return False
        self._set_status("\u2713 " + success_message.lstrip("\u2713 "))
        self._schedule_clipboard_clear(password)
        return True

    def _schedule_clipboard_clear(self, password):
        if self._clear_job is not None:
            self.after_cancel(self._clear_job)
            self._clear_job = None
        self._copied_password = password
        if self.auto_clear_box.get():
            self._clear_job = self.after(CLEAR_CLIPBOARD_AFTER_MS, self._clear_clipboard)

    def _clear_clipboard(self):
        self._clear_job = None
        if self._copied_password and self.clipboard_manager.clear_if_matches(self._copied_password):
            self._set_status("Clipboard cleared for your security.")
        self._copied_password = None

    def reset_options(self):
        """Back to the defaults and clear the displayed password (history is kept)."""
        self._set_length_text(DEFAULT_LENGTH)
        self.length_slider.set(DEFAULT_LENGTH)
        for box in self.type_boxes.values():
            box.select()
        self.ambiguous_box.deselect()
        self.auto_copy_box.select()
        self.auto_clear_box.select()
        self.settings_message.configure(text="")
        self.current_password = ""
        self._display_password()
        self._update_strength("")
        self._set_status("Settings reset. Press Generate or hit Enter.", ok=True)

    def clear_history(self):
        self.history.clear()
        self._refresh_history()
        self._set_status("History cleared.")

    def toggle_visibility(self):
        self.password_visible = bool(self.show_switch.get())
        self._display_password()
        self._refresh_history()

    def toggle_visibility_key(self):
        self.show_switch.toggle()
        self.toggle_visibility()

    def toggle_theme(self):
        ctk.set_appearance_mode("Dark" if self.theme_switch.get() else "Light")

    def toggle_theme_key(self):
        self.theme_switch.toggle()
        self.toggle_theme()

    def _display_password(self):
        self.password_entry.configure(state="normal")
        self.password_entry.delete(0, "end")
        self.password_entry.insert(0, self.current_password)
        self.password_entry.configure(show="" if self.password_visible else "\u2022", state="readonly")

    def _update_strength(self, password):
        if not password:
            self.strength_label.configure(text="Strength: --", text_color=MUTED)
            self.strength_bar.set(0)
            self.strength_details.configure(text="")
            return
        result = evaluate_password(password)
        self.strength_label.configure(text=f"Strength: {result.label}", text_color=result.color)
        self.strength_bar.configure(progress_color=result.color)
        self.strength_bar.set(result.score)
        self.strength_details.configure(
            text=f"{result.length} characters \u2022 {result.character_types} character types \u2022 "
                 f"~{result.entropy_bits:g} bits of entropy (estimate)")

    def _refresh_history(self):
        for child in self.history_frame.winfo_children():
            child.destroy()
        passwords = self.history.get_all()
        if not passwords:
            ctk.CTkLabel(self.history_frame, text="No passwords yet.", text_color=MUTED
                         ).pack(anchor="w", padx=8, pady=6)
            return
        for index, password in enumerate(passwords, start=1):
            row = ctk.CTkFrame(self.history_frame, fg_color=BG, corner_radius=10)
            row.pack(fill="x", pady=3)
            row.grid_columnconfigure(1, weight=1)
            shown = password if self.password_visible else "\u2022" * min(len(password), 20)
            if len(shown) > 34:
                shown = shown[:34] + "\u2026"
            ctk.CTkLabel(row, text=f"{index}.", text_color=MUTED, width=24).grid(row=0, column=0, padx=(10, 0), pady=6)
            ctk.CTkLabel(row, text=shown, font=font(13, family=MONO), text_color=TEXT, anchor="w"
                         ).grid(row=0, column=1, sticky="w", padx=8)
            ctk.CTkButton(row, text="Copy", width=64, height=28, corner_radius=14, fg_color=PRIMARY,
                          hover_color=PRIMARY_HOVER, command=lambda pw=password: self.copy_password(
                              pw, "Previous password copied to the clipboard.")
                          ).grid(row=0, column=2, padx=8, pady=4)

    def _on_close(self):
        """Wipe the in-memory history and, if still unchanged, the clipboard before exiting."""
        if self._clear_job is not None:
            self.after_cancel(self._clear_job)
        try:
            if self._copied_password and self.auto_clear_box.get():
                self.clipboard_manager.clear_if_matches(self._copied_password)
        except (TclError, ClipboardError):
            pass
        self.history.clear()
        self.current_password = ""
        self.destroy()


if __name__ == "__main__":
    PasswordApp().mainloop()
