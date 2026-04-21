"""
messenger_gui.py
================
Graphical front-end for Secure P2P Messenger (CS 4173 Final Project).

Run as:
    python messenger_gui.py

The window lets you:
  • Choose Server or Client role, enter IP/port, username, and password.
  • Select encryption mode: Standard (AES-256-CBC) or Double (extra credit).
  • Enable DH key exchange (extra credit – no pre-shared password needed).
  • Send messages; the chat window shows sent ciphertext (hex) and
    received ciphertext + decrypted plaintext.
  • Manually trigger a key rotation at any time.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import json
import base64
import datetime
import textwrap

from crypto_core import (
    KeyManager, encrypt, decrypt,
    double_encrypt, double_decrypt,
    pack_message, unpack_message,
)
from network import start_server, connect_to_server, ConnectionError


# ---------------------------------------------------------------------------
# Colour palette & fonts
# ---------------------------------------------------------------------------
BG_DARK     = "#0d1117"
BG_PANEL    = "#161b22"
BG_ENTRY    = "#21262d"
ACCENT      = "#58a6ff"
ACCENT2     = "#3fb950"
WARN        = "#f0883e"
TEXT_MAIN   = "#c9d1d9"
TEXT_DIM    = "#8b949e"
TEXT_CIPHER = "#f78166"
BORDER      = "#30363d"

FONT_TITLE  = ("Courier New", 13, "bold")
FONT_BODY   = ("Courier New", 10)
FONT_SMALL  = ("Courier New", 9)
FONT_MONO   = ("Courier New", 10)


def _ts() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")


# ---------------------------------------------------------------------------
# Main Application
# ---------------------------------------------------------------------------

class SecureMessengerApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("🔒 Secure P2P Messenger — CS 4173")
        self.configure(bg=BG_DARK)
        self.geometry("900x700")
        self.minsize(780, 580)
        self.resizable(True, True)

        self.peer       = None   # PeerConnection once connected
        self.key_mgr    = None   # KeyManager once connected

        self._build_ui()

    # ------------------------------------------------------------------ #
    #  UI construction
    # ------------------------------------------------------------------ #

    def _build_ui(self):
        # Top bar
        top = tk.Frame(self, bg=BG_DARK, pady=6)
        top.pack(fill="x", padx=12)
        tk.Label(top, text="🔒 SECURE P2P MESSENGER",
                 font=FONT_TITLE, fg=ACCENT, bg=BG_DARK).pack(side="left")
        self.status_lbl = tk.Label(top, text="● Disconnected",
                                   font=FONT_SMALL, fg=TEXT_CIPHER, bg=BG_DARK)
        self.status_lbl.pack(side="right")

        # Separator
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", padx=0)

        # Main paned area
        paned = tk.PanedWindow(self, orient="horizontal", bg=BG_DARK,
                               sashwidth=4, sashrelief="flat",
                               sashpad=0)
        paned.pack(fill="both", expand=True, padx=0, pady=0)

        # Left: settings panel
        left = tk.Frame(paned, bg=BG_PANEL, width=250)
        paned.add(left, minsize=220)
        self._build_settings(left)

        # Right: chat panel
        right = tk.Frame(paned, bg=BG_DARK)
        paned.add(right, minsize=440)
        self._build_chat(right)

    def _lbl(self, parent, text, small=False):
        font = FONT_SMALL if small else FONT_BODY
        return tk.Label(parent, text=text, font=font,
                        fg=TEXT_DIM, bg=BG_PANEL, anchor="w")

    def _entry(self, parent, **kw):
        e = tk.Entry(parent, font=FONT_BODY,
                     bg=BG_ENTRY, fg=TEXT_MAIN,
                     insertbackground=ACCENT,
                     relief="flat", bd=4,
                     highlightthickness=1,
                     highlightcolor=ACCENT,
                     highlightbackground=BORDER,
                     **kw)
        return e

    def _build_settings(self, parent):
        pad = {"padx": 12, "pady": 3}

        tk.Label(parent, text="CONNECTION", font=FONT_SMALL,
                 fg=ACCENT, bg=BG_PANEL).pack(anchor="w", **pad, pady=(14, 2))

        # Role
        self._lbl(parent, "Role").pack(anchor="w", padx=12)
        self.role_var = tk.StringVar(value="Server")
        role_frame = tk.Frame(parent, bg=BG_PANEL)
        role_frame.pack(fill="x", padx=12, pady=2)
        for r in ("Server", "Client"):
            tk.Radiobutton(role_frame, text=r, variable=self.role_var, value=r,
                           bg=BG_PANEL, fg=TEXT_MAIN, selectcolor=BG_ENTRY,
                           activebackground=BG_PANEL, font=FONT_BODY,
                           command=self._on_role_change).pack(side="left", padx=4)

        # Host
        self._lbl(parent, "Host / IP").pack(anchor="w", **pad)
        self.host_var = tk.StringVar(value="127.0.0.1")
        self.host_entry = self._entry(parent, textvariable=self.host_var)
        self.host_entry.pack(fill="x", **pad)

        # Port
        self._lbl(parent, "Port").pack(anchor="w", **pad)
        self.port_var = tk.StringVar(value="9999")
        self._entry(parent, textvariable=self.port_var).pack(fill="x", **pad)

        # Username
        self._lbl(parent, "Username").pack(anchor="w", **pad)
        self.user_var = tk.StringVar(value="Alice")
        self._entry(parent, textvariable=self.user_var).pack(fill="x", **pad)

        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=12, pady=8)
        tk.Label(parent, text="SECURITY", font=FONT_SMALL,
                 fg=ACCENT, bg=BG_PANEL).pack(anchor="w", **pad)

        # Password
        self.pw_label = self._lbl(parent, "Shared Password")
        self.pw_label.pack(anchor="w", **pad)
        self.pw_var = tk.StringVar(value="")
        self.pw_entry = self._entry(parent, textvariable=self.pw_var, show="●")
        self.pw_entry.pack(fill="x", **pad)

        # DH mode
        self.dh_var = tk.BooleanVar(value=False)
        tk.Checkbutton(parent, text="DH Key Exchange (no password)",
                       variable=self.dh_var,
                       bg=BG_PANEL, fg=TEXT_MAIN, selectcolor=BG_ENTRY,
                       activebackground=BG_PANEL, font=FONT_SMALL,
                       command=self._on_dh_toggle).pack(anchor="w", padx=12, pady=2)

        # Encryption mode
        self._lbl(parent, "Encryption Mode").pack(anchor="w", **pad)
        self.enc_var = tk.StringVar(value="Standard")
        enc_frame = tk.Frame(parent, bg=BG_PANEL)
        enc_frame.pack(fill="x", padx=12, pady=2)
        for m in ("Standard", "Double"):
            tk.Radiobutton(enc_frame, text=m, variable=self.enc_var, value=m,
                           bg=BG_PANEL, fg=TEXT_MAIN, selectcolor=BG_ENTRY,
                           activebackground=BG_PANEL, font=FONT_BODY).pack(side="left", padx=4)

        # Key rotation
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=12, pady=8)
        tk.Label(parent, text="KEY MANAGEMENT", font=FONT_SMALL,
                 fg=ACCENT, bg=BG_PANEL).pack(anchor="w", **pad)

        self.epoch_lbl = tk.Label(parent, text="Epoch: —  |  Msgs: —",
                                  font=FONT_SMALL, fg=TEXT_DIM, bg=BG_PANEL)
        self.epoch_lbl.pack(anchor="w", padx=12)

        tk.Button(parent, text="⟳  Rotate Key Now",
                  font=FONT_SMALL, bg=BG_ENTRY, fg=WARN,
                  relief="flat", bd=0, cursor="hand2",
                  activebackground=BG_PANEL, activeforeground=WARN,
                  command=self._manual_rotate).pack(fill="x", padx=12, pady=4)

        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=12, pady=8)

        # Connect / Disconnect buttons
        self.connect_btn = tk.Button(parent, text="Connect",
                                     font=FONT_BODY, bg=ACCENT, fg=BG_DARK,
                                     relief="flat", bd=0, cursor="hand2",
                                     activebackground="#79b8ff",
                                     command=self._connect)
        self.connect_btn.pack(fill="x", padx=12, pady=3)

        self.disconnect_btn = tk.Button(parent, text="Disconnect",
                                        font=FONT_BODY, bg=BG_ENTRY, fg=TEXT_DIM,
                                        relief="flat", bd=0, cursor="hand2",
                                        activebackground=BG_ENTRY,
                                        state="disabled",
                                        command=self._disconnect)
        self.disconnect_btn.pack(fill="x", padx=12, pady=3)

        # Key info box
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=12, pady=8)
        self.key_info = tk.Text(parent, height=4, font=FONT_SMALL,
                                bg=BG_ENTRY, fg=TEXT_DIM,
                                relief="flat", bd=4, wrap="word",
                                state="disabled")
        self.key_info.pack(fill="x", padx=12, pady=2)

    def _build_chat(self, parent):
        parent.configure(bg=BG_DARK)

        # Chat display
        chat_frame = tk.Frame(parent, bg=BG_DARK)
        chat_frame.pack(fill="both", expand=True, padx=8, pady=(8, 4))

        self.chat_display = scrolledtext.ScrolledText(
            chat_frame,
            font=FONT_MONO, bg=BG_PANEL, fg=TEXT_MAIN,
            relief="flat", bd=0, wrap="word", state="disabled",
            padx=10, pady=8,
            selectbackground=ACCENT,
        )
        self.chat_display.pack(fill="both", expand=True)

        # Tag configuration for coloured text
        self.chat_display.tag_config("ts",      foreground=TEXT_DIM,    font=FONT_SMALL)
        self.chat_display.tag_config("sender",  foreground=ACCENT,      font=("Courier New", 10, "bold"))
        self.chat_display.tag_config("me",      foreground=ACCENT2,     font=("Courier New", 10, "bold"))
        self.chat_display.tag_config("plain",   foreground=TEXT_MAIN)
        self.chat_display.tag_config("cipher",  foreground=TEXT_CIPHER, font=FONT_SMALL)
        self.chat_display.tag_config("sys",     foreground=WARN,        font=FONT_SMALL)
        self.chat_display.tag_config("epoch",   foreground="#d2a8ff",   font=FONT_SMALL)

        # Input row
        input_frame = tk.Frame(parent, bg=BG_DARK)
        input_frame.pack(fill="x", padx=8, pady=(0, 8))

        self.msg_entry = tk.Entry(
            input_frame, font=FONT_BODY,
            bg=BG_ENTRY, fg=TEXT_MAIN,
            insertbackground=ACCENT,
            relief="flat", bd=6,
            highlightthickness=1,
            highlightcolor=ACCENT,
            highlightbackground=BORDER,
        )
        self.msg_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.msg_entry.bind("<Return>", lambda e: self._send_message())
        self.msg_entry.config(state="disabled")

        self.send_btn = tk.Button(
            input_frame, text="Send  ▶",
            font=FONT_BODY, bg=ACCENT, fg=BG_DARK,
            relief="flat", bd=0, cursor="hand2",
            activebackground="#79b8ff",
            state="disabled",
            command=self._send_message,
        )
        self.send_btn.pack(side="right")

    # ------------------------------------------------------------------ #
    #  UI helpers
    # ------------------------------------------------------------------ #

    def _on_role_change(self):
        role = self.role_var.get()
        self.host_entry.config(state="normal" if role == "Client" else "disabled")

    def _on_dh_toggle(self):
        if self.dh_var.get():
            self.pw_entry.config(state="disabled")
            self.pw_label.config(fg="#3d444d")
        else:
            self.pw_entry.config(state="normal")
            self.pw_label.config(fg=TEXT_DIM)

    def _set_connected(self, connected: bool):
        state_on  = "normal" if connected else "disabled"
        state_off = "disabled" if connected else "normal"
        self.connect_btn.config(state=state_off)
        self.disconnect_btn.config(state=state_on)
        self.msg_entry.config(state=state_on)
        self.send_btn.config(state=state_on)
        if connected:
            self.status_lbl.config(text="● Connected", fg=ACCENT2)
            self.msg_entry.focus_set()
        else:
            self.status_lbl.config(text="● Disconnected", fg=TEXT_CIPHER)

    def _append_chat(self, parts):
        """
        parts: list of (text, tag) tuples.
        Thread-safe – schedules on main thread.
        """
        def _do():
            self.chat_display.config(state="normal")
            for text, tag in parts:
                self.chat_display.insert("end", text, tag)
            self.chat_display.insert("end", "\n")
            self.chat_display.see("end")
            self.chat_display.config(state="disabled")
        self.after(0, _do)

    def _sys_msg(self, text):
        self._append_chat([
            (f"[{_ts()}] ", "ts"),
            (f"⚙  {text}", "sys"),
        ])

    def _update_epoch_label(self):
        if self.key_mgr:
            def _do():
                e = self.key_mgr.current_epoch()
                c = self.key_mgr.msg_count
                self.epoch_lbl.config(text=f"Epoch: {e}  |  Msgs: {c}")
                # Show key fingerprint (first 8 hex chars of current key)
                fp = self.key_mgr.key.hex()[:16]
                self._update_key_info(fp, e)
            self.after(0, _do)

    def _update_key_info(self, fingerprint: str, epoch: int):
        self.key_info.config(state="normal")
        self.key_info.delete("1.0", "end")
        self.key_info.insert("end",
            f"Key fingerprint:\n{fingerprint}…\n"
            f"Epoch: {epoch}\n"
            f"Algo: AES-256-{'CBC+CFB⊕' if self.enc_var.get()=='Double' else 'CBC'}"
        )
        self.key_info.config(state="disabled")

    # ------------------------------------------------------------------ #
    #  Connect / Disconnect
    # ------------------------------------------------------------------ #

    def _connect(self):
        role    = self.role_var.get()
        host    = self.host_var.get().strip()
        use_dh  = self.dh_var.get()
        pw      = self.pw_var.get()

        if not use_dh and not pw:
            messagebox.showerror("Missing Password",
                                 "Enter a shared password, or enable DH key exchange.")
            return

        try:
            port = int(self.port_var.get())
        except ValueError:
            messagebox.showerror("Bad Port", "Port must be an integer.")
            return

        self.connect_btn.config(state="disabled", text="Connecting…")
        self._sys_msg(f"{'Listening on' if role=='Server' else 'Connecting to'} {host}:{port} …")

        if role == "Server":
            start_server(
                host="0.0.0.0",
                port=port,
                use_dh=use_dh,
                on_connected=lambda peer: self.after(0, self._on_connected, peer, pw, use_dh),
                on_error=lambda e:        self.after(0, self._on_conn_error, e),
            )
        else:
            connect_to_server(
                host=host,
                port=port,
                use_dh=use_dh,
                on_connected=lambda peer: self.after(0, self._on_connected, peer, pw, use_dh),
                on_error=lambda e:        self.after(0, self._on_conn_error, e),
            )

    def _on_connected(self, peer, password, use_dh):
        self.peer = peer
        self.key_mgr = KeyManager(
            password  = password,
            salt      = peer.salt,
            use_dh    = use_dh,
            dh_secret = peer.dh_secret,
        )
        mode_str = "DH" if use_dh else "password"
        self._sys_msg(f"Connected ({mode_str} mode). Salt: {peer.salt.hex()[:12]}…")
        self._set_connected(True)
        self._update_epoch_label()
        self.connect_btn.config(text="Connect")
        peer.start_receiving(
            on_message    = self._on_message_received,
            on_disconnect = lambda: self.after(0, self._handle_disconnect),
        )

    def _on_conn_error(self, err):
        self._sys_msg(f"Connection error: {err}")
        self.connect_btn.config(state="normal", text="Connect")

    def _disconnect(self):
        if self.peer:
            self.peer.close()
        self._handle_disconnect()

    def _handle_disconnect(self):
        self.peer    = None
        self.key_mgr = None
        self._set_connected(False)
        self._sys_msg("Disconnected.")

    # ------------------------------------------------------------------ #
    #  Send
    # ------------------------------------------------------------------ #

    def _send_message(self):
        if not self.peer or not self.key_mgr:
            return
        text = self.msg_entry.get().strip()
        if not text:
            return
        self.msg_entry.delete(0, "end")

        key    = self.key_mgr.key
        mode   = self.enc_var.get()
        sender = self.user_var.get()
        epoch  = self.key_mgr.current_epoch()

        if mode == "Double":
            payload = double_encrypt(key, text)
        else:
            payload = encrypt(key, text)

        envelope = pack_message(payload, sender, epoch, mode=mode.lower())

        try:
            self.peer.send(envelope)
        except ConnectionError as e:
            self._sys_msg(f"Send error: {e}")
            return

        # Display ciphertext for sent message
        ct_hex = base64.b64decode(payload["ciphertext"]).hex()
        ct_display = textwrap.fill(ct_hex, 56)

        self._append_chat([
            (f"[{_ts()}] ", "ts"),
            (f"{sender} (you): ", "me"),
            (text, "plain"),
        ])
        self._append_chat([
            ("  ↳ Ciphertext: ", "ts"),
            (ct_display, "cipher"),
        ])

        rotated = self.key_mgr.record_message()
        if rotated:
            self._append_chat([("  ⟳ Key rotated → epoch "
                                f"{self.key_mgr.current_epoch()}", "epoch")])
        self._update_epoch_label()

    # ------------------------------------------------------------------ #
    #  Receive
    # ------------------------------------------------------------------ #

    def _on_message_received(self, raw: str):
        """Called from background thread – must schedule UI updates on main thread."""
        try:
            envelope = unpack_message(raw)
        except Exception:
            self._sys_msg("Received malformed message.")
            return

        if not self.key_mgr:
            return

        sender  = envelope.get("sender", "?")
        mode    = envelope.get("mode", "standard")
        payload = envelope.get("payload", {})
        epoch   = envelope.get("epoch", 0)

        # Sync epoch if peer has rotated
        while self.key_mgr.current_epoch() < epoch:
            self.key_mgr.force_rotate()

        key = self.key_mgr.key
        try:
            if mode == "double":
                plaintext = double_decrypt(key, payload)
            else:
                plaintext = decrypt(key, payload)
            error = None
        except Exception as e:
            plaintext = "[DECRYPTION FAILED]"
            error = str(e)

        ct_hex     = base64.b64decode(payload["ciphertext"]).hex()
        ct_display = textwrap.fill(ct_hex, 56)

        self._append_chat([
            (f"[{_ts()}] ", "ts"),
            (f"{sender}: ", "sender"),
            (plaintext if not error else f"[DECRYPTION ERROR: {error}]", "plain"),
        ])
        self._append_chat([
            ("  ↳ Received ciphertext: ", "ts"),
            (ct_display, "cipher"),
        ])

        rotated = self.key_mgr.record_message()
        if rotated:
            self._append_chat([("  ⟳ Key rotated → epoch "
                                f"{self.key_mgr.current_epoch()}", "epoch")])
        self._update_epoch_label()

    # ------------------------------------------------------------------ #
    #  Manual key rotation
    # ------------------------------------------------------------------ #

    def _manual_rotate(self):
        if not self.key_mgr:
            self._sys_msg("Not connected — no key to rotate.")
            return
        self.key_mgr.force_rotate()
        self._sys_msg(f"Key manually rotated → epoch {self.key_mgr.current_epoch()}")
        self._update_epoch_label()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = SecureMessengerApp()
    app.mainloop()
