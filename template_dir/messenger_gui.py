"""
messenger_gui.py
Graphical front-end for Secure P2P Messenger.
"""

import tkinter as tk
from tkinter import scrolledtext, messagebox
import base64, datetime, textwrap

from crypto_core import (
    KeyManager, encrypt, decrypt,
    double_encrypt, double_decrypt,
    pack_message, unpack_message,
)
from network import start_server, connect_to_server, PeerConnectionError


# --- Theme colors and fonts ---
BG_DARK, BG_PANEL, BG_ENTRY = "#0d1117", "#161b22", "#21262d"
ACCENT, ACCENT2, WARN        = "#58a6ff", "#3fb950", "#f0883e"
TEXT_MAIN, TEXT_DIM, TEXT_DARK = "#c9d1d9", "#8b949e", "#0d1117"
TEXT_CIPHER, BORDER          = "#f78166", "#30363d"

FONT_TITLE = ("Courier New", 18, "bold")
FONT_BODY  = ("Courier New", 15)
FONT_SMALL = ("Courier New", 12)


def _ts():
    # Short timestamp shown next to every chat line
    return datetime.datetime.now().strftime("%H:%M:%S")


class SecureMessengerApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("Secure P2P Messenger")
        self.configure(bg=BG_DARK)
        self.geometry("900x700")
        self.minsize(780, 580)

        # Both are None until a connection is established
        self.peer    = None
        self.key_mgr = None

        self._build_ui()

    # --- UI Layout ---

    def _build_ui(self):
        # Top bar with app title on the left and live connection status on the right
        top = tk.Frame(self, bg=BG_DARK, pady=6)
        top.pack(fill="x", padx=12)
        tk.Label(top, text="SECURE P2P MESSENGER",
                 font=FONT_TITLE, fg=ACCENT, bg=BG_DARK).pack(side="left")
        self.status_lbl = tk.Label(top, text="● Disconnected",
                                   font=FONT_SMALL, fg=TEXT_CIPHER, bg=BG_DARK)
        self.status_lbl.pack(side="right")

        # Thin horizontal line separating the top bar from the rest
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # Split the window into left (settings) and right (chat) panes
        paned = tk.PanedWindow(self, orient="horizontal", bg=BG_DARK,
                               sashwidth=4, sashrelief="flat")
        paned.pack(fill="both", expand=True)

        left = tk.Frame(paned, bg=BG_PANEL, width=250)
        paned.add(left, minsize=220)
        self._build_settings(left)

        right = tk.Frame(paned, bg=BG_DARK)
        paned.add(right, minsize=440)
        self._build_chat(right)

    def _lbl(self, parent, text):
        # Reusable dim label used above every input field
        return tk.Label(parent, text=text, font=FONT_SMALL,
                        fg=TEXT_DIM, bg=BG_PANEL, anchor="w")

    def _entry(self, parent, **kw):
        # Reusable styled entry field — passes any extra kwargs straight to tk.Entry
        return tk.Entry(parent, font=FONT_BODY, bg=BG_ENTRY, fg=TEXT_MAIN,
                        insertbackground=ACCENT, relief="flat", bd=4,
                        highlightthickness=1, highlightcolor=ACCENT,
                        highlightbackground=BORDER, **kw)

    def _divider(self, parent):
        # 1px horizontal line used to visually separate settings sections
        tk.Frame(parent, bg=BORDER, height=1).pack(fill="x", padx=12, pady=8)

    def _build_settings(self, parent):
        p = {"padx": 12, "pady": 3}  # shared padding shorthand for this panel

        tk.Label(parent, text="CONNECTION", font=FONT_SMALL,
                 fg=ACCENT, bg=BG_PANEL).pack(anchor="w", padx=12, pady=(14, 2))

        # Server listens for incoming connections; Client connects to a server
        self._lbl(parent, "Role").pack(anchor="w", **p)
        self.role_var = tk.StringVar(value="Host")
        rf = tk.Frame(parent, bg=BG_PANEL)
        rf.pack(fill="x", padx=12, pady=2)
        for r in ("Host", "Client"):
            tk.Radiobutton(rf, text=r, variable=self.role_var, value=r,
                           bg=BG_PANEL, fg=TEXT_MAIN, selectcolor=BG_ENTRY,
                           activebackground=BG_PANEL, font=FONT_BODY,
                           command=self._on_role_change).pack(side="left", padx=4)

        # IP field is only relevant when acting as Client
        self._lbl(parent, "Peer IP (client only)").pack(anchor="w", **p)
        self.host_var   = tk.StringVar(value="127.0.0.1")
        self.host_entry = self._entry(parent, textvariable=self.host_var, state="disabled")
        self.host_entry.pack(fill="x", **p)

        self._lbl(parent, "Port").pack(anchor="w", **p)
        self.port_var = tk.StringVar(value="9999")
        self._entry(parent, textvariable=self.port_var).pack(fill="x", **p)

        self._lbl(parent, "Username").pack(anchor="w", **p)
        self.user_var = tk.StringVar(value="Alice")
        self._entry(parent, textvariable=self.user_var).pack(fill="x", **p)

        self._divider(parent)
        tk.Label(parent, text="SECURITY", font=FONT_SMALL,
                 fg=ACCENT, bg=BG_PANEL).pack(anchor="w", **p)

        self.pw_label = self._lbl(parent, "Shared Password")
        self.pw_label.pack(anchor="w", **p)
        self.pw_var   = tk.StringVar()
        # show="●" masks the password characters as the user types
        self.pw_entry = self._entry(parent, textvariable=self.pw_var, show="●")
        self.pw_entry.pack(fill="x", **p)

        # Enabling DH disables the password field since a shared secret is derived automatically
        self.dh_var = tk.BooleanVar(value=False)
        tk.Checkbutton(parent, text="DH Key Exchange (no password)",
                       variable=self.dh_var, bg=BG_PANEL, fg=TEXT_MAIN,
                       selectcolor=BG_ENTRY, activebackground=BG_PANEL,
                       font=FONT_SMALL,
                       command=self._on_dh_toggle).pack(anchor="w", padx=12, pady=2)

        # Standard = AES-256-CBC; Double = two ciphers XOR'd together (extra credit)
        self._lbl(parent, "Encryption Mode").pack(anchor="w", **p)
        self.enc_var = tk.StringVar(value="Standard")
        ef = tk.Frame(parent, bg=BG_PANEL)
        ef.pack(fill="x", padx=12, pady=2)
        for m in ("Standard", "Double"):
            tk.Radiobutton(ef, text=m, variable=self.enc_var, value=m,
                           bg=BG_PANEL, fg=TEXT_MAIN, selectcolor=BG_ENTRY,
                           activebackground=BG_PANEL,
                           font=FONT_BODY).pack(side="left", padx=4)

        self._divider(parent)
        tk.Label(parent, text="KEY MANAGEMENT", font=FONT_SMALL,
                 fg=ACCENT, bg=BG_PANEL).pack(anchor="w", **p)

        # Updates live as messages are sent and received
        self.epoch_lbl = tk.Label(parent, text="Epoch: —  |  Msgs: —",
                                  font=FONT_SMALL, fg=TEXT_DIM, bg=BG_PANEL)
        self.epoch_lbl.pack(anchor="w", padx=12)

        tk.Button(parent, text="⟳  Rotate Key Now",
                  font=FONT_SMALL, bg=BG_ENTRY, fg=WARN, relief="flat",
                  cursor="hand2", activebackground=BG_PANEL, activeforeground=WARN,
                  command=self._manual_rotate).pack(fill="x", padx=12, pady=4)

        self._divider(parent)

        self.connect_btn = tk.Button(parent, text="Connect",
                                     font=FONT_BODY, bg=ACCENT, fg=BG_DARK,
                                     relief="flat", cursor="hand2",
                                     activebackground="#79b8ff",
                                     command=self._connect, disabledforeground=TEXT_DARK)
        self.connect_btn.pack(fill="x", padx=12, pady=3)

        # Starts disabled — only enabled once a connection is active
        self.disconnect_btn = tk.Button(parent, text="Disconnect",
                                        font=FONT_BODY, bg=BG_ENTRY, fg=TEXT_DIM,
                                        relief="flat", cursor="hand2",
                                        activebackground=BG_ENTRY, state="disabled",
                                        command=self._disconnect, disabledforeground=TEXT_DARK)
        self.disconnect_btn.pack(fill="x", padx=12, pady=3)

        self._divider(parent)
        # Read-only box showing key fingerprint and epoch so both peers can verify they match
        self.key_info = tk.Text(parent, height=4, font=FONT_SMALL, bg=BG_ENTRY,
                                fg=TEXT_DIM, relief="flat", bd=4,
                                wrap="word", state="disabled")
        self.key_info.pack(fill="x", padx=12, pady=2)

    def _build_chat(self, parent):
        chat_frame = tk.Frame(parent, bg=BG_DARK)
        chat_frame.pack(fill="both", expand=True, padx=8, pady=(8, 4))

        # ScrolledText stays locked (state=disabled) and is only briefly unlocked to insert text
        self.chat_display = scrolledtext.ScrolledText(
            chat_frame, font=FONT_BODY, bg=BG_PANEL, fg=TEXT_MAIN,
            relief="flat", wrap="word", state="disabled", padx=10, pady=8,
            selectbackground=ACCENT,
        )
        self.chat_display.pack(fill="both", expand=True)

        # Each tag styles a different part of a message line (timestamp, name, ciphertext, etc.)
        tags = {
            "ts":     (TEXT_DIM,    FONT_SMALL),
            "sender": (ACCENT,      ("Courier New", 10, "bold")),
            "me":     (ACCENT2,     ("Courier New", 10, "bold")),
            "plain":  (TEXT_MAIN,   FONT_BODY),
            "cipher": (TEXT_CIPHER, FONT_SMALL),
            "sys":    (WARN,        FONT_SMALL),
            "epoch":  ("#d2a8ff",   FONT_SMALL),
        }
        for tag, (fg, font) in tags.items():
            self.chat_display.tag_config(tag, foreground=fg, font=font)

        input_frame = tk.Frame(parent, bg=BG_DARK)
        input_frame.pack(fill="x", padx=8, pady=(0, 8))

        # Message input — disabled until connected so users can't send before the handshake
        self.msg_entry = tk.Entry(input_frame, font=FONT_BODY, bg=BG_ENTRY,
                                  fg=TEXT_MAIN, insertbackground=ACCENT,
                                  relief="flat", bd=6, highlightthickness=1,
                                  highlightcolor=ACCENT, highlightbackground=BORDER,
                                  state="disabled")
        self.msg_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        # Allow sending with Enter key as well as clicking the button
        self.msg_entry.bind("<Return>", lambda e: self._send_message())

        self.send_btn = tk.Button(input_frame, text="Send  ▶",
                                  font=FONT_BODY, bg=ACCENT, fg=BG_DARK,
                                  relief="flat", cursor="hand2",
                                  activebackground="#79b8ff", state="disabled",
                                  command=self._send_message)
        self.send_btn.pack(side="right")

    # --- UI Helpers ---

    def _on_role_change(self):
        # Server always binds to 0.0.0.0, so the IP field is only needed for Client
        state = "normal" if self.role_var.get() == "Client" else "disabled"
        self.host_entry.config(state=state)

    def _on_dh_toggle(self):
        # Grey out the password field visually when DH is selected
        if self.dh_var.get():
            self.pw_entry.config(state="disabled")
            self.pw_label.config(fg="#3d444d")
        else:
            self.pw_entry.config(state="normal")
            self.pw_label.config(fg=TEXT_DIM)

    def _set_connected(self, connected: bool):
        # Flip all interactive widgets between their connected and disconnected states
        on, off = ("normal", "disabled") if connected else ("disabled", "normal")
        self.connect_btn.config(state=off)
        self.disconnect_btn.config(state=on)
        self.msg_entry.config(state=on)
        self.send_btn.config(state=on)
        if connected:
            self.status_lbl.config(text="● Connected", fg=ACCENT2)
            self.msg_entry.focus_set()  # move cursor to input so the user can type immediately
        else:
            self.status_lbl.config(text="● Disconnected", fg=TEXT_CIPHER)

    def _append_chat(self, parts):
        # Schedules the insert on the main thread — safe to call from the background recv thread
        def _do():
            self.chat_display.config(state="normal")
            for text, tag in parts:
                self.chat_display.insert("end", text, tag)
            self.chat_display.insert("end", "\n")
            self.chat_display.see("end")  # auto-scroll to the latest message
            self.chat_display.config(state="disabled")
        self.after(0, _do)

    def _sys_msg(self, text):
        # System messages (connection events, errors) shown in a different color from chat
        self._append_chat([(f"[{_ts()}] ", "ts"), (f"⚙  {text}", "sys")])

    def _update_epoch_label(self):
        if not self.key_mgr:
            return
        def _do():
            e  = self.key_mgr.current_epoch()
            c  = self.key_mgr.msg_count
            fp = self.key_mgr.key.hex()[:16]  # first 16 hex chars as a short fingerprint
            self.epoch_lbl.config(text=f"Epoch: {e}  |  Msgs: {c}")
            # Briefly unlock the read-only box to rewrite its contents
            self.key_info.config(state="normal")
            self.key_info.delete("1.0", "end")
            self.key_info.insert("end",
                f"Key fingerprint:\n{fp}…\n"
                f"Epoch: {e}\n"
                f"Algo: AES-256-{'CBC+CFB⊕' if self.enc_var.get() == 'Double' else 'CBC'}"
            )
            self.key_info.config(state="disabled")
        self.after(0, _do)

    # --- Connection ---

    def _connect(self):
        role   = self.role_var.get()
        host   = self.host_var.get().strip()
        use_dh = self.dh_var.get()
        pw     = self.pw_var.get()

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
        self._sys_msg(f"{'Listening on' if role == 'Server' else 'Connecting to'} {host}:{port} …")

        # Callbacks from the network layer arrive on background threads, so route them to main
        on_conn  = lambda peer: self.after(0, self._on_connected, peer, pw, use_dh)
        on_error = lambda e:    self.after(0, self._on_conn_error, e)

        if role == "Server":
            start_server("0.0.0.0", port, use_dh, on_conn, on_error)
        else:
            connect_to_server(host, port, use_dh, on_conn, on_error)

    def _on_connected(self, peer, password, use_dh):
        self.peer    = peer
        # KeyManager derives the encryption key from the shared password and salt
        self.key_mgr = KeyManager(password=password, salt=peer.salt,
                                  use_dh=use_dh, dh_secret=peer.dh_secret)
        self._sys_msg(f"Connected ({'DH' if use_dh else 'password'} mode). "
                      f"Salt: {peer.salt.hex()[:12]}…")
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

    # --- Send ---

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

        # Pick encryption function based on the selected mode
        payload  = double_encrypt(key, text) if mode == "Double" else encrypt(key, text)
        envelope = pack_message(payload, sender, epoch, mode=mode.lower())

        try:
            self.peer.send(envelope)
        except PeerConnectionError as e:
            self._sys_msg(f"Send error: {e}")
            return

        # Decode ciphertext to hex and wrap it so long lines don't overflow the chat window
        ct_hex = textwrap.fill(base64.b64decode(payload["ciphertext"]).hex(), 56)
        self._append_chat([(f"[{_ts()}] ", "ts"), (f"{sender} (you): ", "me"), (text, "plain")])
        self._append_chat([("  ↳ Ciphertext: ", "ts"), (ct_hex, "cipher")])

        # record_message() returns True when the key just automatically rotated
        if self.key_mgr.record_message():
            self._append_chat([(f"  ⟳ Key rotated → epoch {self.key_mgr.current_epoch()}", "epoch")])
        self._update_epoch_label()

    # --- Receive ---

    def _on_message_received(self, raw: str):
        # Runs on the background recv thread — never touch UI widgets directly here
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

        # If the peer rotated their key ahead of us, catch up before attempting to decrypt
        while self.key_mgr.current_epoch() < epoch:
            self.key_mgr.force_rotate()

        try:
            plaintext = (double_decrypt if mode == "double" else decrypt)(self.key_mgr.key, payload)
            error = None
        except Exception as e:
            plaintext, error = "[DECRYPTION FAILED]", str(e)

        ct_hex = textwrap.fill(base64.b64decode(payload["ciphertext"]).hex(), 56)
        label  = plaintext if not error else f"[DECRYPTION ERROR: {error}]"

        self._append_chat([(f"[{_ts()}] ", "ts"), (f"{sender}: ", "sender"), (label, "plain")])
        self._append_chat([("  ↳ Received ciphertext: ", "ts"), (ct_hex, "cipher")])

        if self.key_mgr.record_message():
            self._append_chat([(f"  ⟳ Key rotated → epoch {self.key_mgr.current_epoch()}", "epoch")])
        self._update_epoch_label()

    # --- Key Rotation ---

    def _manual_rotate(self):
        if not self.key_mgr:
            self._sys_msg("Not connected — no key to rotate.")
            return
        self.key_mgr.force_rotate()
        self._sys_msg(f"Key manually rotated → epoch {self.key_mgr.current_epoch()}")
        self._update_epoch_label()


if __name__ == "__main__":
    SecureMessengerApp().mainloop()