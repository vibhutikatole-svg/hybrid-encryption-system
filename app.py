"""
app.py - Graphical User Interface for Hybrid Encryption System (RSA + AES)

Desktop application demonstrating hybrid cryptography for B.Tech Cryptography
and Network Security mini project:
- Section 1: RSA Key Management (RSA-2048 with OAEP-SHA256)
- Section 2: File Encryption (AES-256-GCM + RSA key encapsulation)
- Section 3: File Decryption (RSA unwrapping + AES-GCM AEAD integrity check)
- Section 4: Status & Cryptographic Audit Log
- About Dialog: Comprehensive technical and academic breakdown
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
from typing import Optional

# Import pure cryptographic routines
from crypto_utils import (
    generate_rsa_key_pair,
    check_keys_exist,
    encrypt_file,
    decrypt_file,
    CryptoError,
    KeyNotFoundError,
    InvalidPackageError,
    IntegrityVerificationError,
    DecryptionError,
    DEFAULT_KEYS_DIR
)


class HybridCryptoApp(tk.Tk):
    """Modern Desktop GUI for Hybrid Encryption System (RSA + AES)."""

    def __init__(self):
        super().__init__()

        # Window Configuration
        self.title("Hybrid Encryption System")
        self.geometry("860x740")
        self.minsize(780, 640)

        # Base directories
        self.app_dir = os.path.dirname(os.path.abspath(__file__))
        self.keys_dir = os.path.join(self.app_dir, DEFAULT_KEYS_DIR)
        os.makedirs(self.keys_dir, exist_ok=True)

        # State Variables
        self.var_encrypt_file = tk.StringVar(value="")
        self.var_decrypt_file = tk.StringVar(value="")
        self.var_status_msg = tk.StringVar(value="Ready. Generate RSA keys or select a file to begin.")

        # Configure Styling
        self._configure_styles()

        # Build GUI Layout
        self._create_header()
        self._create_main_container()
        self._create_footer()

        # Initialize Key Status and Log
        self.refresh_key_status()
        self.log_message("Hybrid Encryption System initialized successfully.", "INFO")
        self.log_message(f"Keys directory set to: {self.keys_dir}", "INFO")
        self.log_message("Algorithms: RSA-2048-OAEP (SHA-256) + AES-256-GCM (AEAD).", "INFO")

    def _configure_styles(self):
        """Set up cohesive color palette and ttk styles."""
        # Color Palette - Professional Slate Theme
        self.col_bg = "#0f172a"         # Deep Slate 900
        self.col_card = "#1e293b"       # Slate 800
        self.col_card_inner = "#334155" # Slate 700
        self.col_console = "#030712"    # Dark terminal 950
        self.col_text_main = "#f8fafc"  # Slate 50
        self.col_text_sub = "#94a3b8"   # Slate 400
        self.col_blue = "#38bdf8"       # Sky Blue Accent
        self.col_green = "#10b981"      # Emerald Green Accent
        self.col_amber = "#f59e0b"      # Amber Warning
        self.col_rose = "#f43f5e"       # Rose Error
        self.col_indigo = "#6366f1"     # Indigo Accent

        self.configure(bg=self.col_bg)

        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # Global Defaults
        style.configure(".", background=self.col_bg, foreground=self.col_text_main, font=("Segoe UI", 10))
        
        # Section LabelFrames
        style.configure(
            "Section.TLabelframe",
            background=self.col_card,
            foreground=self.col_blue,
            relief="solid",
            borderwidth=1,
            labelmargins=6
        )
        style.configure(
            "Section.TLabelframe.Label",
            background=self.col_card,
            foreground=self.col_blue,
            font=("Segoe UI", 11, "bold")
        )

        # Standard Label Styles
        style.configure("Card.TLabel", background=self.col_card, foreground=self.col_text_main, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=self.col_card, foreground=self.col_text_sub, font=("Segoe UI", 9))
        style.configure("Badge.TLabel", background=self.col_card_inner, foreground=self.col_text_main, font=("Segoe UI", 9, "bold"), padding=4)

        # Buttons
        style.configure(
            "ActionPrimary.TButton",
            background="#2563eb",
            foreground="#ffffff",
            font=("Segoe UI", 10, "bold"),
            padding=(14, 7),
            borderwidth=0
        )
        style.map("ActionPrimary.TButton", background=[("active", "#1d4ed8"), ("pressed", "#1e40af")])

        style.configure(
            "ActionSuccess.TButton",
            background="#059669",
            foreground="#ffffff",
            font=("Segoe UI", 10, "bold"),
            padding=(14, 7),
            borderwidth=0
        )
        style.map("ActionSuccess.TButton", background=[("active", "#047857"), ("pressed", "#065f46")])

        style.configure(
            "ActionIndigo.TButton",
            background="#4f46e5",
            foreground="#ffffff",
            font=("Segoe UI", 10, "bold"),
            padding=(14, 7),
            borderwidth=0
        )
        style.map("ActionIndigo.TButton", background=[("active", "#4338ca"), ("pressed", "#3730a3")])

        style.configure(
            "Secondary.TButton",
            background=self.col_card_inner,
            foreground="#ffffff",
            font=("Segoe UI", 9),
            padding=(10, 5),
            borderwidth=0
        )
        style.map("Secondary.TButton", background=[("active", "#475569"), ("pressed", "#1e293b")])

        # Entry Styling
        style.configure(
            "Custom.TEntry",
            fieldbackground="#0f172a",
            foreground="#f8fafc",
            insertcolor="#38bdf8",
            padding=6,
            borderwidth=1,
            relief="solid"
        )

    def _create_header(self):
        """Build the top header with project title, subtitle, and About button."""
        header_bar = tk.Frame(self, bg=self.col_bg)
        header_bar.pack(fill="x", padx=20, pady=(15, 10))

        # Title and Subtitle container
        title_box = tk.Frame(header_bar, bg=self.col_bg)
        title_box.pack(side="left", fill="x", expand=True)

        lbl_title = tk.Label(
            title_box,
            text="Hybrid Encryption System",
            font=("Segoe UI", 18, "bold"),
            bg=self.col_bg,
            fg=self.col_text_main
        )
        lbl_title.pack(anchor="w")

        lbl_sub = tk.Label(
            title_box,
            text="Secure File Encryption using RSA + AES",
            font=("Segoe UI", 11, "bold"),
            bg=self.col_bg,
            fg=self.col_blue
        )
        lbl_sub.pack(anchor="w", pady=(2, 0))

        lbl_course = tk.Label(
            title_box,
            text="B.Tech Cryptography & Network Security Mini Project",
            font=("Segoe UI", 9, "italic"),
            bg=self.col_bg,
            fg=self.col_text_sub
        )
        lbl_course.pack(anchor="w", pady=(1, 0))

        # About Button
        btn_about = ttk.Button(
            header_bar,
            text="ℹ About System",
            style="Secondary.TButton",
            command=self.handle_show_about
        )
        btn_about.pack(side="right", padx=(10, 0), pady=5)

    def _create_main_container(self):
        """Construct the four core functional sections."""
        container = tk.Frame(self, bg=self.col_bg)
        container.pack(fill="both", expand=True, padx=20, pady=5)

        # -------------------------------------------------------------
        # SECTION 1: RSA Key Management
        # -------------------------------------------------------------
        sec_keys = ttk.LabelFrame(container, text=" 1. RSA Key Management ", style="Section.TLabelframe", padding=12)
        sec_keys.pack(fill="x", pady=(0, 10))

        sec_keys_row = tk.Frame(sec_keys, bg=self.col_card)
        sec_keys_row.pack(fill="x")

        # Key Status Indicators
        key_info_box = tk.Frame(sec_keys_row, bg=self.col_card)
        key_info_box.pack(side="left", fill="x", expand=True)

        pub_row = tk.Frame(key_info_box, bg=self.col_card)
        pub_row.pack(anchor="w", pady=2)
        tk.Label(pub_row, text="Public Key (public_key.pem): ", font=("Segoe UI", 9), bg=self.col_card, fg=self.col_text_sub).pack(side="left")
        self.lbl_pub_status = tk.Label(pub_row, text="Checking...", font=("Segoe UI", 9, "bold"), bg=self.col_card, fg=self.col_amber)
        self.lbl_pub_status.pack(side="left")

        priv_row = tk.Frame(key_info_box, bg=self.col_card)
        priv_row.pack(anchor="w", pady=2)
        tk.Label(priv_row, text="Private Key (private_key.pem): ", font=("Segoe UI", 9), bg=self.col_card, fg=self.col_text_sub).pack(side="left")
        self.lbl_priv_status = tk.Label(priv_row, text="Checking...", font=("Segoe UI", 9, "bold"), bg=self.col_card, fg=self.col_amber)
        self.lbl_priv_status.pack(side="left")

        # Generate RSA Keys Button
        self.btn_gen_keys = ttk.Button(
            sec_keys_row,
            text="🔑 Generate RSA Keys",
            style="ActionIndigo.TButton",
            command=self.handle_generate_keys
        )
        self.btn_gen_keys.pack(side="right", padx=(10, 0))

        # -------------------------------------------------------------
        # SECTION 2: File Encryption
        # -------------------------------------------------------------
        sec_encrypt = ttk.LabelFrame(container, text=" 2. File Encryption (AES-256-GCM + RSA-2048-OAEP) ", style="Section.TLabelframe", padding=12)
        sec_encrypt.pack(fill="x", pady=(0, 10))

        enc_row = tk.Frame(sec_encrypt, bg=self.col_card)
        enc_row.pack(fill="x")

        tk.Label(enc_row, text="Target File:", font=("Segoe UI", 9, "bold"), bg=self.col_card, fg=self.col_text_main).pack(side="left", padx=(0, 8))

        self.entry_encrypt = ttk.Entry(
            enc_row,
            textvariable=self.var_encrypt_file,
            style="Custom.TEntry",
            font=("Segoe UI", 9)
        )
        self.entry_encrypt.pack(side="left", fill="x", expand=True, padx=(0, 8))

        # Select File Button
        self.btn_select_enc = ttk.Button(
            enc_row,
            text="📂 Select File",
            style="Secondary.TButton",
            command=self.handle_select_file_to_encrypt
        )
        self.btn_select_enc.pack(side="left", padx=(0, 8))

        # Encrypt File Button
        self.btn_encrypt = ttk.Button(
            enc_row,
            text="🔒 Encrypt File",
            style="ActionPrimary.TButton",
            command=self.handle_encrypt_file
        )
        self.btn_encrypt.pack(side="left")

        # -------------------------------------------------------------
        # SECTION 3: File Decryption
        # -------------------------------------------------------------
        sec_decrypt = ttk.LabelFrame(container, text=" 3. File Decryption (RSA Unwrapping + AEAD Verification) ", style="Section.TLabelframe", padding=12)
        sec_decrypt.pack(fill="x", pady=(0, 10))

        dec_row = tk.Frame(sec_decrypt, bg=self.col_card)
        dec_row.pack(fill="x")

        tk.Label(dec_row, text="Package (.enc):", font=("Segoe UI", 9, "bold"), bg=self.col_card, fg=self.col_text_main).pack(side="left", padx=(0, 8))

        self.entry_decrypt = ttk.Entry(
            dec_row,
            textvariable=self.var_decrypt_file,
            style="Custom.TEntry",
            font=("Segoe UI", 9)
        )
        self.entry_decrypt.pack(side="left", fill="x", expand=True, padx=(0, 8))

        # Select Encrypted File Button
        self.btn_select_dec = ttk.Button(
            dec_row,
            text="📂 Select Encrypted File",
            style="Secondary.TButton",
            command=self.handle_select_file_to_decrypt
        )
        self.btn_select_dec.pack(side="left", padx=(0, 8))

        # Decrypt File Button
        self.btn_decrypt = ttk.Button(
            dec_row,
            text="🔓 Decrypt File",
            style="ActionSuccess.TButton",
            command=self.handle_decrypt_file
        )
        self.btn_decrypt.pack(side="left")

        # -------------------------------------------------------------
        # SECTION 4: Status & Audit Log
        # -------------------------------------------------------------
        sec_status = ttk.LabelFrame(container, text=" 4. Status & Cryptographic Audit Log ", style="Section.TLabelframe", padding=12)
        sec_status.pack(fill="both", expand=True)

        # Current Operation Banner
        status_banner = tk.Frame(sec_status, bg=self.col_card_inner, padx=10, pady=6)
        status_banner.pack(fill="x", pady=(0, 8))

        tk.Label(status_banner, text="Current Status: ", font=("Segoe UI", 9, "bold"), bg=self.col_card_inner, fg=self.col_blue).pack(side="left")
        self.lbl_status_banner = tk.Label(
            status_banner,
            textvariable=self.var_status_msg,
            font=("Segoe UI", 9),
            bg=self.col_card_inner,
            fg=self.col_text_main
        )
        self.lbl_status_banner.pack(side="left", fill="x", expand=True)

        # Clear Log Button
        btn_clear = tk.Button(
            status_banner,
            text="Clear Log",
            font=("Segoe UI", 8),
            bg="#1e293b",
            fg=self.col_text_sub,
            activebackground="#475569",
            activeforeground="#ffffff",
            bd=0,
            padx=8,
            pady=2,
            command=self.clear_logs
        )
        btn_clear.pack(side="right")

        # Console Scrolled Text Box
        console_frame = tk.Frame(sec_status, bg=self.col_console, bd=1, relief="solid")
        console_frame.pack(fill="both", expand=True)

        self.scrollbar = tk.Scrollbar(console_frame)
        self.scrollbar.pack(side="right", fill="y")

        self.txt_log = tk.Text(
            console_frame,
            bg=self.col_console,
            fg=self.col_text_main,
            insertbackground="#ffffff",
            font=("Consolas", 9),
            wrap="word",
            yscrollcommand=self.scrollbar.set,
            bd=0,
            padx=10,
            pady=8
        )
        self.txt_log.pack(side="left", fill="both", expand=True)
        self.scrollbar.config(command=self.txt_log.yview)

        # Log Coloring Tags
        self.txt_log.tag_config("TIME", foreground="#64748b")
        self.txt_log.tag_config("INFO", foreground=self.col_blue)
        self.txt_log.tag_config("SUCCESS", foreground=self.col_green)
        self.txt_log.tag_config("WARNING", foreground=self.col_amber)
        self.txt_log.tag_config("ERROR", foreground=self.col_rose)
        self.txt_log.tag_config("HIGHLIGHT", foreground="#e2e8f0")

        self.txt_log.config(state="disabled")

    def _create_footer(self):
        """Status bar at bottom of application."""
        footer_bar = tk.Frame(self, bg="#070c18", height=26)
        footer_bar.pack(fill="x", side="bottom")

        lbl_keys_path = tk.Label(
            footer_bar,
            text=f"Keys: {self.keys_dir}",
            font=("Segoe UI", 8),
            bg="#070c18",
            fg=self.col_text_sub,
            padx=15,
            pady=4
        )
        lbl_keys_path.pack(side="left")

        lbl_crypto_spec = tk.Label(
            footer_bar,
            text="RSA-2048-OAEP (SHA-256) | AES-256-GCM (128-bit Tag)",
            font=("Segoe UI", 8, "bold"),
            bg="#070c18",
            fg=self.col_blue,
            padx=15,
            pady=4
        )
        lbl_crypto_spec.pack(side="right")

    # -----------------------------------------------------------------
    # Logging and Status Utilities
    # -----------------------------------------------------------------

    def set_status(self, message: str):
        """Update the operation status message banner."""
        self.var_status_msg.set(message)

    def log_message(self, message: str, level: str = "INFO"):
        """Append timestamped entry to the console log."""
        timestamp = datetime.now().strftime("[%H:%M:%S]")
        self.txt_log.config(state="normal")
        self.txt_log.insert("end", f"{timestamp} ", "TIME")
        self.txt_log.insert("end", f"[{level:<7}] ", level)
        self.txt_log.insert("end", f"{message}\n", "HIGHLIGHT")
        self.txt_log.see("end")
        self.txt_log.config(state="disabled")

    def clear_logs(self):
        """Clear the console audit log."""
        self.txt_log.config(state="normal")
        self.txt_log.delete("1.0", "end")
        self.txt_log.config(state="disabled")
        self.set_status("Audit log cleared.")

    def refresh_key_status(self):
        """Inspect keys folder and update visual indicators."""
        status = check_keys_exist(self.keys_dir)

        if status["public_exists"]:
            self.lbl_pub_status.config(text="[ FOUND ]", fg=self.col_green)
        else:
            self.lbl_pub_status.config(text="[ MISSING ]", fg=self.col_rose)

        if status["private_exists"]:
            self.lbl_priv_status.config(text="[ FOUND ]", fg=self.col_green)
        else:
            self.lbl_priv_status.config(text="[ MISSING ]", fg=self.col_rose)

        return status

    # -----------------------------------------------------------------
    # Event Handlers: RSA Key Management
    # -----------------------------------------------------------------

    def handle_generate_keys(self):
        """Generate RSA-2048 public and private key pair."""
        status = check_keys_exist(self.keys_dir)

        if status["public_exists"] or status["private_exists"]:
            confirm = messagebox.askyesno(
                "Overwrite Existing Keys?",
                "RSA keys already exist in the keys/ folder.\n\n"
                "WARNING: Overwriting keys will permanently prevent decryption of "
                "any files encrypted with the current key pair!\n\n"
                "Are you sure you want to generate a new key pair?",
                icon="warning"
            )
            if not confirm:
                self.set_status("RSA key generation cancelled by user.")
                self.log_message("Key generation cancelled by user.", "WARNING")
                return

        try:
            self.set_status("Generating RSA-2048 key pair (e=65537)...")
            self.log_message("Generating 2048-bit RSA key pair...", "INFO")
            
            priv_path, pub_path = generate_rsa_key_pair(self.keys_dir, key_size=2048)
            self.refresh_key_status()

            self.set_status("RSA-2048 key pair successfully generated!")
            self.log_message(f"Private Key saved: {os.path.basename(priv_path)} (PKCS#8 PEM)", "SUCCESS")
            self.log_message(f"Public Key saved: {os.path.basename(pub_path)} (SPKI PEM)", "SUCCESS")

            messagebox.showinfo(
                "RSA Keys Generated",
                f"Successfully generated RSA-2048 key pair!\n\n"
                f"• Public Key: {pub_path}\n"
                f"• Private Key: {priv_path}\n\n"
                "The system is now ready to encrypt and decrypt files."
            )
        except Exception as exc:
            self.set_status(f"Error generating keys: {exc}")
            self.log_message(f"Failed to generate RSA keys: {exc}", "ERROR")
            messagebox.showerror("Key Generation Error", f"Failed to generate RSA keys:\n{exc}")

    # -----------------------------------------------------------------
    # Event Handlers: File Encryption
    # -----------------------------------------------------------------

    def handle_select_file_to_encrypt(self):
        """Prompt user to select a file for encryption."""
        file_path = filedialog.askopenfilename(
            title="Select File to Encrypt",
            filetypes=[("All Files", "*.*")]
        )
        if not file_path:
            self.set_status("File selection cancelled by user.")
            return

        if not os.path.isfile(file_path):
            messagebox.showerror("File Not Found", f"The selected file does not exist:\n\n{file_path}")
            return

        self.var_encrypt_file.set(file_path)
        self.set_status(f"Selected file to encrypt: {os.path.basename(file_path)}")
        self.log_message(f"Selected file to encrypt: {file_path}", "INFO")

    def handle_encrypt_file(self):
        """Encrypt the selected file using AES-256-GCM and RSA-2048-OAEP."""
        # 1. Validation: Public Key Exists
        key_status = check_keys_exist(self.keys_dir)
        if not key_status["public_exists"]:
            self.set_status("Encryption halted: Public key (public_key.pem) missing.")
            self.log_message("Encryption halted: Public key not found. Please click 'Generate RSA Keys'.", "ERROR")
            messagebox.showwarning(
                "Public Key Missing",
                "RSA Public Key ('public_key.pem') not found in keys/.\n\n"
                "Please click 'Generate RSA Keys' first before encrypting."
            )
            return

        # 2. Validation: Input File Selected
        input_path = self.var_encrypt_file.get().strip()
        if not input_path:
            self.set_status("Encryption halted: No file selected.")
            self.log_message("Encryption halted: No file selected.", "WARNING")
            messagebox.showwarning(
                "No File Selected",
                "Please select a file to encrypt first using 'Select File'."
            )
            return

        # 3. Validation: Input File Exists
        if not os.path.isfile(input_path):
            self.set_status("Encryption failed: Input file does not exist.")
            self.log_message(f"Input file not found: {input_path}", "ERROR")
            messagebox.showerror(
                "File Not Found",
                f"The selected input file does not exist:\n\n{input_path}\n\nPlease choose a valid file."
            )
            return

        filename = os.path.basename(input_path)
        default_enc_name = f"{filename}.enc"
        initial_dir = os.path.dirname(input_path)

        # 4. Validation: Prompt Output Path & Handle Cancellation
        output_path = filedialog.asksaveasfilename(
            title="Save Encrypted Package (.enc)",
            initialdir=initial_dir,
            initialfile=default_enc_name,
            defaultextension=".enc",
            filetypes=[("Encrypted Packages (*.enc)", "*.enc"), ("All Files", "*.*")]
        )
        if not output_path:
            self.set_status("Encryption cancelled by user.")
            self.log_message("Encryption cancelled: Destination file selection cancelled by user.", "WARNING")
            return

        # 5. Validation: Output Path Validity
        out_dir = os.path.dirname(os.path.abspath(output_path))
        if not os.path.exists(out_dir):
            try:
                os.makedirs(out_dir, exist_ok=True)
            except Exception as exc:
                self.set_status("Encryption failed: Invalid output path.")
                self.log_message(f"Invalid output directory: {out_dir} ({exc})", "ERROR")
                messagebox.showerror(
                    "Invalid Output Path",
                    f"The specified output directory is invalid or not accessible:\n\n{out_dir}"
                )
                return

        # 6. Perform Encryption with Error Trapping
        try:
            self.set_status(f"Encrypting '{filename}'...")
            self.log_message(f"Starting encryption for: '{filename}'", "INFO")
            
            out_file, meta = encrypt_file(
                input_file_path=input_path,
                output_file_path=output_path,
                public_key_path=key_status["public_path"]
            )

            # Auto-populate decryption box for testing convenience
            self.var_decrypt_file.set(out_file)

            self.set_status(f"Successfully encrypted '{filename}' -> {os.path.basename(out_file)}")
            self.log_message("Generated fresh 256-bit AES session key & 12-byte nonce.", "INFO")
            self.log_message("Payload encrypted with AES-256-GCM (16-byte AEAD GMAC tag).", "INFO")
            self.log_message("AES session key encapsulated with RSA-2048-OAEP (SHA-256).", "INFO")
            self.log_message(
                f"Encrypted package saved: {os.path.basename(out_file)} "
                f"({meta['encrypted_size_bytes']} bytes).",
                "SUCCESS"
            )

            messagebox.showinfo(
                "Encryption Successful",
                f"File encrypted successfully!\n\n"
                f"• Input: {meta['original_filename']} ({meta['original_size_bytes']} bytes)\n"
                f"• Package: {out_file}\n"
                f"• Encrypted Size: {meta['encrypted_size_bytes']} bytes\n"
                f"• Asymmetric: {meta['asymmetric_algorithm']}\n"
                f"• Symmetric: {meta['symmetric_algorithm']}"
            )
        except KeyNotFoundError as exc:
            self.set_status(f"Key error: {exc}")
            self.log_message(f"Key error: {exc}", "ERROR")
            messagebox.showerror("Key Not Found", str(exc))
        except CryptoError as exc:
            self.set_status(f"Encryption failed: {exc}")
            self.log_message(f"Cryptographic error during encryption: {exc}", "ERROR")
            messagebox.showerror("Encryption Error", str(exc))
        except Exception as exc:
            self.set_status(f"Encryption failed: {exc}")
            self.log_message(f"Unexpected encryption error: {exc}", "ERROR")
            messagebox.showerror("Encryption Failure", f"An unexpected error occurred while encrypting:\n{exc}")

    # -----------------------------------------------------------------
    # Event Handlers: File Decryption
    # -----------------------------------------------------------------

    def handle_select_file_to_decrypt(self):
        """Prompt user to select a .enc file for decryption."""
        file_path = filedialog.askopenfilename(
            title="Select Encrypted File (.enc) to Decrypt",
            filetypes=[("Encrypted Packages (*.enc)", "*.enc"), ("All Files", "*.*")]
        )
        if file_path:
            self.var_decrypt_file.set(file_path)
            self.set_status(f"Encrypted package selected: {os.path.basename(file_path)}")
            self.log_message(f"Selected encrypted file: {file_path}", "INFO")

    def handle_decrypt_file(self):
        """Decrypt the selected .enc package using RSA and AES-GCM."""
        # 1. Verify Private Key Exists
        key_status = check_keys_exist(self.keys_dir)
        if not key_status["private_exists"]:
            self.set_status("Decryption halted: Private key (private_key.pem) missing.")
            self.log_message("Decryption halted: Private key not found in keys/.", "ERROR")
            messagebox.showerror(
                "Private Key Missing",
                "RSA Private Key ('private_key.pem') not found in keys/.\n\n"
                "Decryption requires the private key corresponding to the public key used during encryption."
            )
            return

        # 2. Verify or Prompt for .enc Input File
        enc_path = self.var_decrypt_file.get().strip()
        if not enc_path or not os.path.isfile(enc_path):
            enc_path = filedialog.askopenfilename(
                title="Select Encrypted File (.enc) to Decrypt",
                filetypes=[("Encrypted Packages (*.enc)", "*.enc"), ("All Files", "*.*")]
            )
            if not enc_path:
                return
            self.var_decrypt_file.set(enc_path)

        # 3. Prompt Destination Folder
        dest_dir = filedialog.askdirectory(
            title="Select Destination Folder for Recovered File",
            initialdir=os.path.dirname(enc_path)
        )
        if not dest_dir:
            self.set_status("Decryption cancelled by user.")
            return

        # 4. Perform Decryption
        try:
            self.set_status(f"Decrypting '{os.path.basename(enc_path)}'...")
            self.log_message(f"Initiating decryption for package: '{os.path.basename(enc_path)}'", "INFO")

            recovered_file, meta = decrypt_file(
                encrypted_file_path=enc_path,
                output_dir=dest_dir,
                private_key_path=key_status["private_path"]
            )

            self.set_status(f"Successfully recovered '{meta['original_filename']}'!")
            self.log_message("RSA private key unwrapped AES session key (OAEP-SHA256 verified).", "INFO")
            self.log_message("AES-GCM integrity authentication confirmed (Tag Valid).", "INFO")
            self.log_message(
                f"File successfully restored: '{meta['original_filename']}' "
                f"({meta['recovered_size_bytes']} bytes) -> {recovered_file}",
                "SUCCESS"
            )

            messagebox.showinfo(
                "Decryption Successful",
                f"File decrypted successfully!\n\n"
                f"• Restored File: {meta['original_filename']}\n"
                f"• Recovered Size: {meta['recovered_size_bytes']} bytes\n"
                f"• Destination: {recovered_file}\n\n"
                f"Cryptographic Integrity: AEAD Tag Authenticated."
            )
        except IntegrityVerificationError as exc:
            self.set_status("CRITICAL: Ciphertext integrity check failed!")
            self.log_message(f"SECURITY ALERT: {exc}", "ERROR")
            messagebox.showerror(
                "Integrity Verification Failed",
                "SECURITY ALERT: Authentication tag verification failed!\n\n"
                "The ciphertext has been modified, tampered with, or corrupted.\n"
                "Decryption was aborted to protect system integrity."
            )
        except DecryptionError as exc:
            self.set_status(f"Decryption error: {exc}")
            self.log_message(f"Decryption failed: {exc}", "ERROR")
            messagebox.showerror(
                "Decryption Error",
                f"Decryption failed:\n\n{exc}\n\n"
                "Ensure that keys/private_key.pem matches the public key used to encrypt the file."
            )
        except InvalidPackageError as exc:
            self.set_status(f"Invalid package: {exc}")
            self.log_message(f"Package error: {exc}", "ERROR")
            messagebox.showerror("Invalid Package", f"Invalid encrypted package:\n\n{exc}")
        except KeyNotFoundError as exc:
            self.set_status(f"Key missing: {exc}")
            self.log_message(f"Key error: {exc}", "ERROR")
            messagebox.showerror("Key Error", str(exc))
        except Exception as exc:
            self.set_status(f"Decryption failure: {exc}")
            self.log_message(f"Unexpected error: {exc}", "ERROR")
            messagebox.showerror("Decryption Failed", f"An unexpected error occurred:\n{exc}")

    # -----------------------------------------------------------------
    # Event Handlers: About System Dialog
    # -----------------------------------------------------------------

    def handle_show_about(self):
        """Display academic and technical project specifications."""
        about_dialog = tk.Toplevel(self)
        about_dialog.title("About - Hybrid Encryption System")
        about_dialog.geometry("620x540")
        about_dialog.minsize(540, 460)
        about_dialog.configure(bg=self.col_card)
        about_dialog.transient(self)
        about_dialog.grab_set()

        content = tk.Frame(about_dialog, bg=self.col_card, padx=24, pady=20)
        content.pack(fill="both", expand=True)

        # Title
        tk.Label(
            content,
            text="Hybrid Encryption System",
            font=("Segoe UI", 16, "bold"),
            bg=self.col_card,
            fg=self.col_blue
        ).pack(anchor="w")

        tk.Label(
            content,
            text="B.Tech Cryptography & Network Security Project",
            font=("Segoe UI", 10, "bold"),
            bg=self.col_card,
            fg=self.col_green
        ).pack(anchor="w", pady=(2, 12))

        # Specifications Box
        specs_frame = tk.Frame(content, bg=self.col_console, bd=1, relief="solid", padx=14, pady=12)
        specs_frame.pack(fill="x", pady=(0, 14))

        tech_specs = [
            ("Asymmetric Algorithm:", "RSA-2048-OAEP (SHA-256 Digest & MGF1)"),
            ("Symmetric Algorithm:", "AES-256-GCM (Galois/Counter Mode AEAD)"),
            ("Authentication Tag:", "128-bit (16-byte) Cryptographic GMAC Tag"),
            ("Session Nonce:", "96-bit (12-byte) Cryptographic Random Nonce"),
            ("Language & Runtime:", "Python 3 (Python 3.9+)"),
            ("GUI Framework:", "Tkinter with modern TTK styling"),
            ("Cryptographic Core:", "Python 'cryptography' library (hazmat primitives)")
        ]

        for label, val in tech_specs:
            row = tk.Frame(specs_frame, bg=self.col_console)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=f"{label:<25}", font=("Segoe UI", 9, "bold"), bg=self.col_console, fg=self.col_blue).pack(side="left")
            tk.Label(row, text=val, font=("Segoe UI", 9), bg=self.col_console, fg=self.col_text_main).pack(side="left")

        # Architectural Text
        txt_desc = tk.Text(
            content,
            bg=self.col_console,
            fg=self.col_text_main,
            font=("Segoe UI", 9),
            wrap="word",
            bd=0,
            padx=12,
            pady=10
        )
        txt_desc.pack(fill="both", expand=True, pady=(0, 14))

        explanation = (
            "Why Hybrid Encryption for Cryptography & Network Security?\n\n"
            "1. Overcomes RSA Limitations:\n"
            "   Pure RSA is computationally slow and cannot encrypt data larger than the modulus.\n"
            "   With OAEP-SHA256, RSA-2048 can only encrypt up to 190 bytes. In hybrid encryption,\n"
            "   RSA encrypts ONLY the 32-byte AES session key.\n\n"
            "2. High-Throughput Authenticated Encryption:\n"
            "   AES-256-GCM provides both bulk data confidentiality and cryptographic authenticity.\n"
            "   Any unauthorized tampering with the ciphertext triggers immediate authentication failure.\n\n"
            "3. Security Guarantees:\n"
            "   • Confidentiality: AES-256 (256-bit key space) + RSA-2048\n"
            "   • Semantic Security & Padding Attack Defense: RSA-OAEP with SHA-256\n"
            "   • Integrity & Anti-Tampering: 16-byte GMAC authentication tag\n"
            "   • Nonce Security: Fresh 12-byte random nonce per encryption session"
        )
        txt_desc.insert("1.0", explanation)
        txt_desc.config(state="disabled")

        # Close Button
        btn_close = ttk.Button(
            content,
            text="Close",
            style="ActionPrimary.TButton",
            command=about_dialog.destroy
        )
        btn_close.pack(anchor="e")


def main():
    """Application entrypoint."""
    app = HybridCryptoApp()
    app.mainloop()


if __name__ == "__main__":
    main()
