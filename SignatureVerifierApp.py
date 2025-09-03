import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.backends import default_backend
import os

class SignatureVerifierApp(tk.Tk):
    """
    A Tkinter application to verify digital signatures and generate RSA keys.
    """
    def __init__(self):
        super().__init__()
        self.title("Advanced Signature Verifier")
        self.geometry("800x700")
        
        # Set a color scheme similar to the HTML version
        self.style = ttk.Style(self)
        self.style.theme_use('clam')
        self.style.configure("TFrame", background="#EFEFEF")
        self.style.configure("TLabel", background="#EFEFEF", foreground="#333333", font=("Segoe UI", 10))
        self.style.configure("TButton", background="#4f46e5", foreground="white", font=("Segoe UI", 10, "bold"), padding=10)
        self.style.map("TButton", background=[("active", "#4338ca")])

        self.style.configure("Result.TLabel", font=("Segoe UI", 12, "bold"))

        # Main frame
        self.main_frame = ttk.Frame(self, padding="20 20 20 20", style="TFrame")
        self.main_frame.pack(expand=True, fill="both")

        # Title and description
        title_label = ttk.Label(self.main_frame, text="Advanced Signature Verifier", font=("Segoe UI", 24, "bold"))
        title_label.pack(pady=(0, 5))
        desc_label = ttk.Label(self.main_frame, text="Verify digital signatures using RSA cryptography.", font=("Segoe UI", 10))
        desc_label.pack(pady=(0, 20))

        # Input frames
        self.input_frame = ttk.Frame(self.main_frame, style="TFrame")
        self.input_frame.pack(fill="x", pady=10)
        
        self.message_frame = ttk.Frame(self.input_frame, style="TFrame")
        self.message_frame.pack(side="left", padx=10, expand=True, fill="both")
        self.signature_frame = ttk.Frame(self.input_frame, style="TFrame")
        self.signature_frame.pack(side="right", padx=10, expand=True, fill="both")

        # Message Input
        ttk.Label(self.message_frame, text="Original Message").pack(anchor="w", pady=(0, 5))
        self.message_text = tk.Text(self.message_frame, height=5, width=40, wrap=tk.WORD, borderwidth=1, relief="solid")
        self.message_text.pack(fill="x", expand=True)
        ttk.Button(self.message_frame, text="Load Message from File", command=lambda: self.load_file_to_text(self.message_text)).pack(fill="x", pady=5)

        # Signature Input
        ttk.Label(self.signature_frame, text="Signature (Base64)").pack(anchor="w", pady=(0, 5))
        self.signature_text = tk.Text(self.signature_frame, height=5, width=40, wrap=tk.WORD, borderwidth=1, relief="solid")
        self.signature_text.pack(fill="x", expand=True)
        ttk.Button(self.signature_frame, text="Load Signature from File", command=lambda: self.load_file_to_text(self.signature_text, base64_encode=True)).pack(fill="x", pady=5)

        # Public Key Input
        ttk.Label(self.main_frame, text="Public Key (PEM format)").pack(anchor="w", pady=(10, 5))
        self.public_key_text = tk.Text(self.main_frame, height=5, width=80, wrap=tk.WORD, borderwidth=1, relief="solid")
        self.public_key_text.pack(fill="x")
        ttk.Button(self.main_frame, text="Load Public Key from File", command=lambda: self.load_file_to_text(self.public_key_text)).pack(fill="x", pady=5)

        # Options frame
        self.options_frame = ttk.Frame(self.main_frame, style="TFrame")
        self.options_frame.pack(fill="x", pady=10)

        ttk.Label(self.options_frame, text="Hash Algorithm").pack(side="left", padx=(0, 5))
        self.hash_alg_var = tk.StringVar(self)
        self.hash_alg_combo = ttk.Combobox(self.options_frame, textvariable=self.hash_alg_var, state="readonly")
        self.hash_alg_combo['values'] = ["SHA-256", "SHA-384", "SHA-512"]
        self.hash_alg_combo.set("SHA-256")
        self.hash_alg_combo.pack(side="left", padx=(0, 10))

        ttk.Label(self.options_frame, text="Signature Algorithm").pack(side="left", padx=(0, 5))
        self.sig_alg_var = tk.StringVar(self)
        self.sig_alg_combo = ttk.Combobox(self.options_frame, textvariable=self.sig_alg_var, state="readonly")
        self.sig_alg_combo['values'] = ["RSASSA-PKCS1-v1_5", "RSA-PSS"]
        self.sig_alg_combo.set("RSASSA-PKCS1-v1_5")
        self.sig_alg_combo.pack(side="left", padx=(0, 10))

        ttk.Label(self.options_frame, text="Key Size (bits)").pack(side="left", padx=(0, 5))
        self.key_size_var = tk.StringVar(self)
        self.key_size_combo = ttk.Combobox(self.options_frame, textvariable=self.key_size_var, state="readonly")
        self.key_size_combo['values'] = ["2048", "3072", "4096"]
        self.key_size_combo.set("2048")
        self.key_size_combo.pack(side="left", padx=(0, 10))

        # Button frame
        self.button_frame = ttk.Frame(self.main_frame, style="TFrame")
        self.button_frame.pack(pady=10)
        
        ttk.Button(self.button_frame, text="Verify Signature", command=self.verify_signature).pack(side="left", padx=5)
        ttk.Button(self.button_frame, text="Generate Test Keys", command=self.generate_keys).pack(side="left", padx=5)

        # Key generation output frame
        self.key_output_frame = ttk.Frame(self.main_frame, style="TFrame")
        self.key_output_frame.pack(fill="x", pady=10)
        self.key_output_frame.pack_forget() # Hide initially

        ttk.Label(self.key_output_frame, text="Generated Test Keys", font=("Segoe UI", 14, "bold")).pack(anchor="w", pady=(0, 5))

        self.key_gen_grid_frame = ttk.Frame(self.key_output_frame, style="TFrame")
        self.key_gen_grid_frame.pack(fill="x", expand=True)

        ttk.Label(self.key_gen_grid_frame, text="Public Key (PEM)").grid(row=0, column=0, sticky="w", padx=(0, 5), pady=(0, 5))
        self.gen_pub_key_text = tk.Text(self.key_gen_grid_frame, height=5, wrap=tk.WORD, borderwidth=1, relief="solid")
        self.gen_pub_key_text.grid(row=1, column=0, sticky="ew", padx=(0, 5), pady=(0, 5))

        ttk.Label(self.key_gen_grid_frame, text="Private Key (PEM)").grid(row=0, column=1, sticky="w", padx=(5, 0), pady=(0, 5))
        self.gen_priv_key_text = tk.Text(self.key_gen_grid_frame, height=5, wrap=tk.WORD, borderwidth=1, relief="solid")
        self.gen_priv_key_text.grid(row=1, column=1, sticky="ew", padx=(5, 0), pady=(0, 5))
        self.key_gen_grid_frame.grid_columnconfigure(0, weight=1)
        self.key_gen_grid_frame.grid_columnconfigure(1, weight=1)

        # Result label
        self.result_label = ttk.Label(self.main_frame, text="", style="Result.TLabel")
        self.result_label.pack(fill="x", pady=10)
        
    def load_file_to_text(self, text_widget, base64_encode=False):
        """Opens a file dialog and loads the content into a text widget."""
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            if base64_encode:
                content = base64.b64encode(content).decode('utf-8')
            else:
                content = content.decode('utf-8')
            
            text_widget.delete('1.0', tk.END)
            text_widget.insert('1.0', content)
            self.result_label.config(text="")
        except Exception as e:
            messagebox.showerror("File Read Error", f"Failed to read file: {e}")

    def get_hash_algorithm(self, name):
        """Returns the hashing algorithm object based on the name."""
        if name == "SHA-256":
            return hashes.SHA256()
        elif name == "SHA-384":
            return hashes.SHA384()
        elif name == "SHA-512":
            return hashes.SHA512()
        return None

    def verify_signature(self):
        """Verifies the digital signature using the provided data."""
        message = self.message_text.get("1.0", tk.END).strip()
        signature_str = self.signature_text.get("1.0", tk.END).strip()
        public_key_str = self.public_key_text.get("1.0", tk.END).strip()
        hash_alg_name = self.hash_alg_combo.get()
        sig_alg_name = self.sig_alg_combo.get()

        if not all([message, signature_str, public_key_str, hash_alg_name, sig_alg_name]):
            self.show_result("Please fill in all required fields.", "red")
            return

        try:
            # Decode the Base64 signature
            signature = base64.b64decode(signature_str)
            
            # Load the public key from PEM format
            public_key = serialization.load_pem_public_key(
                public_key_str.encode('utf-8'),
                backend=default_backend()
            )

            # Determine the hashing and padding algorithms
            hash_algorithm = self.get_hash_algorithm(hash_alg_name)
            
            if sig_alg_name == "RSASSA-PKCS1-v1_5":
                padding_alg = padding.PKCS1v15()
            elif sig_alg_name == "RSA-PSS":
                padding_alg = padding.PSS(
                    mgf=padding.MGF1(algorithm=hash_algorithm),
                    salt_length=padding.Auto
                )
            
            # Hash the original message
            hasher = hashes.Hash(hash_algorithm, backend=default_backend())
            hasher.update(message.encode('utf-8'))
            message_hash = hasher.finalize()

            # Verify the signature
            public_key.verify(
                signature,
                message_hash,
                padding_alg,
                Prehashed(hash_algorithm)
            )

            self.show_result("Signature verification successful: The signature matches the message.", "green")

        except Exception as e:
            self.show_result(f"Verification failed: {e}", "red")

    def generate_keys(self):
        """Generates a new RSA public and private key pair."""
        try:
            key_size = int(self.key_size_combo.get())
            public_exponent = 65537
            
            # Generate the private key
            private_key = rsa.generate_private_key(
                public_exponent=public_exponent,
                key_size=key_size,
                backend=default_backend()
            )
            
            # Get the public key from the private key
            public_key = private_key.public_key()
            
            # Export the private key to PEM format
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Export the public key to PEM format
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            self.gen_pub_key_text.delete('1.0', tk.END)
            self.gen_pub_key_text.insert('1.0', public_pem.decode('utf-8'))
            self.gen_priv_key_text.delete('1.0', tk.END)
            self.gen_priv_key_text.insert('1.0', private_pem.decode('utf-8'))

            # Show the key generation frame
            self.key_output_frame.pack(fill="x", expand=True)
            self.result_label.config(text="")
            
        except Exception as e:
            messagebox.showerror("Key Generation Error", f"Failed to generate keys: {e}")
            self.show_result(f"Key Generation Error: {e}", "red")

    def show_result(self, message, color):
        """Displays a colored result message to the user."""
        self.result_label.config(text=message, foreground=color)
        
if __name__ == "__main__":
    app = SignatureVerifierApp()
    app.mainloop()
