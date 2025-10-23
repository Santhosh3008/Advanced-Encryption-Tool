"""
filecrypt.py
Encrypt / Decrypt files using AES-256-GCM with a simple Tkinter GUI and CLI.

Usage (CLI):
  python filecrypt.py --encrypt -i path/to/input -o path/to/output
  python filecrypt.py --decrypt -i path/to/input -o path/to/output
"""

import os
import struct
import argparse
from getpass import getpass
from pathlib import Path
from tkinter import Tk, Label, Entry, Button, StringVar, filedialog, messagebox

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.backends import default_backend

# === File container constants ===
MAGIC = b'FCFT'           # 4 bytes file magic
VERSION = b'\x01'         # 1 byte version
SALT_SIZE = 16            # 16 bytes salt
NONCE_SIZE = 12           # 12 bytes nonce for GCM
TAG_SIZE = 16             # 16 bytes auth tag for GCM
KDF_ITERATIONS = 200_000  # PBKDF2 iterations (adjust based on performance/security tradeoff)
CHUNK_SIZE = 64 * 1024    # 64 KiB chunks for streaming

backend = default_backend()

def derive_key(password: bytes, salt: bytes, iterations=KDF_ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,            # 256-bit key
        salt=salt,
        iterations=iterations,
        backend=backend
    )
    return kdf.derive(password)

def encrypt_file(in_path: str, out_path: str, password: str):
    in_path = Path(in_path)
    out_path = Path(out_path)

    if not in_path.is_file():
        raise FileNotFoundError(f"Input file not found: {in_path}")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password.encode('utf-8'), salt)

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=backend)
    encryptor = cipher.encryptor()

    with in_path.open('rb') as fin, out_path.open('wb') as fout:
        # Write header
        fout.write(MAGIC)
        fout.write(VERSION)
        fout.write(salt)
        fout.write(nonce)

        # Stream encrypt
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            ct = encryptor.update(chunk)
            if ct:
                fout.write(ct)

        # finalize & write tag
        encryptor.finalize()
        tag = encryptor.tag
        fout.write(tag)

def decrypt_file(in_path: str, out_path: str, password: str):
    in_path = Path(in_path)
    out_path = Path(out_path)

    if not in_path.is_file():
        raise FileNotFoundError(f"Input file not found: {in_path}")

    file_size = in_path.stat().st_size
    header_len = len(MAGIC) + len(VERSION) + SALT_SIZE + NONCE_SIZE
    if file_size < header_len + TAG_SIZE:
        raise ValueError("File too small or not a valid encrypted container")

    with in_path.open('rb') as fin:
        magic = fin.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("Unrecognized file format (magic mismatch)")

        version = fin.read(len(VERSION))
        if version != VERSION:
            raise ValueError(f"Unsupported version: {version}")

        salt = fin.read(SALT_SIZE)
        nonce = fin.read(NONCE_SIZE)

        # Remaining bytes = ciphertext + tag
        remaining = file_size - header_len
        ciphertext_len = remaining - TAG_SIZE
        if ciphertext_len < 0:
            raise ValueError("Corrupt file (ciphertext length negative)")

        key = derive_key(password.encode('utf-8'), salt)

        # Read ciphertext in streaming manner, but we need the tag to construct GCM decryptor
        # So we seek to read ciphertext_len bytes then read tag
        # Strategy: read ciphertext_len bytes in chunks and decrypt as we go
        # But cryptography's GCM decryptor requires tag when creating decryptor object.
        # So read tag first by seeking to the end, then reconstruct stream.
        fin.seek(header_len + ciphertext_len)
        tag = fin.read(TAG_SIZE)

        # Create decryptor with nonce and tag
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=backend)
        decryptor = cipher.decryptor()

        # Seek back to start of ciphertext
        fin.seek(header_len)

        with out_path.open('wb') as fout:
            bytes_left = ciphertext_len
            while bytes_left > 0:
                to_read = min(CHUNK_SIZE, bytes_left)
                chunk = fin.read(to_read)
                if not chunk:
                    break
                pt = decryptor.update(chunk)
                if pt:
                    fout.write(pt)
                bytes_left -= len(chunk)

            # finalize - will raise if authentication fails
            try:
                decryptor.finalize()
            except Exception as e:
                # remove partial output if authentication fails
                try:
                    fout.close()
                    out_path.unlink(missing_ok=True)
                except Exception:
                    pass
                raise ValueError("Decryption failed: authentication error or wrong password") from e

# === Simple Tkinter GUI ===

def launch_gui():
    root = Tk()
    root.title("FileCrypt — AES-256-GCM")
    root.geometry("520x200")
    root.resizable(False, False)

    file_var = StringVar()
    out_var = StringVar()
    pwd_var = StringVar()
    mode_var = StringVar(value="encrypt")

    def choose_file():
        path = filedialog.askopenfilename()
        if path:
            file_var.set(path)
            # set default output filename
            out_var.set(str(Path(path).with_suffix(Path(path).suffix + ('.enc' if mode_var.get() == 'encrypt' else '.dec'))))

    def choose_out():
        path = filedialog.asksaveasfilename()
        if path:
            out_var.set(path)

    def do_action():
        infile = file_var.get().strip()
        outfile = out_var.get().strip()
        pwd = pwd_var.get()
        if not infile or not outfile or not pwd:
            messagebox.showwarning("Missing", "Please choose a file, output path, and enter a password.")
            return
        try:
            if mode_var.get() == 'encrypt':
                encrypt_file(infile, outfile, pwd)
                messagebox.showinfo("Success", f"Encrypted -> {outfile}")
            else:
                decrypt_file(infile, outfile, pwd)
                messagebox.showinfo("Success", f"Decrypted -> {outfile}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    Label(root, text="Input File:").place(x=10, y=12)
    Entry(root, textvariable=file_var, width=55).place(x=90, y=12)
    Button(root, text="Browse", command=choose_file).place(x=440, y=8)

    Label(root, text="Output File:").place(x=10, y=48)
    Entry(root, textvariable=out_var, width=55).place(x=90, y=48)
    Button(root, text="Browse", command=choose_out).place(x=440, y=44)

    Label(root, text="Password:").place(x=10, y=84)
    Entry(root, textvariable=pwd_var, show="*", width=30).place(x=90, y=84)

    Button(root, text="Encrypt", width=12, command=lambda: [mode_var.set("encrypt"), do_action()]).place(x=90, y=120)
    Button(root, text="Decrypt", width=12, command=lambda: [mode_var.set("decrypt"), do_action()]).place(x=220, y=120)
    Button(root, text="Quit", width=12, command=root.destroy).place(x=350, y=120)

    root.mainloop()

# === CLI wrapper ===

def main_cli():
    parser = argparse.ArgumentParser(description="FileCrypt: AES-256-GCM file encrypt/decrypt")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("-e", "--encrypt", action="store_true", help="Encrypt input to output")
    group.add_argument("-d", "--decrypt", action="store_true", help="Decrypt input to output")
    parser.add_argument("-i", "--input", required=False, help="Input file path")
    parser.add_argument("-o", "--output", required=False, help="Output file path")
    parser.add_argument("--gui", action="store_true", help="Launch GUI")
    args = parser.parse_args()

    if args.gui or (not args.encrypt and not args.decrypt and not args.input and not args.output):
        launch_gui()
        return

    if not args.input or not args.output:
        print("For CLI mode specify both -i and -o paths (or use --gui).")
        return

    # ask for password securely
    pwd = getpass("Enter password: ")
    if args.encrypt:
        encrypt_file(args.input, args.output, pwd)
        print("Encrypted:", args.output)
    elif args.decrypt:
        decrypt_file(args.input, args.output, pwd)
        print("Decrypted:", args.output)
    else:
        print("Specify --encrypt or --decrypt.")

if __name__ == "__main__":
    main_cli()
