"""
crypto_utils.py - Cryptographic Core for Hybrid Encryption System

Combines RSA-2048 asymmetric encryption and AES-256-GCM authenticated
symmetric encryption into a robust hybrid encryption pipeline.

Cryptographic Architecture:
- Asymmetric: RSA-2048 with OAEP (Optimal Asymmetric Encryption Padding),
MGF1 (Mask Generation Function 1) parameterized with SHA-256, and SHA-256 digest.
- Symmetric: AES-256 in Galois/Counter Mode (GCM) providing both confidentiality
and cryptographic authentication/integrity (AEAD).
- Session Nonce: 12-byte (96-bit) cryptographically secure random value per encryption.
- Authenticated Data (AAD): Domain-separated version tag to bind ciphertext context.
- Key Encapsulation: The AES session key is 256 bits (32 bytes), safely encrypted
using RSA-2048-OAEP, ensuring RSA is never directly applied to large or arbitrary payloads.
"""

import os
import json
import base64
from typing import Tuple, Dict, Any, Optional

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


# Protocol constants
PACKAGE_MAGIC = "HYBRID_ENCRYPTION_SYSTEM_V1"
PROTOCOL_VERSION = "1.0"
ASSOCIATED_DATA = b"HYBRID_ENCRYPTION_V1"
DEFAULT_KEYS_DIR = "keys"


class CryptoError(Exception):
    """Base exception for cryptographic operations in this module."""
    pass


class KeyNotFoundError(CryptoError):
    """Raised when an expected RSA key file does not exist."""
    pass


class InvalidPackageError(CryptoError):
    """Raised when an encrypted package file is corrupted or structurally invalid."""
    pass


class IntegrityVerificationError(CryptoError):
    """Raised when AES-GCM authentication/integrity verification fails (tampering/corruption)."""
    pass


class DecryptionError(CryptoError):
    """Raised when decryption fails due to mismatched keys or payload corruption."""
    pass


def check_keys_exist(keys_dir: str = DEFAULT_KEYS_DIR) -> Dict[str, Any]:
    """
    Check if RSA public and private key files exist in the specified folder.

    Args:
        keys_dir: Directory where key files are expected.

    Returns:
        Dictionary with existence flags and paths.
    """
    pub_path = os.path.join(keys_dir, "public_key.pem")
    priv_path = os.path.join(keys_dir, "private_key.pem")

    return {
        "public_exists": os.path.isfile(pub_path),
        "private_exists": os.path.isfile(priv_path),
        "public_path": pub_path,
        "private_path": priv_path,
        "keys_dir": keys_dir
    }


def generate_rsa_key_pair(keys_dir: str = DEFAULT_KEYS_DIR, key_size: int = 2048) -> Tuple[str, str]:
    """
    Generate an RSA-2048 key pair and save them as PEM-encoded files.

    - private_key.pem: PKCS#8 format
    - public_key.pem: SubjectPublicKeyInfo format

    Args:
        keys_dir: Directory path where keys will be saved.
        key_size: RSA key size in bits (default 2048).

    Returns:
        Tuple of (private_key_path, public_key_path).
    """
    if key_size < 2048:
        raise ValueError("Key size must be at least 2048 bits for secure operation.")

    os.makedirs(keys_dir, exist_ok=True)
    priv_path = os.path.join(keys_dir, "private_key.pem")
    pub_path = os.path.join(keys_dir, "public_key.pem")

    # Generate RSA private key (e=65537 is standard, 2048 bits)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    # Export private key to PEM format (PKCS#8)
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Export public key to PEM format (SubjectPublicKeyInfo)
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Write private key
    with open(priv_path, "wb") as f_priv:
        f_priv.write(pem_private)

    # Write public key
    with open(pub_path, "wb") as f_pub:
        f_pub.write(pem_public)

    return priv_path, pub_path


def load_public_key(public_key_path: str):
    """
    Load an RSA public key from a PEM file.

    Args:
        public_key_path: Path to public_key.pem.

    Returns:
        RSAPublicKey object.
    """
    if not os.path.isfile(public_key_path):
        raise KeyNotFoundError(f"Public key not found at '{public_key_path}'.")

    try:
        with open(public_key_path, "rb") as f:
            data = f.read()
        return serialization.load_pem_public_key(data)
    except Exception as exc:
        raise CryptoError(f"Failed to parse public key: {exc}") from exc


def load_private_key(private_key_path: str, password: Optional[bytes] = None):
    """
    Load an RSA private key from a PEM file.

    Args:
        private_key_path: Path to private_key.pem.
        password: Optional decryption password if key is encrypted.

    Returns:
        RSAPrivateKey object.
    """
    if not os.path.isfile(private_key_path):
        raise KeyNotFoundError(f"Private key not found at '{private_key_path}'.")

    try:
        with open(private_key_path, "rb") as f:
            data = f.read()
        return serialization.load_pem_private_key(data, password=password)
    except Exception as exc:
        raise CryptoError(f"Failed to parse private key: {exc}") from exc


def get_rsa_oaep_padding():
    """
    Construct the RSA-OAEP padding scheme with SHA-256 for hash and MGF1.

    Returns:
        padding.OAEP instance configured with SHA-256.
    """
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )


def encrypt_file(
    input_file_path: str,
    output_file_path: Optional[str] = None,
    public_key_path: Optional[str] = None,
    keys_dir: str = DEFAULT_KEYS_DIR
) -> Tuple[str, Dict[str, Any]]:
    """
    Encrypt a file using Hybrid Encryption (AES-256-GCM + RSA-2048-OAEP).

    Process:
    1. Validate input file and key paths.
    2. Read input file as bytes.
    3. Generate a cryptographically secure random 256-bit AES session key.
    4. Generate a secure random 12-byte nonce for AES-GCM.
    5. Encrypt the file payload using AES-256-GCM (generating ciphertext + 16-byte tag).
    6. Encrypt the 32-byte AES key using RSA-2048 with OAEP (SHA-256).
    7. Construct a structured package (.enc) containing all components and metadata.

    Args:
        input_file_path: Path of file to encrypt.
        output_file_path: Destination path (defaults to <input_file_path>.enc).
        public_key_path: Path to public key PEM file.
        keys_dir: Folder containing keys if public_key_path is not specified.

    Returns:
        Tuple of (output_file_path, metadata_dict).
    """
    if not input_file_path or not isinstance(input_file_path, str):
        raise ValueError("No input file specified for encryption.")

    if not os.path.isfile(input_file_path):
        raise FileNotFoundError(f"Input file does not exist: {input_file_path}")

    # Determine public key
    if public_key_path is None:
        public_key_path = os.path.join(keys_dir, "public_key.pem")

    if not os.path.isfile(public_key_path):
        raise KeyNotFoundError(
            f"Public key not found at '{public_key_path}'. Please generate RSA keys first."
        )

    # Determine output path
    if output_file_path is None:
        output_file_path = input_file_path + ".enc"

    # Validate output destination directory
    out_dir = os.path.dirname(os.path.abspath(output_file_path))
    if out_dir:
        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception as exc:
            raise CryptoError(f"Cannot access or create output directory '{out_dir}': {exc}") from exc

    # Read original file bytes
    try:
        with open(input_file_path, "rb") as f_in:
            plaintext_bytes = f_in.read()
    except Exception as exc:
        raise CryptoError(f"Failed to read input file '{input_file_path}': {exc}") from exc

    original_size = len(plaintext_bytes)
    original_filename = os.path.basename(input_file_path)

    # 1. Generate AES-256 session key (32 bytes / 256 bits)
    aes_session_key = AESGCM.generate_key(bit_length=256)

    # 2. Generate random 12-byte (96-bit) nonce
    nonce = os.urandom(12)

    # 3. Encrypt payload with AES-256-GCM (produces ciphertext with 16-byte tag appended)
    aesgcm = AESGCM(aes_session_key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, ASSOCIATED_DATA)

    # 4. Encrypt the AES session key with RSA-2048-OAEP (SHA-256)
    public_key = load_public_key(public_key_path)
    encrypted_aes_key = public_key.encrypt(
        aes_session_key,
        get_rsa_oaep_padding()
    )

    # 5. Build encrypted package
    package = {
        "magic": PACKAGE_MAGIC,
        "version": PROTOCOL_VERSION,
        "algorithm": {
            "asymmetric": "RSA-2048-OAEP-SHA256",
            "symmetric": "AES-256-GCM",
            "key_size_bits": 256,
            "nonce_size_bytes": 12,
            "auth_tag_size_bytes": 16
        },
        "original_filename": original_filename,
        "original_size_bytes": original_size,
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext_with_tag).decode("ascii")
    }

    # Write package file
    try:
        with open(output_file_path, "w", encoding="utf-8") as f_out:
            json.dump(package, f_out, indent=2)
    except Exception as exc:
        raise CryptoError(f"Failed to write encrypted package to '{output_file_path}': {exc}") from exc

    metadata = {
        "original_filename": original_filename,
        "original_size_bytes": original_size,
        "encrypted_size_bytes": os.path.getsize(output_file_path),
        "asymmetric_algorithm": "RSA-2048-OAEP-SHA256",
        "symmetric_algorithm": "AES-256-GCM",
        "output_file_path": output_file_path
    }

    return output_file_path, metadata


def decrypt_file(
    encrypted_file_path: str,
    output_dir: Optional[str] = None,
    output_file_path: Optional[str] = None,
    private_key_path: Optional[str] = None,
    keys_dir: str = DEFAULT_KEYS_DIR
) -> Tuple[str, Dict[str, Any]]:
    """
    Decrypt a hybrid-encrypted package (.enc) back to its original file.

    Process:
    1. Validate inputs and private key availability.
    2. Read and parse the package JSON.
    3. Verify package header and required fields.
    4. Decode and validate base64 components.
    5. Decrypt the AES session key using the RSA private key with OAEP (SHA-256).
    6. Decrypt the ciphertext and verify authentication tag using AES-256-GCM.
    7. Write the restored plaintext bytes to the designated output file.

    Args:
        encrypted_file_path: Path of the .enc file to decrypt.
        output_dir: Folder to save the recovered file (if output_file_path is None).
        output_file_path: Explicit path for the recovered file.
        private_key_path: Path to private_key.pem.
        keys_dir: Folder containing keys if private_key_path is not specified.

    Returns:
        Tuple of (recovered_file_path, metadata_dict).
    """
    if not encrypted_file_path or not isinstance(encrypted_file_path, str):
        raise ValueError("No encrypted package file specified for decryption.")

    if not os.path.isfile(encrypted_file_path):
        raise FileNotFoundError(f"Encrypted file does not exist: {encrypted_file_path}")

    # Determine private key
    if private_key_path is None:
        private_key_path = os.path.join(keys_dir, "private_key.pem")

    if not os.path.isfile(private_key_path):
        raise KeyNotFoundError(
            f"Private key not found at '{private_key_path}'. Decryption requires the private key."
        )

    # 1. Parse JSON package
    try:
        with open(encrypted_file_path, "r", encoding="utf-8") as f_in:
            package = json.load(f_in)
    except json.JSONDecodeError as exc:
        raise InvalidPackageError("Selected file is not a valid JSON package (malformed JSON).") from exc
    except Exception as exc:
        raise InvalidPackageError(f"Could not read encrypted package file: {exc}") from exc

    # 2. Validate header and essential fields
    if not isinstance(package, dict) or package.get("magic") != PACKAGE_MAGIC:
        raise InvalidPackageError(
            "Unrecognized file format or invalid hybrid encryption header. "
            "This file was not created by this system or is corrupted."
        )

    required_keys = ["encrypted_aes_key", "nonce", "ciphertext", "original_filename"]
    for req in required_keys:
        if req not in package:
            raise InvalidPackageError(f"Encrypted package is incomplete: missing required field '{req}'.")
        if not isinstance(package[req], str) or not package[req].strip():
            raise InvalidPackageError(f"Encrypted package field '{req}' is empty or invalid.")

    original_filename = package["original_filename"]

    # 3. Base64 decode and validate package payloads
    try:
        encrypted_aes_key = base64.b64decode(package["encrypted_aes_key"], validate=True)
        nonce = base64.b64decode(package["nonce"], validate=True)
        ciphertext_with_tag = base64.b64decode(package["ciphertext"], validate=True)
    except Exception as exc:
        raise InvalidPackageError("Corrupted or invalid base64 payload in encrypted package.") from exc

    if len(nonce) != 12:
        raise InvalidPackageError(f"Invalid nonce length: expected 12 bytes, got {len(nonce)}.")

    # 4. Load private key
    private_key = load_private_key(private_key_path)

    # 5. Decrypt the AES session key using RSA-2048-OAEP
    try:
        aes_session_key = private_key.decrypt(
            encrypted_aes_key,
            get_rsa_oaep_padding()
        )
    except ValueError as exc:
        raise DecryptionError(
            "RSA decryption failed. The private key does not match the public key "
            "used to encrypt this file, or the key payload is corrupted."
        ) from exc
    except Exception as exc:
        raise DecryptionError(f"Error unwrapping AES session key: {exc}") from exc

    if len(aes_session_key) != 32:
        raise DecryptionError(
            f"Invalid unwrapped AES key length: expected 32 bytes, got {len(aes_session_key)}."
        )

    # 6. Decrypt payload and verify integrity with AES-256-GCM
    try:
        aesgcm = AESGCM(aes_session_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, ASSOCIATED_DATA)
    except InvalidTag as exc:
        raise IntegrityVerificationError(
            "Integrity check failed: Authentication tag verification failed! "
            "The ciphertext has been corrupted, tampered with, or modified."
        ) from exc
    except Exception as exc:
        raise DecryptionError(f"AES-GCM decryption failed: {exc}") from exc

    # 7. Determine output path
    if output_file_path is None:
        destination_folder = output_dir if output_dir else os.path.dirname(os.path.abspath(encrypted_file_path))
        target_path = os.path.join(destination_folder, original_filename)

        # Prevent overwriting if user decrypts a file named the same as an existing plaintext
        if os.path.exists(target_path):
            base_name, ext = os.path.splitext(original_filename)
            counter = 1
            while os.path.exists(target_path):
                target_path = os.path.join(destination_folder, f"{base_name}_recovered_{counter}{ext}")
                counter += 1
        output_file_path = target_path

    out_dir = os.path.dirname(os.path.abspath(output_file_path))
    if out_dir:
        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception as exc:
            raise CryptoError(f"Cannot access or create destination directory '{out_dir}': {exc}") from exc

    try:
        with open(output_file_path, "wb") as f_out:
            f_out.write(plaintext)
    except Exception as exc:
        raise CryptoError(f"Failed to write decrypted file to '{output_file_path}': {exc}") from exc

    metadata = {
        "original_filename": original_filename,
        "recovered_file_path": output_file_path,
        "recovered_size_bytes": len(plaintext),
        "algorithm": package.get("algorithm", {})
    }

    return output_file_path, metadata