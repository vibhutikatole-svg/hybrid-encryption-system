"""
test_crypto.py - Unit Tests for Cryptographic Core (crypto_utils.py)
"""

import os
import json
import shutil
import tempfile
import unittest

from crypto_utils import (
    generate_rsa_key_pair,
    check_keys_exist,
    encrypt_file,
    decrypt_file,
    CryptoError,
    KeyNotFoundError,
    InvalidPackageError,
    IntegrityVerificationError,
    DecryptionError
)


class TestHybridCrypto(unittest.TestCase):

    def setUp(self):
        """Create a temporary directory for test artifacts."""
        self.test_dir = tempfile.mkdtemp()
        self.keys_dir = os.path.join(self.test_dir, "keys")
        self.priv_key_path, self.pub_key_path = generate_rsa_key_pair(self.keys_dir, key_size=2048)

    def tearDown(self):
        """Clean up temporary directory after tests run."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_key_generation(self):
        """Verify RSA key pair generation and file existence check."""
        status = check_keys_exist(self.keys_dir)
        self.assertTrue(status["public_exists"])
        self.assertTrue(status["private_exists"])
        self.assertTrue(os.path.isfile(self.pub_key_path))
        self.assertTrue(os.path.isfile(self.priv_key_path))

    def test_encrypt_decrypt_roundtrip(self):
        """Verify full round-trip encryption and decryption of plaintext payload."""
        sample_file = os.path.join(self.test_dir, "sample.txt")
        enc_file = os.path.join(self.test_dir, "sample.txt.enc")
        rec_file = os.path.join(self.test_dir, "sample_recovered.txt")

        content = b"Confidential Cryptographic Test Payload - 1234567890!"
        with open(sample_file, "wb") as f:
            f.write(content)

        # Encrypt
        out_enc, enc_meta = encrypt_file(
            input_file_path=sample_file,
            output_file_path=enc_file,
            public_key_path=self.pub_key_path
        )
        self.assertEqual(out_enc, enc_file)
        self.assertTrue(os.path.isfile(enc_file))

        # Decrypt
        out_rec, dec_meta = decrypt_file(
            encrypted_file_path=enc_file,
            output_file_path=rec_file,
            private_key_path=self.priv_key_path
        )
        self.assertEqual(out_rec, rec_file)
        self.assertTrue(os.path.isfile(rec_file))

        with open(rec_file, "rb") as f:
            restored = f.read()

        self.assertEqual(restored, content)

    def test_integrity_verification_failure_on_tampering(self):
        """Verify that modifying ciphertext in .enc package triggers IntegrityVerificationError."""
        sample_file = os.path.join(self.test_dir, "tamper_test.txt")
        enc_file = os.path.join(self.test_dir, "tamper_test.txt.enc")
        rec_file = os.path.join(self.test_dir, "tamper_test_recovered.txt")

        with open(sample_file, "wb") as f:
            f.write(b"Tamper-sensitive data.")

        encrypt_file(sample_file, enc_file, self.pub_key_path)

        # Tamper with encrypted package payload
        with open(enc_file, "r", encoding="utf-8") as f:
            package = json.load(f)

        # Flip characters in ciphertext
        raw_ct = package["ciphertext"]
        tampered_ct = ("A" if raw_ct[0] != "A" else "B") + raw_ct[1:]
        package["ciphertext"] = tampered_ct

        with open(enc_file, "w", encoding="utf-8") as f:
            json.dump(package, f)

        # Decryption must fail with IntegrityVerificationError
        with self.assertRaises(IntegrityVerificationError):
            decrypt_file(enc_file, output_file_path=rec_file, private_key_path=self.priv_key_path)

    def test_decryption_with_mismatched_key(self):
        """Verify that decrypting with an incorrect private key raises DecryptionError."""
        sample_file = os.path.join(self.test_dir, "wrong_key_test.txt")
        enc_file = os.path.join(self.test_dir, "wrong_key_test.txt.enc")

        with open(sample_file, "wb") as f:
            f.write(b"Secret data encrypted with key set A.")

        encrypt_file(sample_file, enc_file, self.pub_key_path)

        # Generate separate key set B
        other_keys_dir = os.path.join(self.test_dir, "other_keys")
        other_priv_path, _ = generate_rsa_key_pair(other_keys_dir, key_size=2048)

        # Decryption with key set B must fail
        with self.assertRaises(DecryptionError):
            decrypt_file(enc_file, private_key_path=other_priv_path)

    def test_invalid_package_format(self):
        """Verify that invalid package files raise InvalidPackageError."""
        bad_file = os.path.join(self.test_dir, "bad.enc")
        with open(bad_file, "w") as f:
            f.write("THIS IS NOT JSON DATA")

        with self.assertRaises(InvalidPackageError):
            decrypt_file(bad_file, private_key_path=self.priv_key_path)


if __name__ == "__main__":
    unittest.main()
