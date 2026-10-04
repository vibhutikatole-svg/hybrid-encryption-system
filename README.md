# 1. Hybrid Encryption System – RSA + AES

This project is a Python-based desktop application designed for B.Tech Cryptography and Network Security mini project coursework. It implements a **Hybrid Encryption System** that combines symmetric and asymmetric cryptographic algorithms to securely encrypt, store, decrypt, and verify files. 

In this system:
- **AES-256-GCM** is used for encrypting the actual file data quickly and securely.
- **RSA-2048-OAEP** with **SHA-256** is used to encrypt and protect the random AES session key.
- **Tkinter** provides a clean desktop graphical user interface (GUI) for file selection, key management, and audit logging.

*Note: This project is strictly designed for local file encryption and decryption and does not implement network communication protocols.*

---

## 2. Problem Statement

Securing sensitive files stored on local drives or transmitted across insecure media requires both data confidentiality and authenticity. 

- **Symmetric Encryption (AES)** is fast and computationally efficient for large files, but requires both sender and receiver to share a secret key securely.
- **Asymmetric Encryption (RSA)** uses a public key for encryption and a private key for decryption, solving key distribution issues. However, pure RSA is computationally slow and mathematically limited in payload size (e.g., RSA-2048 with OAEP padding cannot encrypt data larger than 190 bytes).
- **Hybrid Encryption** resolves this dilemma by using symmetric encryption (AES-256-GCM) for high-speed file payloads, while using asymmetric encryption (RSA-2048-OAEP) to safely protect and exchange the small AES session key.

---

## 3. Objectives

1. **Implement AES-256-GCM** for bulk file encryption with high performance and confidentiality.
2. **Generate RSA-2048 Public/Private Key Pairs** saved locally in standard PEM format.
3. **Protect the AES Session Key** using RSA-2048 with OAEP padding and SHA-256 hash.
4. **Provide a User-Friendly Graphical Interface (GUI)** using Tkinter for simple file selection, encryption, and decryption.
5. **Verify Data Integrity** using AES-GCM 128-bit authentication tags (AEAD) to detect any file tampering or corruption.
6. **Demonstrate Practical Cryptography and Network Security Concepts** in an educational setting.
7. **Provide Input Validation and Security Safeguards** against missing keys, bad paths, and corrupted payloads.
8. **Provide an Automated Test Suite** (`test_crypto.py`) to verify cryptographic routines automatically.

---

## 4. Technologies Used

| Technology | Purpose |
| :--- | :--- |
| **Python 3.9+** | Primary programming language and application runtime |
| **Tkinter / TTK** | Graphical User Interface (GUI) desktop framework |
| **`cryptography` Library** | Core Python cryptographic package (`hazmat.primitives`) |
| **RSA (2048-bit)** | Asymmetric key encapsulation algorithm |
| **AES-GCM (256-bit)** | Symmetric authenticated file encryption cipher |
| **JSON** | Structured formatting for encrypted `.enc` package files |
| **Git / GitHub** | Version control and source code repository management |

---

## 5. Python Libraries Used

### Standard Library Modules (Pre-installed with Python)

| Module / Package | Purpose in Project |
| :--- | :--- |
| **`tkinter`** | Provides desktop windows, labels, entries, buttons, and dialog boxes |
| **`os`** | Handles file paths, directory creation, and file existence checks |
| **`sys`** | Manages system execution paths and python environment details |
| **`json`** | Serializes encrypted payloads and metadata into `.enc` package files |
| **`base64`** | Encodes binary ciphertexts, nonces, and keys into ASCII strings |
| **`tempfile`** | Generates temporary directories for unit test executions |
| **`shutil`** | Cleans up temporary test folders after running unit tests |
| **`time`** | Provides visual delay timing for the demonstration workflow |
| **`datetime`** | Generates timestamp tags for the GUI cryptographic audit log |
| **`unittest`** | Automated testing framework used in `test_crypto.py` |

### External Third-Party Packages

| Package | Purpose in Project |
| :--- | :--- |
| **`cryptography`** | Provides low-level primitives (`AESGCM`, `rsa`, `padding`, `hashes`, `serialization`) |

*Note: The `cryptography` library is installed via `requirements.txt`.*

---

## 6. Cryptography / Network Security Concepts Used

### 1. Hybrid Encryption
- **What it is**: A cryptosystem combining symmetric encryption (for data speed) and asymmetric encryption (for key protection).
- **How it is used**: AES-256 encrypts the file; RSA-2048 encrypts the 32-byte AES key.

### 2. Symmetric Encryption
- **What it is**: Encryption where the same key is used for both encrypting and decrypting data.
- **How it is used**: AES-256 encrypts file bytes using a randomly generated session key.

### 3. Asymmetric Encryption
- **What it is**: Encryption using a pair of mathematically linked keys (Public Key to encrypt, Private Key to decrypt).
- **How it is used**: The RSA public key encapsulates the AES session key during encryption; the private key unwraps it during decryption.

### 4. AES-256
- **What it is**: Advanced Encryption Standard using a 256-bit key space.
- **How it is used**: Provides confidentiality for file contents against brute-force attacks.

### 5. AES-GCM
- **What it is**: Galois/Counter Mode—an Authenticated Encryption with Associated Data (AEAD) mode.
- **How it is used**: Encrypts file payload and calculates a 16-byte authentication tag to guarantee integrity.

### 6. RSA-2048
- **What it is**: Rivest–Shamir–Adleman asymmetric cryptosystem with a 2048-bit key size.
- **How it is used**: Securely stores key pairs (`private_key.pem` and `public_key.pem`) to protect symmetric keys.

### 7. RSA-OAEP
- **What it is**: Optimal Asymmetric Encryption Padding scheme.
- **How it is used**: Adds random padding and MGF1 masking to prevent RSA deterministic encryption attacks and timing leaks.

### 8. SHA-256
- **What it is**: Secure Hash Algorithm producing a 256-bit hash digest.
- **How it is used**: Serves as the hashing parameter inside RSA-OAEP padding and MGF1 mask generation.

### 9. Random Nonce
- **What it is**: A Number Used Once—a 12-byte (96-bit) cryptographically secure random value.
- **How it is used**: Ensures every AES-GCM encryption produces unique ciphertext even if identical files are encrypted.

### 10. Authentication / Integrity Verification
- **What it is**: Verification that ciphertext has not been tampered with or modified.
- **How it is used**: AES-GCM validates the 16-byte tag during decryption; if tampered, decryption halts immediately.

### 11. Public Key and Private Key
- **What it is**: Public key is shared for encryption; Private key is kept secret for decryption.
- **How it is used**: `public_key.pem` encrypts session keys; `private_key.pem` decrypts session keys.

---

## 7. Key Features

- **RSA Key Pair Generation**: Generates 2048-bit RSA keys saved in standard PEM formats (`private_key.pem` in PKCS#8 and `public_key.pem` in SubjectPublicKeyInfo).
- **AES-256-GCM File Encryption**: Encrypts files of any type using a fresh random 256-bit AES session key and 12-byte nonce.
- **RSA-OAEP Key Protection**: Encapsulates the 32-byte AES key using RSA-2048-OAEP (SHA-256).
- **Graphical File Selection**: Interactive Tkinter file pickers for selecting target input files and `.enc` package destinations.
- **Encrypted `.enc` Package Generation**: Packages algorithm metadata, base64-encoded encrypted key, nonce, ciphertext, and original filename into a clean JSON file.
- **File Decryption**: Restores original files by unwrapping the session key with the private key.
- **AES-GCM Integrity Verification**: Validates the 128-bit authentication tag before outputting recovered files.
- **Input Validation**: Ensures keys exist, paths are accessible, and files exist before performing actions.
- **Error Handling**: Displays explicit dialogs and warnings for missing keys, corrupted JSON, invalid tags, or mismatched key pairs.
- **Status Messages & Audit Log**: Real-time status banner updates (`"RSA key pair generated successfully."`, `"File encrypted successfully."`, `"Encrypted package created successfully."`, `"File decrypted successfully."`, `"AES-GCM integrity verification successful."`) and timestamped console log.
- **Automated Encryption/Decryption Test**: Includes `test_crypto.py` covering key generation, round-trip encryption, tampered payload rejection, key mismatch detection, and bad JSON format handling.
- **Private Key Protection via `.gitignore`**: Excludes `keys/*.pem`, `.enc` packages, and temporary test directories from Git commits.

---

## 8. System Requirements

### Hardware Requirements
- **Computer / Laptop**: Any modern system running Windows, macOS, or Linux.
- **Processor**: Intel Core i3 / AMD Ryzen 3 or equivalent.
- **RAM**: Minimum 2 GB RAM (4 GB recommended).
- **Storage**: At least 100 MB free disk space.

### Software Requirements
- **Operating System**: Windows 10/11, macOS, or Linux.
- **Python**: Version 3.9 or higher.
- **IDE / Text Editor**: VS Code, PyCharm, or IDLE.
- **Git**: Version control CLI for cloning repository.
- **Internet Connection**: Required only for initial dependency installation (`pip install cryptography`) and GitHub access.

---

## 9. Project Structure

```text
hybrid-encryption-system/
│
├── app.py              # Tkinter GUI application interface & event handlers
├── crypto_utils.py     # Cryptographic core routines (RSA-2048 + AES-256-GCM)
├── test_crypto.py      # Automated unit test suite
├── requirements.txt    # External Python dependencies (cryptography)
├── README.md           # Comprehensive project documentation
├── .gitignore          # Git exclusion rules for keys, cache, and packages
└── keys/               # Folder storing generated public_key.pem & private_key.pem
```

*CRITICAL SECURITY NOTE: Generated RSA key files (`keys/private_key.pem` and `keys/public_key.pem`) contain sensitive credentials and must **NEVER** be committed to GitHub or public repositories.*

---

## 10. How to Install and Run

### Step 1: Clone Repository

```bash
git clone https://github.com/vibhutikatole-svg/hybrid-encryption-system.git
cd hybrid-encryption-system
```

### Step 2: Install Dependencies

Install the required `cryptography` library using `requirements.txt`:

```bash
python -m pip install -r requirements.txt
```

*(Alternatively, install directly via `python -m pip install cryptography`)*

### Step 3: Run Application

Start the graphical application interface:

```bash
python app.py
```

### Step 4: Run Automated Tests

Execute the unit test suite:

```bash
python test_crypto.py
```

#### Expected Verified Test Output
```text
.....
----------------------------------------------------------------------
Ran 5 tests in 0.305s

OK
```

---

## 11. How the System Works

The complete end-to-end operation follows these 10 steps:

1. **User generates RSA key pair**: Clicking *Generate RSA Keys* executes `generate_rsa_key_pair()`.
2. **Public and private keys are created**: Saves `keys/private_key.pem` (private) and `keys/public_key.pem` (public).
3. **User selects a file**: Chooses an input file to encrypt via the file dialog.
4. **Random AES-256 session key generated**: `AESGCM.generate_key(bit_length=256)` generates a fresh 32-byte key and a 12-byte random nonce (`os.urandom(12)`).
5. **AES-256-GCM encrypts the file**: Encrypts plaintext bytes, returning ciphertext and a 16-byte GMAC authentication tag.
6. **RSA-2048-OAEP encrypts AES session key**: The public key encrypts the 32-byte AES key using OAEP padding with SHA-256 digest.
7. **Encrypted package created (`.enc`)**: Stores base64-encoded encrypted AES key, nonce, ciphertext, original filename, and magic header into a JSON file.
8. **RSA private key recovers AES key during decryption**: `load_private_key()` unwraps the 32-byte AES key using the private key.
9. **AES-GCM decrypts and authenticates data**: `aesgcm.decrypt()` decrypts ciphertext and checks the 16-byte tag.
10. **Original file recovered**: Plaintext bytes are saved to disk, completing successful restoration.

---

## 12. Screenshots

Screenshots will be added after the final application demonstration.

### Recommended Screenshots to Capture for Documentation
1. **Main Application GUI**: Application window on startup.
2. **RSA Key Pair Generation**: Screen showing key status update to `[ FOUND ]` and generated PEM files.
3. **Target File Selection**: Selection of sample plaintext input file.
4. **File Encryption Success**: Status banner display `"File encrypted successfully."` and `"Encrypted package created successfully."`
5. **Structure of Encrypted `.enc` File**: JSON package displaying base64 encrypted key, nonce, and ciphertext.
6. **File Decryption Window**: `.enc` package selection and destination folder selection.
7. **Successful Integrity Verification**: Status banner displaying `"AES-GCM integrity verification successful."`
8. **Automated Unit Test Results**: Terminal window running `python test_crypto.py` displaying `Ran 5 tests ... OK`.

---

## 13. Project Demonstration

### Demonstration Steps (Workflow Walkthrough)
1. **Launch Application**: Run `python app.py`.
2. **Generate RSA Keys**: Click `🔑 Generate RSA Keys` in Section 1.
3. **Select Sample File**: Click `📂 Select File` and pick a test text file.
4. **Encrypt File**: Click `🔒 Encrypt File` and select `.enc` save destination.
5. **Show `.enc` File**: Open the generated `.enc` file in Notepad/VS Code to view the JSON package.
6. **Select Encrypted Package**: Choose the `.enc` file in Section 3.
7. **Decrypt Package**: Click `🔓 Decrypt File` and pick destination directory.
8. **Show Recovered File**: Open the recovered file and verify content matching.
9. **Demonstrate Integrity Verification**: Note AEAD tag check confirmation in log.
10. **Run Automated Test**: Run `python test_crypto.py` in terminal.

### Actual Verified Test Results
```text
TEST 1: Generate RSA keys ................................... PASS
TEST 2: Create sample file .................................. PASS
TEST 3: Encrypt file ........................................ PASS
TEST 4: Encrypted .enc file created ......................... PASS
TEST 5: Decrypt .enc file ................................... PASS
TEST 6: Recovered file content match ........................ PASS
TEST 7: AES-GCM integrity check on tampered package ......... PASS
TEST 8: Encryption without RSA public key error handling ... PASS
TEST 9: Decryption without RSA private key error handling .. PASS
TEST 10: Run test_crypto.py unit tests (5 OK) ............... PASS
```

---

## 14. Security Considerations

- **Private Key Confidentiality**: `private_key.pem` must be kept secret on the local host.
- **Git Protection via `.gitignore`**: Private key files (`keys/*.pem`) and `.enc` files are ignored to prevent committing credentials to GitHub.
- **AEAD Integrity Verification**: AES-256-GCM uses a 128-bit authentication tag to protect against unauthorized data tampering in transit or on disk.
- **RSA-OAEP Padding Defense**: RSA-2048-OAEP with SHA-256 and MGF1 protects against deterministic textbook RSA flaws and timing oracle attacks.
- **Fresh Random Session Parameters**: Every encryption task generates a unique 256-bit AES key and a 12-byte random nonce, preventing IV reuse vulnerabilities.
- **No Hardcoded Keys**: Cryptographic keys are generated dynamically rather than embedded in source code.

---

## 15. GitHub Repository

[View the project on GitHub](https://github.com/vibhutikatole-svg/hybrid-encryption-system.git)

<!-- Replace this placeholder with the actual GitHub repository URL. -->

---

## 16. Conclusion

This project demonstrates the practical application of **Hybrid Encryption** for secure file storage and management. By uniting the speed and authenticated integrity of **AES-256-GCM** with the asymmetric key encapsulation strength of **RSA-2048-OAEP**, the system efficiently overcomes RSA payload limits while ensuring strong data confidentiality and tamper detection. It serves as an effective educational model for Cryptography and Network Security principles.
