# Advanced-Encryption-Tool

COMPANY: CODTECH IT SOLUTIONS

NAME: SANTHOSH N

INTERN ID: CT04DR350

DOMAIN: CYBER SECURITY

DURATION: 4 WEEKS

MENTOR: MUZAMMIL

****DESCRIPTION:****

Securing sensitive data is a fundamental aspect of information security. Unauthorized access or tampering with files can lead to severe consequences such as data breaches, identity theft, and system compromise. To mitigate such risks, encryption plays a vital role by transforming readable information (plaintext) into an unreadable format (ciphertext), ensuring that only authorized users with the correct key can restore it. This project focuses on building a Python-based File Encryption and Decryption Tool that leverages the AES-256-GCM (Advanced Encryption Standard – 256-bit key with Galois/Counter Mode) algorithm, one of the most secure and efficient encryption standards in modern cryptography.

The tool provides both a Command Line Interface (CLI) and a Graphical User Interface (GUI) (built using Tkinter) to make encryption accessible to both technical and non-technical users. Through these interfaces, users can securely encrypt and decrypt any file using a password-derived key, ensuring the confidentiality and integrity of stored or transmitted data.

At its core, the tool uses PBKDF2 (Password-Based Key Derivation Function 2) with SHA-256 hashing to derive a strong cryptographic key from the user’s password. A unique random salt and nonce are generated for each encryption operation, preventing attacks based on key reuse or pattern recognition. AES-GCM mode ensures both encryption and authentication, meaning that any modification to the encrypted data or use of an incorrect password will be immediately detected and rejected during decryption.

**The workflow of the project involves:**

**Encryption Phase:** The user selects an input file, provides a password, and the tool encrypts the file in chunks for efficiency. The output file includes metadata like version, salt, nonce, and authentication tag to facilitate secure decryption later.

**Decryption Phase:** Using the same password, the tool reconstructs the key, validates the authentication tag, and decrypts the file securely. If the password or data is incorrect, decryption fails, ensuring protection against tampering.

**GUI Operation:** The Tkinter-based interface simplifies interaction by allowing users to browse files, enter passwords, and perform encryption or decryption with a single click, while CLI mode provides flexibility for automation or advanced users.

This tool effectively combines cryptographic strength, user-friendliness, and data integrity into one utility. It is ideal for securing personal or confidential documents, ensuring compliance with data protection policies, and serving as an educational project to demonstrate practical applications of modern encryption techniques. By implementing AES-256-GCM with PBKDF2 key derivation, the project exemplifies how robust cryptography can be integrated into real-world applications to achieve high standards of data security.
