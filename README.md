# Veritas Encryptor

<p align="center">
<img width="50%" src="https://github.com/user-attachments/assets/205cda6b-54d0-40d4-8748-24227188712e">
</p>

## Introduction
Hello, NNNanase from Veritas is hier.

There are already excellent encryption software solutions like Veracrypt, created by skilled developers. In my personal opinion, these solutions provide sufficient security for most situations.

However, there are some scenarios where such software might not be the most suitable choice. Like, when you need to encrypt small files for email attachments, or when you need to encrypt files for devices that operate differently from conventional storage devices. Veritas Encryptor was developed to provide adequate security for file owners in such situations.

I developed this software primarily for my own use. As I'm still gaining experience as a developer, I cannot guarantee that the implementation is flawless. There's no warranty that this software provides the intended level of security, and users must assume all risks associated with its use. Compliance with encryption-related regulations remains the responsibility of the users.

Nevertheless, I hope this program can be helpfull to you.

I always welcome suggestions for improvements, related issues, and opinions on how I can make this software better.

## Key Features
Veritas Encryptor is designed to provide maximum security for file owners in situations where more comprehensive encryption software like Veracrypt might be impractical.

Users can encrypt individual files using a multi-algorithm encryption chain and decrypt files encrypted with this software. The software also offers functionality to change decryption passwords and verify encrypted files to check password matching and metadata integrity.

## Encryption Algorithm
Veritas Encryptor implements sequential dual encryption in the order of "ChaCha20-Poly1305" -> "AES-GCM", using independent keys and nonces for each algorithm.

The encryption key derivation follows this sequence:
"User Password" -> "Argon2id" -> "Master Key" -> "HKDF" -> "Two 32-byte keys (for ChaCha20-Poly1305 and AES-GCM)"

Argon2id is configured with 2GB memory cost, utilizing 8 threads for 8 iterations. The nonce is generated using HKDF, incorporating magic values, chunk numbers, and stage numbers.

## Core Libraries Used
- cryptography (v41.0.1)
- argon2-cffi (v23.1.0)
- psutil (v5.9.5)

## System Requirements
- Operating System: Windows 10 or later / Ubuntu 20.04 or later
- RAM: Minimum 4GB (8GB or more recommended)
- Disk Space: Sufficient space for program installation + temporary files during encryption

## Installation
We currently provide builds for Windows and Linux. Download and run the appropriate version for your operating system.

For Windows: Run VeritasEncryptor-windows.exe
For Linux: Execute ./VeritasEncryptor-linux in terminal

## Usage
The directory structure is as follows:

```
veritas-encryptor-windows(-linux)/
├── decrypted/    # Stores decrypted files
├── encrypted/    # Stores encrypted files
├── original/     # Place original files here
├── _internal/    # Required program libraries
└── VeritasEncryptor-windows(-linux)    # Executable
```

If you starts this software, you will provides the following functions:

1. File Encryption: Encrypts specific files or all files from the "original" folder using a password. Encrypted files are saved to the "encrypted" folder.
2. File Decryption: Decrypts specific files or all files from the "encrypted" folder using the corresponding password. Decrypted files are saved to the "decrypted" folder.
3. Change Password: Changes the encryption password for specific files or all files in the "encrypted" folder. Requires the current password.
4. File Verification: Verifies files in the "encrypted" folder to check password matching and metadata integrity.
5. Exit: Closes the program.

## Common Issues
Memory Insufficiency Error
- Cause: Insufficient memory for Argon2id operation
- Solution: Close other programs or free up system memory

File Corruption
- Cause: Interruption during encryption/decryption process
- Solution: Retry encryption with the original file

## Important Notes
It's recommended to use strong passwords that are not personally identifiable and have sufficient length. Since encrypted files cannot be recovered without the password, please keep your original files whenever possible.

This software was developed for personal use. As the developer of this software is still gaining experience, there's no guarantee of perfect implementation. I used Claude 3.5 Sonnet for error resolution process. And to saving myself from my spaghetti code, aswell.

While I believe the fully encrypted files provide adequate security, I currently feel that countermeasures against attacks targeting the encryption process, temporary files, and memory-related elements have not been sufficiently implemented. I plan to address these issues and add solutions once I gain more experience in the future. So there's no warranty for the security level provided, and users must assume all risks associated with its use. Compliance with encryption-related regulations remains the responsibility of the users.

## License
MIT License
