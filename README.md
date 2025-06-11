# HACK3FORCE 

**Advanced Modular Brute Force Tool for Penetration Testing**

---

## Overview

**HACK3FORCE** is a cutting-edge, all-in-one brute force and dictionary attack tool, meticulously crafted entirely from scratch in Python. Unlike many existing tools that rely heavily on external engines such as Hashcat, John the Ripper, or Hydra, **HACK3FORCE** implements its own robust, native cracking logic. This makes it a truly unique, self-sufficient, and highly customizable solution tailored for penetration testers, security researchers, and ethical hackers who demand full control and transparency.

Designed with versatility and efficiency in mind, **HACK3FORCE** supports cracking passwords and hashes across a wide range of protocols and file formats. It leverages parallel processing to maximize speed and effectiveness, while providing detailed feedback and logging to keep users fully informed throughout the cracking process.

---

## Why HACK3FORCE?

In today’s cybersecurity landscape, password cracking tools are abundant, but many depend on external binaries or libraries, which can limit flexibility, transparency, and customization. **HACK3FORCE** was born out of the desire to break free from these constraints by delivering a fully independent Python-based tool that empowers security professionals to tailor their attacks precisely to their needs.

This project embodies the spirit of building from the ground up — combining deep technical expertise with practical usability — to deliver a tool that is not only powerful but also uniquely yours. By avoiding dependencies on third-party cracking engines, **HACK3FORCE** offers unparalleled control, extensibility, and the ability to innovate on top of a solid, self-contained foundation.

---

## Core Features and Capabilities

### 1. Password Cracking for Hashes

- **Wide Algorithm Support:**  
  Supports an extensive list of hash algorithms including but not limited to:
  MD5, SHA1, SHA256, SHA512, NTLM, bcrypt (including passlib variants), crypt family (md5-crypt, sha256-crypt, sha512-crypt), Argon2, RIPEMD160, Whirlpool, SHA3 variants, HMACs, and scrypt.

- **Salted Hash Handling:**  
  Flexible support for salted hashes with customizable salt placement, enabling cracking of more complex and realistic password storage schemes.

- **Attack Modes:**  
  Offers both dictionary attacks (using user-provided wordlists) and brute force attacks with fully customizable character sets and password length ranges.

- **Parallel Processing:**  
  Utilizes Python’s multiprocessing capabilities to distribute workload across multiple CPU cores, significantly accelerating cracking speed.

- **Customizable Parameters:**  
  Users can specify hash type, salt, dictionary files, brute force character sets, and more, allowing fine-tuned control over the cracking process.

---

### 2. Archive Password Cracking

- **Supported Formats:**  
  HACK3FORCE supports password cracking for a wide variety of protected file types, including common archive formats such as ZIP, RAR, RAR5, and 7z, as well as encrypted documents like PDF, Microsoft Office files (Word, Excel, PowerPoint in both legacy and Open XML formats), and encrypted key files including SSH private keys, PEM keys, and KeePass databases (KDB and KDBX). Additionally, it supports cracking GPG-encrypted files.
This extensive support enables recovery of lost or forgotten passwords across multiple file types and encryption schemes, all within a single unified tool.

- **Attack Types:**  
  Both dictionary and brute force attacks are implemented, with error handling to gracefully manage corrupted or unsupported archives.

- **Parallel Brute Force:**  
  The brute force attack is parallelized across multiple processes, splitting the character set to speed up cracking.

- **Verbose Feedback:**  
  Detailed console output informs users of progress, success, or failure, making it easy to monitor long-running cracking sessions.

---

### 3. Network Service Brute Forcing

- **Supported Protocols:**  
  Fully supports brute forcing of SSH, FTP, MySQL, and SMB services.

- **User and Password Lists:**  
  Allows specifying user lists and password lists for targeted credential guessing.

- **Rate Limiting and Proxy Support:**  
  Includes options to throttle request rates and use proxies, helping evade detection and avoid IP bans.

- **Detailed Logging:**  
  Verbose output and logging provide transparency and auditability of brute force attempts.

---

### 4. User Experience and Logging

- **Color-Coded Console Output:**  
  Uses ANSI color codes to highlight successes, failures, and informational messages, improving readability.

- **Secure Logging:**  
  Cracked passwords and relevant session data are logged securely to files for later review and auditing.

- **Error Handling:**  
  Robust error handling ensures the tool continues running smoothly even when encountering unexpected issues.

---

## Installation Guide

### Prerequisites

- **System Utilities:**
For RAR archive cracking, ensure the unrar utility is installed and accessible in your system’s PATH.

- **Python Version:**  
Python 3.7 or higher is required. Verify your Python version by running:

```bash
python3 --version
```

---

## Step-by-Step Installation

1. Clone the Repository :

```bash
git clone https://github.com/davidvora/HACK3FORCE
cd HACK3FORCE
```

2. Verify Optional Dependencies:

```bash
pip install -r requirements.txt
```

3. (Optional) Install system utilities for RAR support:

* On Debian/Ubuntu:

```bash
sudo apt-get install unrar
```

* On macOS (with Homebrew):

```bash
brew install unrar
```

---

## Usage

Run the tool with the desired mode and options. The tool supports three main modes:

### Mode 1: Single Hash Cracking

Crack a single hash using dictionary or brute force:

```bash
python3 HACK3FORCE.py --mode 1 --hash <hash> --type <hash_type> [--dictionary <wordlist>] [--max-length N] [--processes N] [--verbose]
```

Example:

```bash
python3 HACK3FORCE.py --mode 1 --hash 5f4dcc3b5aa765d61d8327deb882cf99 --type md5 --dictionary passwords.txt --verbose
```

---

### Mode 2: Cracking Passwords for Archives, Encrypted Documents, and Key Files

**Archives Cracking:**

Crack ZIP archive password:

```bash
python3 HACK3FORCE.py --mode 2 --zip2hack secret.zip --dictionary passwords.txt --processes 4 --verbose
```

Crack 7z archive Password:

```bash
python3 HACK3FORCE.py --mode 2 --a7z2hack secret.7z --dictionary passwords.txt --processes 4 --verbose
```

Crack RAR archive password:

```bash
python3 HACK3FORCE.py --mode 2 --rar2hack secret.rar --dictionary passwords.txt --processes 4 --verbose
```

Crack RAR5 Archive Password:

```bash
python3 HACK3FORCE.py --mode 2 --a5r2hack secret_rar5.rar --dictionary passwords.txt --processes 4 --verbose
```

**Encrypted File Cracking:**

Crack GPG Encrypted File Password:

```bash
python3 HACK3FORCE.py --mode 2 --gpg2hack secret.gpg --dictionary passwords.txt --processes 4 --verbose
```

**Office Documents Cracking:**

Crack PDF document Encrypted password:

```bash
python3 HACK3FORCE.py --mode 2 --pdf2hack secret.pdf --dictionary passwords.txt --processes 4 --verbose
```

Crack Word Document Encrypted Password (legacy format):

```bash
python3 HACK3FORCE.py --mode 2 --doc2hack secret.doc --dictionary passwords.txt --processes 4 --verbose
```

Crack Word Document Encrypted Password (Open XML format):

```bash
python3 HACK3FORCE.py --mode 2 --docx2hack secret.docx --dictionary passwords.txt --processes 4 --verbose
```

Crack Excel Document Encrypted Password (legacy format):

```bash
python3 HACK3FORCE.py --mode 2 --xls2hack secret.xls --dictionary passwords.txt --processes 4 --verbose
```

Crack Excel Document Encrypted Password (Open XML format):

```bash
python3 HACK3FORCE.py --mode 2 --xlsx2hack secret.xlsx --dictionary passwords.txt --processes 4 --verbose
```

Crack PowerPoint Document Encrypted Password (legacy format):

```bash
python3 HACK3FORCE.py --mode 2 --ppt2hack secret.ppt --dictionary passwords.txt --processes 4 --verbose
```

Crack PowerPoint Document Encrypted Password (Open XML format):

```bash
python3 HACK3FORCE.py --mode 2 --pptx2hack secret.pptx --dictionary passwords.txt --processes 4 --verbose
```

**Encrypted Key files Cracking:**

Crack SSH Private Key password:

```bash
python3 HACK3FORCE.py --mode 2 --spk2hack secret_id_rsa --dictionary passwords.txt --processes 4 --verbose
```

Crack PEM Private Key password:

```bash
python3 HACK3FORCE.py --mode 2 --pem2hack secret_private_key.pem --dictionary passwords.txt --processes 4 --verbose
```

Crack KeePass KDB (v1.x) password:

```bash
python3 HACK3FORCE.py --mode 2 --kdb2hack secret.kdb --dictionary passwords.txt --processes 4 --verbose
```

Crack KeePass KDBX (v2.x) password:

```bash
python3 HACK3FORCE.py --mode 2 --kdbx2hack secret.kdbx --dictionary passwords.txt --processes 4 --verbose
```

**After Cracking protected file:**

Display the cracked password:

```bash
python3 HACK3FORCE.py --mode 2 --show-pass [secret.zip | secret.rar | secret.pdf | secret_id_rsa | secret.gpg]
```

---

### Mode 3: Network Service Brute Forcing

Brute force SSH, FTP, MySQL, or SMB services:

```bash
python3 HACK3FORCE.py --mode 3 --user <user> --password-list <password_list> --target-ip <ip> [--ssh | --ftp | --mysql | --smb] [--verbose]
```

Example SSH brute force:

```bash
python3 HACK3FORCE.py --mode 3 --user admin --password-list passwords.txt --target-ip 192.168.1.100 --ssh --verbose
```

Example FTP brute force:

```bash
python3 HACK3FORCE.py --mode 3 --user admin --password-list passwords.txt --target-ip 192.168.1.100 --ftp --verbose
```

Example MYSQL brute force:

```bash
python3 HACK3FORCE.py --mode 3 --user admin --password-list passwords.txt --target-ip 192.168.1.100 --mysql --verbose
```

Example SMB brute force:

```bash
python3 HACK3FORCE.py --mode 3 --user admin --password-list passwords.txt --target-ip 192.168.1.100 --smb --verbose
```

---

## Notes and Best Practices

* Always ensure you have explicit permission to test the target systems.
* Use verbose mode (`--verbose`) for detailed output during cracking.
* Adjust `--max-length` and `--processes` to balance speed and resource usage.
* Monitor logs (`cracked_passwords.log`) for results and auditing.
* Use strong, comprehensive wordlists for dictionary attacks to improve success rates.

---

## Ethical Notice

**For Authorized and Ethical Use Only**

1. HACK3FORCE is a professional offensive security tool intended solely for use by authorized individuals in legitimate penetration testing, red teaming, or security research environments, and only with proper consent.
2. Any unauthorized, illegal, or unethical use — including use against systems without explicit permission — is strictly forbidden and may constitute a criminal offense under applicable laws.
3. The developer of this tool disclaims all liability for misuse, damage, or legal consequences resulting from improper use.

---

## Author

Developed by [David.dvora]

---

## Acknowledgments

This project was developed with the assistance of advanced AI tools to enhance coding efficiency, structure, and quality.
Special thanks to AI-assisted technologies for supporting the development process.

---
