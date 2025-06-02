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
  Password-protected ZIP and RAR archives are supported, enabling recovery of lost or forgotten archive passwords.

- **Attack Types:**  
  Both dictionary and brute force attacks are implemented, with error handling to gracefully manage corrupted or unsupported archives.

- **Parallel Brute Force:**  
  The brute force attack is parallelized across multiple processes, splitting the character set to speed up cracking.

- **Verbose Feedback:**  
  Detailed console output informs users of progress, success, or failure, making it easy to monitor long-running cracking sessions.

---

### 3. Network Service Brute Forcing

- **Protocols Supported:**  
  SSH and FTP forms brute forcing are fully supported.

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
python HACK3FORCE.py --mode 1 --hash <hash> --type <hash_type> [--dictionary <wordlist>] [--max-length N] [--processes N] [--verbose]
```

Example:

```bash
python HACK3FORCE.py --mode 1 --hash 5f4dcc3b5aa765d61d8327deb882cf99 --type md5 --dictionary passwords.txt --verbose
```

---

### Mode 2: Archive Cracking

Crack ZIP archive password:

```bash
python HACK3FORCE.py --mode 2 --zip2hack secret.zip --dictionary passwords.txt --processes 4 --verbose
```

Crack RAR archive password:

```bash
python HACK3FORCE.py --mode 2 --rar2hack secret.rar --dictionary passwords.txt --processes 4 --verbose
```

Show cracked password after crack:

```bash
python HACK3FORCE.py --mode 2 --show-pass secret.zip
```

OR:

```bash
python HACK3FORCE.py --mode 2 --show-pass secret.rar
```

---

### Mode 3: Network Service Brute Forcing

Brute force SSH or FTP forms:

```bash
python HACK3FORCE.py --mode 3 --user <user> --password-list <password_list> --target-ip <ip> [--ssh | --ftp | [--verbose]
```

Example SSH brute force:

```bash
python HACK3FORCE.py --mode 3 --user admin --password-list passwords.txt --target-ip 192.168.1.100 --ssh --verbose
```

Example FTP brute force:

```bash
python HACK3FORCE.py --mode 3 --user admin --password-list passwords.txt --target-ip 192.168.1.100 --ftp --verbose
```

---

## Notes and Best Practices

* Always ensure you have explicit permission to test the target systems.
* Use verbose mode (--verbose) for detailed output during cracking.
* Adjust --max-length and --processes to balance speed and resource usage.
* Monitor logs (cracked_passwords.log) for results and auditing.
* Use strong comprehensive wordlists for dictionary attacks to improve success rates.

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
