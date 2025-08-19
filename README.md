# HACK3FORCE

**Next-Generation Modular Password Cracking Framework for Penetration Testing**  
A revolutionary, fully Python-native framework designed to deliver unparalleled control, flexibility, and power in password cracking, wordlist generation, and hash analysis — all without relying on external engines or binaries.

---

## Overview

![Image](https://github.com/user-attachments/assets/5be1817e-d527-42d0-9249-46ad851b7ada)

**HACK3FORCE** is a state-of-the-art, all-encompassing brute force and dictionary attack platform, meticulously engineered from the ground up in pure Python. Unlike conventional tools that depend heavily on third-party cracking engines such as Hashcat, John the Ripper, or Hydra, **HACK3FORCE** features a proprietary, native cracking core. This independence ensures complete transparency, extensibility, and customization, empowering penetration testers, security researchers, and ethical hackers to tailor every aspect of their attack strategies.

The tool’s modular architecture divides functionality into three primary modes:

- **Mode 1:** Brute Force and Dictionary Attacks — supports a vast array of hash algorithms, encrypted archives, office documents, key files, and network services. It leverages multiprocessing to maximize throughput and includes advanced features like salted hash handling and customizable attack parameters.

- **Mode 2:** Wordlist Generation — offers targeted wordlist engineering based on personal data inputs, exhaustive combinatorial generators with pattern support, and web scraping capabilities to harvest contextual vocabulary from target websites.

- **Mode 3:** Hash Scanning and Analysis — provides multi-tiered hash identification and verification, from basic pattern matching to advanced heuristic and structural analysis, enabling users to gain deep insights into hash formats and optimize cracking approaches.

Designed for versatility and efficiency, **HACK3FORCE** supports a broad spectrum of protocols and file formats, including legacy and modern encryption schemes. Its parallel processing capabilities harness the full power of multi-core CPUs, drastically reducing cracking times while maintaining detailed, color-coded console feedback and secure logging for auditability.

By combining technical rigor with practical usability, **HACK3FORCE** stands as a comprehensive, self-contained solution that adapts seamlessly to diverse penetration testing scenarios — from targeted credential recovery to large-scale security assessments.

---

## Why HACK3FORCE?

In the rapidly evolving cybersecurity landscape, password cracking remains a cornerstone technique for assessing system resilience and uncovering vulnerabilities. However, many existing tools suffer from critical limitations:

- **Dependency on External Engines:** Reliance on third-party binaries restricts customization, complicates integration, and often obscures internal workings.

- **Limited Flexibility:** Predefined attack modes and rigid workflows hinder adaptation to unique or complex testing environments.

- **Transparency Concerns:** Closed-source or opaque implementations reduce trust and limit the ability to audit or extend functionality.

**HACK3FORCE** was conceived to overcome these challenges by delivering a fully independent, Python-based framework that puts control back into the hands of security professionals. Its native implementation of cracking algorithms and attack logic ensures:

- **Complete Transparency:** Every line of code is accessible and modifiable, enabling deep understanding and tailored enhancements.

- **Unmatched Flexibility:** Modular design and extensive configuration options allow precise tuning of attack parameters, from hash types and salts to character sets and multiprocessing strategies.

- **Extensibility:** The clean, well-structured codebase invites contributions and custom modules, fostering innovation and adaptation to emerging threats.

- **User-Centric Experience:** Intuitive command-line interface, color-coded output, verbose logging, and robust error handling streamline complex operations and improve productivity.

By eschewing external dependencies, **HACK3FORCE** not only simplifies deployment and maintenance but also empowers users to innovate freely — whether developing new attack vectors, integrating with custom workflows, or conducting research on novel hash formats.

In essence, **HACK3FORCE** is more than a tool; it is a platform for offensive security excellence, designed to evolve alongside the ever-changing landscape of cybersecurity threats.

---

## Core Features and Capabilities

## Mode 1 (Brute Force Attack Modes)

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

## Mode 2 (Make Wordlists Modes)

### 1. Targeted Wordlist Engineering Maker

- Interactive input prompts to gather personal information about the target such as names, nicknames, birthdates, partner and child details, pet names, and company names.
- Generates a comprehensive wordlist by combining and transforming the input data.
- Supports leet transformations, appending special characters, and numerical sequences to increase password variation.
- Outputs the generated wordlist to a dedicated directory for easy access.

---

### 2. All Combination Wordlist Generator

- Generates exhaustive password combinations based on user-defined character sets and length ranges.
- Supports pattern-based generation where specific character classes can be defined using symbols (e.g., `,` for lowercase letters, `@` for uppercase, `#` for digits, `%` for symbols).
- Ideal for brute force style attacks where all permutations within constraints are required.
- Efficiently saves generated wordlists to files with progress animations and verbose output options.

---

### 3. Web Scraper Wordlist Maker

- Scrapes text content from a target URL and optionally follows links up to a specified depth.
- Extracts meaningful words filtered by length and character type to build a contextual wordlist.
- Limits the number of URLs visited to control scraping scope.
- Useful for gathering target-specific vocabulary for social engineering or targeted dictionary attacks.

---

## Mode 3: 3 Ranks of Information Scan Hashes

This mode offers three levels of hash scanning sophistication, enabling users to analyze and process hashes with increasing depth and intelligence.

### 1. Basic Level Hash Scanner

- Performs straightforward hash identification and verification.
- Supports common hash types and simple pattern matching.
- Useful for quick checks and initial reconnaissance.

---

### 2. Intermediate Level Hash Scanner

- Enhances detection with additional heuristics.
- Supports salted hashes and more complex hash formats.
- Provides better accuracy in identifying hash algorithms and parameters.

---

### 3. Advanced Level Hash Scanner

- Implements deep analysis of hash structures.
- Supports multi-hash formats and combined hash types.
- Integrates with external data sources or dictionaries for improved cracking success.
- Designed for advanced users requiring detailed hash insights and customized cracking strategies.

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

1. Clone the Repository:

```bash
git clone https://github.com/davidvora/HACK3FORCE
cd HACK3FORCE
```

2. Verify Optional Dependencies:

```bash
pip install -r requirements.txt
```

Note: If the above command doesn't work (e.g., due to missing or broken environment), follow the optional steps below to set up a virtual environment and install the dependencies manually.

---

## Optional: Setting up a Virtual Environment

A. Check if `venv` is installed:

```bash
dpkg -s python3-venv
```

B. If it's not installed, install it with:

```bash
sudo apt install python3-venv
```

C. Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

D. Now install the Dependencies again:

```bash
pip install -r requirements.txt
```

---

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

## Usage Example for Mode 1 (Brute Force Attack Modes)

### Attack Mode 1: Single Hash Cracking

Crack a single hash using dictionary or brute force:

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 1 --hash <hash> --type <hash_type> [--dictionary <wordlist>] [--max-length N] [--processes N] [--verbose]
```

Example:

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 1 --hash 5f4dcc3b5aa765d61d8327deb882cf99 --type md5 --dictionary passwords.txt --verbose
```

---

### Attack Mode 2: Cracking Passwords for Archives, Encrypted Documents, and Key Files

**Archives Cracking:**

Crack ZIP Archive password:

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 2 --zip2hack secret.zip --dictionary passwords.txt --processes 4 --verbose
```

Crack 7z Archive password:

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 2 --a7z2hack secret.7z --dictionary passwords.txt --processes 4 --verbose
```

Crack RAR Archive password:

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 2 --rar2hack secret.rar --dictionary passwords.txt --processes 4 --verbose
```

Crack RAR5 Archive password:

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 2 --a5r2hack secret_rar5.rar --dictionary passwords.txt --processes 4 --verbose
```

**Encrypted File Cracking:**

Crack GPG Encrypted File password:

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 2 --gpg2hack secret.gpg --dictionary passwords.txt --processes 4 --verbose
```

**Office Documents Cracking:**

Crack PDF document Encrypted password:

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 2 --pdf2hack secret.pdf --dictionary passwords.txt --processes 4 --verbose
```

Crack Word Document Encrypted password (legacy format):

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 2 --doc2hack secret.doc --dictionary passwords.txt --processes 4 --verbose
```

Crack Word Document Encrypted password (Open XML format):

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 2 --docx2hack secret.docx --dictionary passwords.txt --processes 4 --verbose
```

Crack Excel Document Encrypted password (legacy format):

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 2 --xls2hack secret.xls --dictionary passwords.txt --processes 4 --verbose
```

Crack Excel Document Encrypted password (Open XML format):

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 2 --xlsx2hack secret.xlsx --dictionary passwords.txt --processes 4 --verbose
```

Crack PowerPoint Document Encrypted password (legacy format):

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 2 --ppt2hack secret.ppt --dictionary passwords.txt --processes 4 --verbose
```

Crack PowerPoint Document Encrypted password (Open XML format):

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 2 --pptx2hack secret.pptx --dictionary passwords.txt --processes 4 --verbose
```

**Encrypted Key files Cracking:**

Crack SSH Private Key password:

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 2 --spk2hack secret_id_rsa --dictionary passwords.txt --processes 4 --verbose
```

Crack PEM Private Key password:

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 2 --pem2hack secret_private_key.pem --dictionary passwords.txt --processes 4 --verbose
```

Crack KeePass KDB (v1.x) password:

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 2 --kdb2hack secret.kdb --dictionary passwords.txt --processes 4 --verbose
```

Crack KeePass KDBX (v2.x) password:

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 2 --kdbx2hack secret.kdbx --dictionary passwords.txt --processes 4 --verbose
```

**After Cracking protected file:**

Display the cracked password:

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 2 --show-pass [secret.zip | secret.7z | secret.rar | secret_rar5.rar | secret.gpg | secret.pdf | secret.doc | secret.docx | secret.xls | secret.xlsx | secret.ppt | secret.pptx | secret_id_rsa | secret_private_key.pem | secret.kdb | secret.kdbx]
```

---

### Attack Mode 3: Network Service Brute Forcing

Brute force SSH, FTP, MySQL, or SMB services:

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 3 --user <user> --password-list <password_list> --target-ip <ip> [--ssh | --ftp | --mysql | --smb] [--verbose]
```

Example SSH brute force:

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 3 --user admin --password-list passwords.txt --target-ip 192.168.1.100 --ssh --verbose
```

Example FTP brute force:

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 3 --user admin --password-list passwords.txt --target-ip 192.168.1.100 --ftp --verbose
```

Example MYSQL brute force:

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 3 --user admin --password-list passwords.txt --target-ip 192.168.1.100 --mysql --verbose
```

Example SMB brute force:

```bash
python3 HACK3FORCE.py --mode 1 --at_mode 3 --user admin --password-list passwords.txt --target-ip 192.168.1.100 --smb --verbose
```

---

## Usage Example for Mode 2 (Make Wordlist Modes)

### Make Wordlist Mode 1: Targeted Wordlist Engineering Maker

Example for targeted wordlist creation (interactive):

```bash
python3 HACK3FORCE.py --mode 2 --mk_mode 1
```

---

### Make Wordlist Mode 2: All Combination Wordlist Generator

Example for All Combination Wordlist generation:

```bash
python3 HACK3FORCE.py --mode 2 --mk_mode 2 --min 4 --max 4 --pat "@,#%" --out wordlist.txt --verbose
```

Example for selection characters Wordlist generation:

```bash
python3 HACK3FORCE.py --mode 2 --mk_mode 2 --min 4 --max 7 --chr test123 --out wordlist.txt --verbose
```
**Notes:**

`--mk_mode 2` selects the Make Wordlists mode.
`--min` and `--max` specify minimum and maximum password lengths (for all combination generator).
`--chr` defines the custom character set pattern
`--pat` defines the character set pattern (`,`=lowercase, `@`=uppercase, `#`=digits, `%`=symbols).
`--out` specifies the output file name.

---

### Make Wordlist Mode 3: Web Scraper Wordlist Maker

Example For web scraping wordlist generation:

```bash
python3 HACK3FORCE.py --mode 2 --mk_mode 3 --url https://example.com --depth 2 --max-url 10 --out scraped_wordlist.txt --verbose
```

---

## Usage Example for Mode 3 (Scan Hashes Modes)

Run the tool specifying Mode 3 and the desired scan rank:

Example Scan Hash Basic Level: 

```bash
python3 HACK3FORCE.py --mode 3 --sc_mode 1 --sc-hash <hash>
```

---

Example Scan Hash Intermediate Level: 

```bash
python3 HACK3FORCE.py --mode 3 --sc_mode 2
```

---

Example Scan Hash Advanced Level:

```bash
python3 HACK3FORCE.py --mode 3 --sc_mode 3
```

---

## Notes and Best Practices

* Always ensure you have explicit permission to test the target systems.
* Use verbose mode (`--verbose`) for detailed output during cracking.
* Adjust `--max-length` and `--processes` to balance speed and resource usage.
* Monitor logs (`cracked_passwords.log`) for results and auditing.
* Use strong, comprehensive wordlists for dictionary attacks to improve success rates.
* Use targeted wordlists to increase the success rate of dictionary attacks by incorporating personal information.
* Leverage the all combination generator for exhaustive brute force attempts within manageable keyspaces.
* Employ web scraping to gather contextual words related to the target environment.
* Always verify you have explicit permission before conducting any penetration testing activities.
* Use verbose mode to gain insights into the scanning process and results.
* Always verify you have authorization to test the target hashes.

---

## Ethical Notice

**For Authorized and Ethical Use Only**

1. HACK3FORCE is a professional offensive security tool intended solely for use by authorized individuals in legitimate penetration testing, red teaming, or security research environments, and only with proper consent.
2. Any unauthorized, illegal, or unethical use — including use against systems without explicit permission — is strictly forbidden and may constitute a criminal offense under applicable laws.
3. The developer of this tool disclaims all liability for misuse, damage, or legal consequences resulting from improper use.

---

## Tutorial HACK3FORCE Video

[![HACK3FORCE Demo Video](https://github.com/user-attachments/assets/6a19c636-e383-4821-9914-0beeabcb7294)](https://youtu.be/dJENF3bXl7A)

---

## Author

Developed by [David.dvora]

---

## Acknowledgments

This project was developed with the assistance of advanced AI tools to enhance coding efficiency, structure, and quality.
Special thanks to AI-assisted technologies for supporting the development process.

---
