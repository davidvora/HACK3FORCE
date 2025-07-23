import argparse
import subprocess
import sys


class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def banner():
    print(Colors.FAIL + """       
██╗  ██╗ █████╗  ██████╗██╗  ██╗ ██████╗  ███████╗ ██████╗ ██████╗   ██████╗███████╗
██║  ██║██╔══██╗██╔════╝██║ ██╔╝ ╚════██╗ ██╔════╝██╔═══██╗██╔══██╗ ██╔════╝██╔════╝
███████║███████║██║     █████╔╝   █████╔╝ ███████╗██║   ██║██████╔╝ ██║     █████╗
██╔══██║██╔══██║██║     ██╔═██╗   ╚═══██╗ ██╔════╝██║   ██║██╔══██╗ ██║     ██╔══╝
██║  ██║██║  ██║╚██████╗██║  ██╗ ██████╔╝ ██║     ╚██████╔╝██║   ██╗╚██████╗███████╗
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚═╝      ╚═════╝ ╚═╝   ╚═╝ ╚═════╝╚══════╝
""" + Colors.ENDC)                
    print(Colors.FAIL + Colors.BOLD + "Next-Generation Modular Password Cracking Framework for Penetration Testing \n" + Colors.ENDC)
    print(Colors.WARNING + "[!] WARNING: HACK3FORCE is a powerful offensive security Framework intended for ethical use only.\n"
          "[!] Any unauthorized, illegal, or malicious use is strictly prohibited and may constitute a criminal offense.\n"
          "[!] The creator of this Framework take no responsibility for misuse or any resulting damage.\n" + Colors.ENDC)
    print(Colors.FAIL + Colors.BOLD + "by David Dvora" + Colors.ENDC)
    print(Colors.FAIL + Colors.BOLD + "Version: v3.0\n" + Colors.ENDC)

def main():
    banner()
    parser = argparse.ArgumentParser(
        description="HACK3FORCE - Next-Generation Modular Password Cracking Framework for Penetration Testing"
    )
    parser.add_argument("--mode", type=int, choices=[1, 2, 3], required=True,
                        help="Main mode: 1=Attack (--at_mode), 2=make Wordlist (--mk_mode), 3=Hash Scan (--sc_mode)")
    
    parser.add_argument("--at_mode", type=int, choices=[1, 2, 3],
                        help='Mode of operation: 1=hash crack (like Hashcat), 2=hash file crack (like JTR), 3=network crack (like Hydra)')
    
    parser.add_argument("--mk_mode", type=int, choices=[1, 2, 3],
                        help="Wordlist sub-mode: 1=Targeted Wordlist Engineering (like Cupp), 2=All Combination Generator (like Crunch), 3=Web Scraper (like CeWL)")

    parser.add_argument("--sc_mode", type=int, choices=[1, 2, 3],
                        help="Hash scan sub-mode: 1=Basic Scan (like hashid), 2=Intermediate Scan (like hash-identifier), 3=Advanced Scan (like Name That Hash)")

    parser.add_argument("--hash", type=str, help="Target hash to crack (--mode 1 --at_mode 1)")
    parser.add_argument('--type', default='md5', help='Hash type (md5, sha1, sha256, sha512, ntlm, bcrypt, bcrypt-passlib, md5-crypt, sha256-crypt, sha512-crypt, argon2, ripemd160, whirlpool, sha3_256, sha3_512, md5_salt_pass, md5_pass_salt, sha1_salt_pass, sha1_pass_salt, sha256_salt_pass, sha256_pass_salt, hmac_md5, hmac_sha1, hmac_sha256, hmac_sha512, scrypt) (--mode 1 --at_mode 1)')
    parser.add_argument('--salt', help='Salt value if required by hash type (--mode 1 --at_mode 1)')
    parser.add_argument('--max-length', type=int, default=6, help='Max password length for brute force (--mode 1 --at_mode 1/2)')
    parser.add_argument('--processes', type=int, default=4, help='Number of parallel processes (--mode 1 --at_mode 1/2/3)')
    parser.add_argument('--dictionary', help='Path to dictionary file for dictionary attack (--mode 1 --at_mode 1/2)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output (--mode 1/2/3 --at_mode 1/2/3 | --mk_mode 2/3)')
    parser.add_argument('--zip2hack', help="Path to ZIP file to crack (--mode 1 --at_mode 2)")
    parser.add_argument('--a7z2hack', help='Path to 7z encrypted archive to crack (--mode 1 --at_mode 2)')
    parser.add_argument('--rar2hack', help='Path to RAR file to crack (--mode 1 --at_mode 2)')
    parser.add_argument('--a5r2hack', help='Path to RAR5 encrypted archive to crack (--mode 1 --at_mode 2)')
    parser.add_argument('--gpg2hack', help='Path to GPG encrypted file to crack (--mode 1 --at_mode 2)')
    parser.add_argument('--pdf2hack', help='Path to PDF file to crack (--mode 1 --at_mode 2)')
    parser.add_argument('--doc2hack', help='Path to Word document protected to crack (--mode 1 --at_mode 2)')
    parser.add_argument('--xls2hack', help='Path to Excel document password protected to crack (--mode 1 --at_mode 2)')
    parser.add_argument('--ppt2hack', help='Path to PowerPoint document password protected to crack (--mode 1 --at_mode 2)')
    parser.add_argument('--docx2hack', help='Path to DOCX (Open XML) protected document to crack (--mode 1 --at_mode 2)')
    parser.add_argument('--xlsx2hack', help='Path to XLSX (Open XML) protected document to crack (--mode 1 --at_mode 2)')
    parser.add_argument('--pptx2hack', help='Path to PPTX (Open XML) protected document to crack (--mode 1 --at_mode 2)')
    parser.add_argument('--pem2hack', help='Path to encrypted PEM file protected to crack (--mode 1 --at_mode 2)')
    parser.add_argument('--spk2hack', help='Path to SSH private key file to crack (password protected) (--mode 1 --at_mode 2)')
    parser.add_argument('--kdb2hack', help='Path to KeePass 1.x kdb file protected to crack (--mode 1 --at_mode 2)')
    parser.add_argument('--kdbx2hack', help='Path to KeePass 2.x kdbx protected to crack (--mode 1 --at_mode 2)')
    parser.add_argument('--show-pass', help='Show cracked password for given file (--mode 1 --at_mode 2)')
    parser.add_argument('--user', help='Single username or path to user list file (--mode 1 --at_mode 3)')
    parser.add_argument('--password-list', help='Password list file (--mode 1 --at_mode 3)')
    parser.add_argument('--target-ip', help='Target IP address (--mode 1 --at_mode 3)')
    parser.add_argument('--ssh', action='store_true', help='Use SSH protocol (--mode 1 --at_mode 3)')
    parser.add_argument('--ftp', action='store_true', help='Use FTP protocol (--mode 1 --at_mode 3)')
    parser.add_argument('--mysql', action='store_true', help='Use MySQL protocol (--mode 1 --at_mode 3)')
    parser.add_argument('--smb', action='store_true', help='Use SMB protocol (--mode 1 --at_mode 3)')
    parser.add_argument("--min", type=int, help="Minimum password length (for --mode 2 --mk_mode 2)")
    parser.add_argument("--max", type=int, help="Maximum password length (for --mode 2 --mk_mode 2)")
    parser.add_argument("--chr", type=str, help="Custom character set (for --mode 2 --mk_mode 2)")
    parser.add_argument("--pat", type=str, help="Password pattern (e.g., '@,#%%') (lower-case = , | upper-case = @ | Digits = # | Symbols = %%) (--mode 2 --mk_mode 2)")
    parser.add_argument("--out", type=str, help="Output file path (--mode 2 --mk_mode 2/3)")
    parser.add_argument("--url", type=str, help="Target URL for web scraping (--mode 2 --mk_mode 3)")
    parser.add_argument("--depth", type=int, help="Scan depth (--mode 2 --mk_mode 3)")
    parser.add_argument("--max-url", type=int, default=None, help="Maximum number of URLs to scan (--mode 2 --mk_mode 3)")
    parser.add_argument("--sc-hash", type=str, help="Hash to identify (--mode 3 --sc_mode 1)")
    args = parser.parse_args()

    filtered_args = []
    skip_next = False
    for arg in sys.argv[1:]:
        if skip_next:
            skip_next = False
            continue
        if arg == "--mode":
            skip_next = True
            continue
        filtered_args.append(arg)

    if args.mode == 1:
        subprocess.run(["python3", "HACK3FORCE_MODS/at_mode.py"] + filtered_args)
    elif args.mode == 2:
        subprocess.run(["python3", "HACK3FORCE_MODS/mk_mode.py"] + filtered_args)
    elif args.mode == 3:
        subprocess.run(["python3", "HACK3FORCE_MODS/sc_mode.py"] + filtered_args)

if __name__ == "__main__":
    main()
