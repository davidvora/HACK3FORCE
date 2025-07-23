import re
import argparse
from typing import Dict, List

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def identify_hash(hash_input: str) -> Dict[str, List[str]]:
    """
    Identify the hash algorithm based on the input hash.
    Returns a dictionary with 'possible' and 'least_possible' algorithms.
    """
    hash_length = len(hash_input)
    hash_algorithms = {
        'MD5': {
            'length': 32,
            'regex': r'^[a-fA-F0-9]{32}$',
            'description': 'md5 hash (weak, widely used for checksums)',
            'probability': 'High'
        },
        'SHA-1': {
            'length': 40,
            'regex': r'^[a-fA-F0-9]{40}$',
            'description': 'sha1 hash (deprecated due to vulnerabilities)',
            'probability': 'High'
        },
        'SHA-256': {
            'length': 64,
            'regex': r'^[a-fA-F0-9]{64}$',
            'description': 'sha256 hash (secure, part of SHA-2 family)',
            'probability': 'High'
        },
        'SHA-512': {
            'length': 128,
            'regex': r'^[a-fA-F0-9]{128}$',
            'description': 'sha512 hash (secure, part of SHA-2 family)',
            'probability': 'High'
        },
        'SHA3-256': {
            'length': 64,
            'regex': r'^[a-fA-F0-9]{64}$',
            'description': 'sha3_256 hash (secure, part of SHA-3 family)',
            'probability': 'Medium'
        },
        'SHA3-512': {
            'length': 128,
            'regex': r'^[a-fA-F0-9]{128}$',
            'description': 'sha3_512 hash (secure, part of SHA-3 family)',
            'probability': 'Medium'
        },
        'RIPEMD-160': {
            'length': 40,
            'regex': r'^[a-fA-F0-9]{40}$',
            'description': 'ripemd160 hash (used in Bitcoin)',
            'probability': 'Medium'
        },
        'Whirlpool': {
            'length': 128,
            'regex': r'^[a-fA-F0-9]{128}$',
            'description': 'whirlpool hash (secure but rarely used)',
            'probability': 'Low'
        },
        'NTLM': {
            'length': 32,
            'regex': r'^[a-fA-F0-9]{32}$',
            'description': 'NTLM hash (used in Windows authentication)',
            'probability': 'High'
        },
        'bcrypt': {
            'length': 60,
            'regex': r'^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$',
            'description': 'bcrypt hash (secure, used for password hashing)',
            'probability': 'High'
        },
    }

    possible = []
    least_possible = []

    for algo, properties in hash_algorithms.items():
        if hash_length == properties['length'] and re.match(properties['regex'], hash_input):
            possible.append(algo)
        elif hash_length == properties['length']:
            least_possible.append(algo)

    return {
        'possible': possible,
        'least_possible': least_possible,
        'algorithms': hash_algorithms
    }

def main():
    parser = argparse.ArgumentParser(description="HACK3FORCE")
    parser.add_argument("--mode", type=int, help="Operation mode (for internal use)")
    parser.add_argument("--sc_mode", type=int, required=True, help="Scan mode (1=Basic Scan (like hashid), 2=Intermediate Scan (like hash-identifier), 3=Advanced Scan (like Name That Hash)")
    parser.add_argument("--sc-hash", type=str, help="Hash to analyze (required for --sc_mode 1)")
    args = parser.parse_args()

    if args.sc_mode == 1:
        if not args.sc_hash:
            print(f"{Colors.FAIL}Error: --sc-hash is required for --sc_mode 1.{Colors.ENDC}")
            return
        print(f"{Colors.OKCYAN}Analyzing {Colors.OKGREEN}{args.sc_hash}{Colors.ENDC}\n")
        identified = identify_hash(args.sc_hash)
        if identified['possible']:
            for algo in identified['possible']:
                print(f"{Colors.OKBLUE}[+] {Colors.OKGREEN}{algo}{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}No matching hash algorithm found.{Colors.ENDC}")

    elif args.sc_mode == 2:
        print(f"{Colors.OKCYAN}Hash to scan: {Colors.OKGREEN}", end="")
        hash_input = input().strip()
        identified = identify_hash(hash_input)
        
        if identified['possible']:
            print(f"\n{Colors.OKCYAN}Possible Hashes:{Colors.ENDC}")
            for algo in identified['possible']:
                print(f"{Colors.OKBLUE}[+] {Colors.OKGREEN}{algo}{Colors.ENDC}")
        
        if identified['least_possible']:
            print(f"\n{Colors.OKCYAN}Least Possible Hashes:{Colors.ENDC}")
            for algo in identified['least_possible']:
                print(f"{Colors.OKBLUE}[+] {Colors.OKGREEN}{algo}{Colors.ENDC}")
        
        if not identified['possible'] and not identified['least_possible']:
            print(f"{Colors.FAIL}No matching hash algorithm found.{Colors.ENDC}")

    elif args.sc_mode == 3:
        print(f"{Colors.OKCYAN}Please enter the hash value for scanning: {Colors.OKGREEN}", end="")
        hash_input = input().strip()
        identified = identify_hash(hash_input)
        
        print(f"\n{Colors.OKCYAN}Results for hash:{Colors.ENDC}\n")
        
        if identified['possible']:
            print(f"{Colors.HEADER}=== High Probability Hashes ==={Colors.ENDC}\n")
            for algo in identified['possible']:
                algo_info = identified['algorithms'][algo]
                print(f"{Colors.OKBLUE}[+] {Colors.OKGREEN}{algo}{Colors.ENDC}")
                print(f"{Colors.WARNING}   Description: {Colors.OKCYAN}{algo_info['description']}{Colors.ENDC}")
                print(f"{Colors.WARNING}   Probability: {Colors.BOLD}{Colors.FAIL}{algo_info['probability']}{Colors.ENDC}\n")
        
        if identified['least_possible']:
            print(f"{Colors.HEADER}=== Low Probability Hashes ==={Colors.ENDC}\n")
            for algo in identified['least_possible']:
                algo_info = identified['algorithms'][algo]
                print(f"{Colors.OKBLUE}[+] {Colors.OKGREEN}{algo}{Colors.ENDC}")
                print(f"{Colors.WARNING}   Description: {Colors.OKCYAN}{algo_info['description']}")
                print(f"{Colors.WARNING}   Probability: {Colors.BOLD}{Colors.FAIL}{algo_info['probability']}{Colors.ENDC}\n")
        
        if not identified['possible'] and not identified['least_possible']:
            print(f"{Colors.FAIL}No matching hash algorithm found.{Colors.ENDC}")

    else:
        print(f"{Colors.WARNING}Error: Only --sc_mode 1, 2, and 3 are supported.{Colors.ENDC}")

if __name__ == "__main__":
    main()
