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

def banner():
    print(Colors.FAIL + """       
██╗  ██╗ █████╗  ██████╗██╗  ██╗ ██████╗  ███████╗ ██████╗ ██████╗   ██████╗███████╗
██║  ██║██╔══██╗██╔════╝██║ ██╔╝ ╚════██╗ ██╔════╝██╔═══██╗██╔══██╗ ██╔════╝██╔════╝
███████║███████║██║     █████╔╝   █████╔╝ ███████╗██║   ██║██████╔╝ ██║     █████╗
██╔══██║██╔══██║██║     ██╔═██╗   ╚═══██╗ ██╔════╝██║   ██║██╔══██╗ ██║     ██╔══╝
██║  ██║██║  ██║╚██████╗██║  ██╗ ██████╔╝ ██║     ╚██████╔╝██║   ██╗╚██████╗███████╗
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚═╝      ╚═════╝ ╚═╝   ╚═╝ ╚═════╝╚══════╝
""" + Colors.ENDC)                
    print(Colors.FAIL + Colors.BOLD + "Advanced Modular Brute Force Tool for Penetration Testing \n" + Colors.ENDC)
    print(Colors.WARNING + "[!] WARNING: HACK_FORCE is a powerful offensive security tool intended for ethical use only.\n"
          "[!] Any unauthorized, illegal, or malicious use is strictly prohibited and may constitute a criminal offense.\n"
          "[!] The creator of this tool take no responsibility for misuse or any resulting damage.\n" + Colors.ENDC)
    print(Colors.FAIL + Colors.BOLD + "by David Dvora" + Colors.ENDC)
    print(Colors.FAIL + Colors.BOLD + "Version: v1.0\n" + Colors.ENDC)
    
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

def run_hack_force(mode=1,target_hash=None,hash_type='md5',salt=None,max_length=6,processes=4,dictionary=None,verbose=False,zip2hack=None,rar2hack=None,show_pass=None,user=None,password_list=None,target_ip=None,HPF=None,ssh=False,ftp=False):

    salt_val = salt if salt else None

    if mode == 1:
        if not target_hash:
            print(f"{Colors.WARNING}[!]Error: target_hash is required in mode 1{Colors.ENDC}")
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

    elif mode == 2:
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

    elif mode == 3:
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
    except rarfile.RarWrongPassword: # Bad Rar file!
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

def crack_archive(archive_path, archive_type, dictionary_file=None, verbose=False, processes=1):
    if dictionary_file:
        password = dictionary_attack_archive(archive_path, archive_type, dictionary_file, verbose, processes)
        return password
    else:
        if verbose:
            print(f"{Colors.WARNING}[!] No dictionary file provided, starting brute force...{Colors.ENDC}")
        password = brute_force_parallel_archive(archive_path, archive_type, max_length=6, processes=processes, verbose=verbose)
        return password

def run_mode_3(args):
    if not (args.user and args.password_list and args.target_ip):
        print("Error: --user, --password-list, and --target-ip are required for mode 3")
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
    else:
        print(f"{Colors.WARNING}[!]Error: You must specify one of --ssh, --ftp, or --HPF for mode 3.{Colors.ENDC}")
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

def main():
    banner()
    parser = argparse.ArgumentParser(description="HACK_3_FORCE - Advanced Modular Brute Force Tool for Penetration Testing")
    parser.add_argument('--mode', type=int, choices=[1,2,3], default=1,
                        help='Mode of operation: 1=hash crack (like Hashcat), 2=hash file crack (like JTR), 3=network crack (like Hydra)')
    parser.add_argument('--hash', help='Target hash to crack (mode 1)')
    parser.add_argument('--type', default='md5', help='Hash type (md5, sha1, sha256, sha512, ntlm, bcrypt, bcrypt-passlib, md5-crypt, sha256-crypt, sha512-crypt, argon2, ripemd160, whirlpool, sha3_256, sha3_512, md5_salt_pass, md5_pass_salt, sha1_salt_pass, sha1_pass_salt, sha256_salt_pass, sha256_pass_salt, hmac_md5, hmac_sha1, hmac_sha256, hmac_sha512, scrypt)')
    parser.add_argument('--salt', help='Salt value if required by hash type')
    parser.add_argument('--max-length', type=int, default=6, help='Max password length for brute force')
    parser.add_argument('--processes', type=int, default=4, help='Number of parallel processes')
    parser.add_argument('--dictionary', help='Path to dictionary file for dictionary attack (mode 1 or 2)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--zip2hack', help='Path to ZIP file to crack (mode 2)')
    parser.add_argument('--rar2hack', help='Path to RAR file to crack (mode 2)')
    parser.add_argument('--show-pass', help='Show cracked password for given file (mode 2)')
    parser.add_argument('--user', help='Single username or path to user list file (mode 3)')
    parser.add_argument('--password-list', help='Password list file for mode 3')
    parser.add_argument('--target-ip', help='Target IP address (mode 3)')
    parser.add_argument('--ssh', action='store_true', help='Use SSH protocol (mode 3)')
    parser.add_argument('--ftp', action='store_true', help='Use FTP protocol (mode 3)')
    args = parser.parse_args()

    salt = args.salt if args.salt else None

    if args.mode == 1:
        if not args.hash:
            print(f"{Colors.WARNING}[!] Error: --hash is required in mode 1{Colors.ENDC}")
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

    elif args.mode == 2:
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

    elif args.mode == 3:
    	run_mode_3(args)
    	return

if __name__ == "__main__":
    main()
