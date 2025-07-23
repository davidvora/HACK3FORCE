import time
import itertools
import argparse
import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin


class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def mk_mode_1(output_file=None, verbose=False):
    print(Colors.FAIL + r"""
     /\     [ BUILDING WORDLIST MISSILE...                                                                          ]
    //\\    [ MODE: Targeted Wordlist Engineering                                                                   ]
    ||||    [ PHASE 1: Primary First Name, Family Name / Last Name, Common Alias / Username Nickname, date of birth ]
    ||||    [ PHASE 2: Significant Other's First Name, Partner's Common Alias, Partner’s Date of Birth              ]
    ||||    [ PHASE 3: Child’s Full Name, Child’s Nickname, Child’s Date of Birth                                   ]
    ||||    [ PHASE 4: Pet’s Name, Employer or Company Name, Hobbies or Interests, Phone numbers, Address, And more ]
   /_||_\   [ PHASE 5: (Optional) Adding key words, special chars, random numbers, Leet mode                        ]
    """ + Colors.ENDC)
    time.sleep(1.5)
    print(f"{Colors.OKCYAN}[+] Insert the information about the victim to make a missile wordlist for dictionary attack!{Colors.ENDC}")
    print(f"{Colors.OKCYAN}[+] If you don't know all the info, just hit enter when asked! ;){Colors.ENDC}\n")

    first_name = input(f"{Colors.BOLD}> Primary First Name: {Colors.ENDC}")
    surname = input(f"{Colors.BOLD}> Family Name / Last Name: {Colors.ENDC}")
    nickname = input(f"{Colors.BOLD}> Username Nickname: {Colors.ENDC}")
    birthdate = input(f"{Colors.BOLD}> date of birth (DDMMYYYY): {Colors.ENDC}")

    partner_name = input(f"\n{Colors.BOLD}> Significant Other's First Name: {Colors.ENDC}")
    partner_nickname = input(f"{Colors.BOLD}> Partner's Common Alias: {Colors.ENDC}")
    partner_birthdate = input(f"{Colors.BOLD}> Partner’s Date of Birth (DDMMYYYY): {Colors.ENDC}")

    child_name = input(f"\n{Colors.BOLD}> Child’s Full Name: {Colors.ENDC}")
    child_nickname = input(f"{Colors.BOLD}> Child’s Nickname: {Colors.ENDC}")
    child_birthdate = input(f"{Colors.BOLD}> Child’s Date of Birth (DDMMYYYY): {Colors.ENDC}")

    pet_name = input(f"\n{Colors.BOLD}> Pet’s Name: {Colors.ENDC}")
    company_name = input(f"{Colors.BOLD}> Employer or Company Name: {Colors.ENDC}")
    hobbies = input(f"{Colors.BOLD}> Hobbies or Interests: {Colors.ENDC}")
    phone_numbers = input(f"{Colors.BOLD}> Phone numbers or area codes: {Colors.ENDC}")
    address_city = input(f"{Colors.BOLD}> Address or City: {Colors.ENDC}")
    important_dates = input(f"{Colors.BOLD}> Other important dates (e.g., anniversary): {Colors.ENDC}")
    additional_pets = input(f"{Colors.BOLD}> Additional pet names or nicknames: {Colors.ENDC}")
    old_passwords = input(f"{Colors.BOLD}> Known old passwords or password patterns: {Colors.ENDC}")

    add_keywords = input(f"\n{Colors.BOLD}> Would you like to add personalized keywords related to the target? Y/[N]: {Colors.ENDC}").lower()
    keywords = []
    if add_keywords == 'y':
        keywords_input = input(f"{Colors.BOLD}> Enter custom words (separated by commas): {Colors.ENDC}")
        keywords = [word.strip() for word in keywords_input.split(',')]

    add_special_chars = input(f"\n{Colors.BOLD}> Append special characters to generated values? Y/[N]: {Colors.ENDC}").lower()
    special_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '?', '_'] if add_special_chars == 'y' else []

    add_numbers = input(f"\n{Colors.BOLD}> Append numerical sequences to generated values? Y/[N]: {Colors.ENDC}").lower()
    numbers = [str(i).zfill(2) for i in range(100)] if add_numbers == 'y' else []

    leet_mode = input(f"\n{Colors.BOLD}> Enable Leet Transformations (e.g., elite → 3l1t3)? Y/[N]: {Colors.ENDC}").lower()
    leet_replacements = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'} if leet_mode == 'y' else {}

    base_words = [
        first_name, surname, nickname, birthdate,
        partner_name, partner_nickname, partner_birthdate,
        child_name, child_nickname, child_birthdate,
        pet_name, company_name, hobbies, phone_numbers, address_city, important_dates, additional_pets, old_passwords
    ] + keywords

    base_words = [word for word in base_words if word]

    wordlist = set()
    for word in base_words:
        word = word.strip()
        variations = {
            word,
            word.lower(),
            word.upper(),
            word.capitalize(),
            word[::-1],  
        }

        if leet_mode == 'y':
            leet_word = ''.join([leet_replacements.get(c.lower(), c) for c in word])
            variations.add(leet_word)

        for variation in list(variations):
            for num in numbers:
                wordlist.add(f"{variation}{num}")
                wordlist.add(f"{num}{variation}")
                wordlist.add(f"{variation}_{num}")
            for char in special_chars:
                wordlist.add(f"{variation}{char}")
                wordlist.add(f"{char}{variation}")

        for other_word in base_words:
            if other_word != word:
                wordlist.add(f"{word}{other_word}")
                wordlist.add(f"{word}_{other_word}")
                wordlist.add(f"{word}.{other_word}")

    output_dir = "Wordlists"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    if not output_file:
        output_file = f"{first_name}.txt"
    output_path = os.path.join(output_dir, output_file)
    with open(output_path, 'w') as f:
        for word in sorted(wordlist):
            f.write(f"{word}\n")

    animate_missile_build()

    animate_missile_armed(output_path, len(wordlist))

    print(f"\n{Colors.OKBLUE}[+] Wordlist saved to {output_path}, counting {len(wordlist)} Passwords.{Colors.ENDC}")
    print(f"{Colors.OKGREEN}[+] Now load your wordlist with the command and attack! Good luck!{Colors.ENDC}")

    return output_file, wordlist

def animate_missile_build():
    print(Colors.WARNING + r"""
     /\
    //\\    [ BUILDING WORDLIST MISSILE...          ]
    ||||    [ PHASE 1: Collecting Target Data       ]
    ||||    [ PHASE 2: Generating Combinations      ]
    ||||    [ PHASE 3: Applying Leet Transformations]
    ||||    [ PHASE 4: Adding Special Payloads      ]
   /_||_\   [ PHASE 5: Finalizing Wordlist Matrix   ]
    """ + Colors.ENDC)
    time.sleep(1.5)

def animate_missile_armed(output_path, wordlist_size):
    print(Colors.OKGREEN + r"""
     /\
    //\\    
    ||||    [ STATUS: MISSILE ARMED!                ]
    ||||    [ TARGET FILE: """ + f"{output_path}".ljust(20) + Colors.OKGREEN + """     ]
    ||||    [ PAYLOAD SIZE: """ + f"{wordlist_size} Passwords".ljust(20) + Colors.OKGREEN + """    ]
    ||||    [ READY FOR ATTACK                      ]
   /_||_\\   [ AWAITING YOUR COMMAND...              ]
    """ + Colors.ENDC)
    time.sleep(1.5)

def generate_from_pattern(pattern, verbose=False):
    char_sets = {
        ',': 'abcdefghijklmnopqrstuvwxyz',  
        '@': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',  
        '#': '0123456789',                  
        '%': '!@#$%^&*()'                   
    }
    
    parts = []
    for char in pattern:
        if char in char_sets:
            parts.append(char_sets[char])
        else:
            parts.append(char)
    
    for combo in itertools.product(*parts):
        password = ''.join(combo)
        if verbose:
            print(f"{Colors.OKCYAN}[*] Generated: {Colors.OKGREEN}{password}{Colors.ENDC}")
        yield password


def generate_from_charset(charset, min_len, max_len, verbose=False):
    unique_passwords = set()
    for length in range(min_len, max_len + 1):
        if verbose:
            print(f"{Colors.OKBLUE}[*] Generating passwords of length: {length}{Colors.ENDC}")
        for combo in itertools.product(charset, repeat=length):
            password = ''.join(combo)
            unique_passwords.add(password)  
            if verbose:
                print(f"{Colors.OKCYAN}[*] Generated: {Colors.OKGREEN}{password}{Colors.ENDC}")
    return unique_passwords

def mk_mode_2(min_len=None, max_len=None, charset=None, pattern=None, output_file=None, verbose=False):
    animate_missile_build_mode2()  

    if verbose:
        print(f"{Colors.OKBLUE}[+] Verbose mode enabled. Showing detailed output.{Colors.ENDC}")

    if pattern:
        if verbose:
            print(f"{Colors.OKCYAN}[+] Using pattern: {pattern}{Colors.ENDC}")
        wordlist = list(generate_from_pattern(pattern, verbose))  
    elif charset and min_len and max_len:
        if verbose:
            print(f"{Colors.OKCYAN}[+] Using charset: {charset}{Colors.ENDC}")
            print(f"{Colors.OKBLUE}[+] Password length range: {min_len} to {max_len}{Colors.ENDC}")
        wordlist = generate_from_charset(charset, min_len, max_len, verbose) 
    else:
        print(f"{Colors.WARNING}[!] Error: Must specify either --pat or (--chr + --min + --max).{Colors.ENDC}")
        return

    output_dir = "Wordlists"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    if not output_file:
        output_file = "custom_wordlist.txt"
    output_path = os.path.join(output_dir, output_file)

    with open(output_path, 'w') as f:
        for word in wordlist:
            f.write(f"{word}\n")

    animate_missile_armed_mode2(output_path, len(wordlist))

    print(f"\n{Colors.OKBLUE}[+] Wordlist saved to {output_path}, counting {len(wordlist)} Passwords.{Colors.ENDC}")
    print(f"{Colors.OKGREEN}[+] Now load your wordlist and attack! Good luck!{Colors.ENDC}")

def animate_missile_build_mode2():
    print(Colors.WARNING + r"""
     /\
    //\\    [ BUILDING WORDLIST MISSILE...          ]
    ||||    [ MODE: ALL COMBINATION GENERATOR       ]
    ||||    [ Generating All Combinations...        ]
   /_||_\   
    """ + Colors.ENDC)
    time.sleep(1.5)

def animate_missile_armed_mode2(output_path, wordlist_size):
    print(Colors.OKGREEN + r"""
        
     /\     [ STATUS: MISSILE ARMED!                ]
    //\\    [ TARGET FILE: """ + f"{output_path}".ljust(20) + Colors.OKGREEN + """  ]
    ||||    [ PAYLOAD SIZE: """ + f"{wordlist_size} Passwords".ljust(20) + Colors.OKGREEN + """    ]
    ||||    [ READY FOR ATTACK                      ]
   /_||_\\   [ AWAITING YOUR COMMAND...              ]
    """ + Colors.ENDC)
    time.sleep(1.5)

def scrape_words_from_url(url, depth=1, max_url=None, verbose=False):
    """
    Scrape words from a given URL and optionally follow linked pages up to a specified depth.
    Stops if the number of visited URLs exceeds max_url (prints message only once).
    """
    words = set()
    visited = set()
    limit_reached = False  

    def _scrape(current_url, current_depth):
        nonlocal limit_reached  

        if current_url in visited or current_depth > depth or limit_reached:
            return

        if max_url is not None and len(visited) >= max_url:
            if verbose and not limit_reached:  
                print(f"{Colors.WARNING}[!] Reached max URL limit ({max_url}). Stopping.{Colors.ENDC}")
            limit_reached = True
            return

        visited.add(current_url)

        try:
            response = requests.get(current_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text()
            for word in text.split():
                cleaned_word = ''.join(c for c in word if c.isalnum())
                if len(cleaned_word) >= 4:  
                    words.add(cleaned_word.lower())

            if verbose:
                print(f"{Colors.OKCYAN}[*] Scraped: {current_url} (Depth: {current_depth}){Colors.ENDC}")

            if current_depth < depth and not limit_reached:
                for link in soup.find_all('a', href=True):
                    absolute_url = urljoin(current_url, link['href'])
                    if absolute_url.startswith(('http://', 'https://')):
                        _scrape(absolute_url, current_depth + 1)

        except Exception as e:
            if verbose:
                print(f"{Colors.FAIL}[!] Failed to scrape {current_url}: {e}{Colors.ENDC}")

    _scrape(url, 1)
    return words

def mk_mode_3(url=None, depth=1, max_url=None, output_file=None, verbose=False):
    animate_missile_build_mode3()  

    if not url:
        print(f"{Colors.FAIL}[!] Error: Must specify --url.{Colors.ENDC}")
        return

    if verbose:
        print(f"{Colors.OKBLUE}[+] Scraping words from: {url} (Depth: {depth}, Max URLs: {max_url}){Colors.ENDC}")

    words = scrape_words_from_url(url, depth, max_url, verbose)

    output_dir = "Wordlists"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    if not output_file:
        output_file = "scraped_wordlist.txt"
    output_path = os.path.join(output_dir, output_file)

    with open(output_path, 'w') as f:
        for word in sorted(words):
            f.write(f"{word}\n")

    animate_missile_armed_mode3(output_path, len(words))

    print(f"\n{Colors.OKBLUE}[+] Wordlist saved to {output_path}, counting {len(words)} words.{Colors.ENDC}")
    print(f"{Colors.OKGREEN}[+] Now load your wordlist and attack! Good luck!{Colors.ENDC}")

def animate_missile_build_mode3():
    print(Colors.WARNING + r"""
     /\
    //\\    [ BUILDING WORDLIST MISSILE...         ]
    ||||    [ MODE: WEB SCRAPER GENERATOR          ]
    ||||    [ Scraping Target Website...           ]
    ||||
   /_||_\   
    """ + Colors.ENDC)
    time.sleep(1.5)

def animate_missile_armed_mode3(output_path, wordlist_size):
    print(Colors.OKGREEN + r"""
     /\  
    //\\    [ STATUS: MISSILE ARMED!                ]
    ||||    [ TARGET FILE: """ + f"{output_path}".ljust(20) + Colors.OKGREEN + """     ]
    ||||    [ PAYLOAD SIZE: """ + f"{wordlist_size} words".ljust(20) + Colors.OKGREEN + """    ]
    ||||    [ READY FOR ATTACK                      ]
   /_||_\\   [ AWAITING YOUR COMMAND...              ]
    """ + Colors.ENDC)
    time.sleep(1.5)

def main():
    parser = argparse.ArgumentParser(description="HACK3FORCE Wordlist Generator")
    parser.add_argument("--mk_mode", type=int, choices=[1, 2, 3], required=True,
                        help="Wordlist sub-mode: 1=CUPP-like, 2=Crunch-like, 3=Web Scraping")
    parser.add_argument("--min", type=int, help="Minimum password length (for Crunch-like mode)")
    parser.add_argument("--max", type=int, help="Maximum password length (for Crunch-like mode)")
    parser.add_argument("--chr", type=str, help="Custom character set (for Crunch-like mode)")
    parser.add_argument("--pat", type=str, help="Password pattern (e.g., '@,#%') (lower-case = , | upper case = @ | Digits = # | Symbols = '%)")
    parser.add_argument("--out", type=str, help="Output file path for the wordlist")
    parser.add_argument("--url", type=str, help="Target URL to scrape (for Web Scraping mode)")
    parser.add_argument("--depth", type=int, default=1, help="Scraping depth (default: 1)")
    parser.add_argument("--max-url", type=int, help="Maximum number of URLs to scan (for Web Scraping mode)")
    parser.add_argument("--verbose", "--ver", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    if args.mk_mode == 1:
        mk_mode_1(args.out)
    elif args.mk_mode == 2:
        mk_mode_2(args.min, args.max, args.chr, args.pat, args.out, args.verbose)
    elif args.mk_mode == 3:
        mk_mode_3(args.url, args.depth, args.max_url, args.out, args.verbose)

if __name__ == "__main__":
    main()
