#!/usr/bin/env python3
import hashlib
import binascii
import argparse
from impacket.krb5.crypto import string_to_key

def generate_ad_hashes(password, domain, username):
    print(f"[*] Target User : {username}")
    print(f"[*] Target FQDN : {domain}")
    print(f"[*] Password    : {password}\n")

    # 1. NTLM Hash (RC4)
    # Active Directory NTLM is just MD4(UTF-16LE(password))
    try:
        ntlm_hash = hashlib.new('md4', password.encode('utf-16le')).digest()
        print(f"[+] NTLM (RC4) : {binascii.hexlify(ntlm_hash).decode('utf-8')}")
    except Exception as e:
        print(f"[-] Error calculating NTLM: {e}")

    # 2. Kerberos AES Keys
    # The salt is strictly: UPPERCASE_DOMAIN + lowercase_username
    salt = domain.upper() + username
    print(f"[*] Applied Salt: {salt}\n")

    try:
        # AES-128 (etype 17)
        key_aes128 = string_to_key(17, password, salt, None)
        print(f"[+] AES-128    : {key_aes128.contents.hex()}")

        # AES-256 (etype 18)
        key_aes256 = string_to_key(18, password, salt, None)
        print(f"[+] AES-256    : {key_aes256.contents.hex()}")
    except Exception as e:
        print(f"[-] Error calculating AES keys: {e}")

if __name__ == "__main__":
    
    # Setup the argument parser
    parser = argparse.ArgumentParser(description="Calculate NTLM, AES-128, and AES-256 keys for Active Directory accounts.")
    parser.add_argument('-u', '--username', required=True, help="The target SAMAccountName (e.g., Fmoheb)")
    parser.add_argument('-p', '--password', required=True, help="The plaintext password")
    parser.add_argument('-d', '--domain', required=True, help="The Fully Qualified Domain Name (e.g., redteamrecipes.com)")
    
    # Parse the arguments from the CLI
    args = parser.parse_args()
    
    # Execute the function with the provided arguments
    generate_ad_hashes(args.password, args.domain, args.username)
