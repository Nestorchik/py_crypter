# A&AP Programmer Group, NStor
# py_crypter.py
# AES-256-GCM + PBKDF2-HMAC-SHA256
# Использование:
#   uv run py_crypter.py input.py output.enc --pass "ключ"
# Если --pass опущен, скрипт запросит пароль интерактивно (без эха).

import sys, os, argparse, getpass
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

MAGIC = b'AESG'     # 4 bytes magic
VERSION = b'\x01'   # 1 byte version
SALT_LEN = 16       # bytes
NONCE_LEN = 12      # bytes (recommended for GCM)
TAG_LEN = 16        # bytes (GCM tag)
PBKDF2_ITERS = 200_000
KEY_LEN = 32        # 32 bytes = AES-256

def derive_key(password: bytes, salt: bytes, iters=PBKDF2_ITERS, dklen=KEY_LEN):
    return PBKDF2(password, salt, dklen, count=iters, hmac_hash_module=None)

def encrypt_file(in_path: str, out_path: str, password: bytes):
    with open(in_path, 'rb') as f:
        plaintext = f.read()

    salt = get_random_bytes(SALT_LEN)
    key = derive_key(password, salt)
    nonce = get_random_bytes(NONCE_LEN)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    with open(out_path, 'wb') as f:
        f.write(MAGIC)
        f.write(VERSION)
        f.write(salt)
        f.write(nonce)
        f.write(tag)
        f.write(ciphertext)

    return True

def main():
    ap = argparse.ArgumentParser(description='Encrypt Python file with AES-256-GCM')
    ap.add_argument('input', help='input .py file')
    ap.add_argument('output', help='output encrypted file (.enc)')
    ap.add_argument('--pass', dest='password', help='password (insecure on CLI). If omitted, will prompt.')
    args = ap.parse_args()

    if not os.path.isfile(args.input):
        print('Input file not found:', args.input)
        sys.exit(2)

    if args.password:
        pwd = args.password.encode('utf-8')
    else:
        pwd = getpass.getpass('Password: ').encode('utf-8')

    try:
        encrypt_file(args.input, args.output, pwd)
    except Exception as e:
        print('Encryption failed:', e)
        sys.exit(1)

    print('Encrypted ->', args.output)

if __name__ == '__main__':
    main()
