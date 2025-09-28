# A&AP Programmer Group, NStor
# py_loader.py
# Использование:
#   uv run py_loader.py program.enc --pass "ключ"
# или:
#   python py_loader.py program.enc
# Если --pass опущен, скрипт запросит пароль интерактивно (без эха).
# "ключ" - практически безопасно использовать несколько тысяч символов (например 4096+), можно с пробелами, но тогда заключите строку ключа в скобки

import sys, os, argparse, getpass
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

MAGIC = b'AESG'
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
PBKDF2_ITERS = 200_000
KEY_LEN = 32

def derive_key(password: bytes, salt: bytes, iters=PBKDF2_ITERS, dklen=KEY_LEN):
    return PBKDF2(password, salt, dklen, count=iters, hmac_hash_module=None)

def load_and_execute(enc_path: str, password: bytes):
    with open(enc_path, 'rb') as f:
        header = f.read(4)
        if header != MAGIC:
            raise ValueError('Bad file format or not an AESG file')
        ver = f.read(1)
        # read salt/nonce/tag
        salt = f.read(SALT_LEN)
        nonce = f.read(NONCE_LEN)
        tag = f.read(TAG_LEN)
        ciphertext = f.read()
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as e:
        raise ValueError('Decryption failed (wrong password or corrupted data)') from e

    # Execute in-memory, do not write plaintext to disk
    # supply filename for stack traces as original encoded file name
    code_obj = compile(plaintext, enc_path, 'exec')
    globals_dict = {'__name__': '__main__'}
    exec(code_obj, globals_dict)

def main():
    ap = argparse.ArgumentParser(description='AES-256-GCM loader: decrypt in memory and exec')
    ap.add_argument('encfile', help='encrypted file (*.enc)')
    ap.add_argument('--pass', dest='password', help='password (insecure on CLI). If omitted, will prompt.')
    args = ap.parse_args()

    if not os.path.isfile(args.encfile):
        print('Encrypted file not found:', args.encfile)
        sys.exit(2)

    if args.password:
        pwd = args.password.encode('utf-8')
    else:
        pwd = getpass.getpass('Password: ').encode('utf-8')

    try:
        load_and_execute(args.encfile, pwd)
    except Exception as e:
        print('ERROR:', e)
        sys.exit(1)

if __name__ == '__main__':
    main()
