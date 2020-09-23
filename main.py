import sys
import os
import time
import secrets
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

backend = default_backend()
iterations = 100_000


def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
    """Derive a secret key from a given password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=iterations, backend=backend)
    return b64e(kdf.derive(password))

def password_encrypt(message: bytes, password: str, iterations: int = iterations) -> bytes:
    salt = secrets.token_bytes(16)
    key = _derive_key(password.encode(), salt, iterations)
    return b64e(
        b'%b%b%b' % (
            salt,
            iterations.to_bytes(4, 'big'),
            b64d(Fernet(key).encrypt(message)),
        )
    )

def password_decrypt(token: bytes, password: str) -> bytes:
    decoded = b64d(token)
    salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iter, 'big')
    key = _derive_key(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token)

def generate_key():
    """
    Generates a key and save it into a file
    """
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

    print("Done")

def load_key():
    """
    Load the previously generated key
    """
    return open("secret.key", "rb").read()

def encrypt_message(message):
    """
    Encrypts a message
    """
    key = load_key()
    encoded_message = message.encode()
    f = Fernet(key)
    encrypted_message = f.encrypt(encoded_message)

    return encrypted_message


def load_key():
    """
    Load the previously generated key
    """
    return open("secret.key", "rb").read()

def decrypt_message(encrypted_message):
    """
    Decrypts an encrypted message
    """
    key = load_key()
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)

    print(decrypted_message.decode())

def dummy():
    pass

def scroll(thing,dela=.04):
    for i in thing:
        sys.stdout.write(i)
        sys.stdout.flush()
        time.sleep(dela)
    print("")


def runencryptstr():
    scroll("ENTER INPUT TO ENCRYPT")
    message = input(">")
    message = encrypt_message(message)
    print(message)

def rundecryptstr():
    scroll("ENTER INPUT TO DECRYPT")
    message = input(">")
    message = decrypt_message(message.encode())
    print(message)




def main():
    scroll("Welcome to the encryptor")
    time.sleep(1)
    scroll("MODES:")
    time.sleep(1)
    scroll("1: FILE_ENC")
    scroll("2: FILE_DEC")
    scroll("3: STR_ENC")
    scroll("4: STR_DEC")
    scroll("5: GENERATE NEW KEY")

    inpcase = {1: dummy, 2: dummy, 3: runencryptstr, 4: rundecryptstr, 5: generate_key}
    while True:
        
        a = int(input(">>>"))
        func = inpcase.get(a, lambda:"not_exist")
        func()





    

#main()