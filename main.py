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
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

    print("Done")

def load_key():
    return open("secret.key", "rb").read()

def encrypt_message(message):
    key = load_key()
    encoded_message = message.encode()
    f = Fernet(key)
    encrypted_message = f.encrypt(encoded_message)

    return encrypted_message



def decrypt_message(encrypted_message):
    key = load_key()
    f = Fernet(key)
    decrypted_message = f.decrypt(str.encode(encrypted_message))
    return decrypted_message


def encrypt_file(filename):
    key = load_key()
    l = Fernet(key)

    input_file = filename
    output_file = "enc_" + filename

    with open(input_file, 'rb') as f:
        data = f.read()  # Read the bytes of the input file
    encrypted = l.encrypt(data)

    with open(output_file, 'wb') as f:
        f.write(encrypted)  # Write the encrypted bytes to the output file

    print("DONE")


def decrypt_file(filename):
    key = load_key()
    l = Fernet(key)

    with open(filename, "rb") as file:
        encrypted_data = file.read()

    decrypted_data = l.decrypt(encrypted_data)
    with open("dec_" + filename, "wb") as file:
        file.write(decrypted_data)

    print("DONE")

    

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
    message = decrypt_message(message)
    print(message)

def runencryptfile():
    scroll("ENTER FILENAME TO ENCRYPT")
    filename = input(">")
    encrypt_file(filename)

def rundecryptfile():
    scroll("ENTER FILENAME TO DECRYPT")
    filename = input(">")
    decrypt_file(filename)

def main():
    os.system("cls")
    scroll("**ENCRYPTOR**")
    scroll("MAKE SURE A KEY FILE IS PRESENT IN THE WORKING DIRECTORY")
    scroll("IF A NEW KEY IS GENERATED THE CURRENT KEY WILL BE OVERWRITTEN")
    print("***********************************")
    scroll("MODES:")
    scroll("1: FILE_ENC")
    scroll("2: FILE_DEC")
    scroll("3: STR_ENC")
    scroll("4: STR_DEC")
    scroll("5: GENERATE NEW KEY")

    inpcase = {1: runencryptfile, 2: rundecryptfile, 3: runencryptstr, 4: rundecryptstr, 5: generate_key}
    while True:
        
        a = int(input(">>>"))
        func = inpcase.get(a, lambda:"not_exist")
        func()


main()