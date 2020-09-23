import os
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

print("installing pre-requisites")
os.system("pip install cryptography")
os.system("pip install fernet")
os.system('dir > "secret.key"')



print("press enter to continue...")
input()
os.system("cls")
key = Fernet.generate_key()
with open("secret.key", "wb") as key_file:
    key_file.write(key)
    
import main
