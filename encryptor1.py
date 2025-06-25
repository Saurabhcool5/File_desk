from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import os

def encrypt_file(file_path):
    key = get_random_bytes(32)
    
    nonce = get_random_bytes(16)
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    with open(file_path, 'rb') as f:
        data = f.read()

    encrypted_data, tag = cipher.encrypt_and_digest(data)

    encrypted_path = file_path + "_encrypted"
    with open(encrypted_path, 'wb') as ef:
        ef.write(nonce)       
        ef.write(tag)         
        ef.write(encrypted_data)  

    return encrypted_path, base64.b64encode(key).decode()