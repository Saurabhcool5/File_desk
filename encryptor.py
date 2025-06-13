# encryptor.py
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import os

def pad(data):
    block_size = 16
    padding = block_size - len(data) % block_size
    return data + bytes([padding]) * padding

def encrypt_file(file_path):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)

    with open(file_path, 'rb') as f:
        data = f.read()

    padded_data = pad(data)
    encrypted_data = cipher.encrypt(padded_data)

    encrypted_path = file_path + "_encrypted"
    with open(encrypted_path, 'wb') as ef:
        ef.write(encrypted_data)

    # Return both path and base64 key for web decryption
    return encrypted_path, base64.b64encode(key).decode()
