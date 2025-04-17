import socket
from os import urandom, path
from PIL import Image
import io
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad

def compress_image(input_path):
    print("[📥] Opening image for compression...")
    img = Image.open(input_path)
    buffer = io.BytesIO()
    img.save(buffer, format="JPEG", quality=50)
    print("[✅] Image compressed.")
    return buffer.getvalue()

def load_public_key(filename): 
    with open(filename, "rb") as f:
        return RSA.import_key(f.read())

def load_private_key(filename):
    with open(filename, "rb") as f:
        return RSA.import_key(f.read())

HOST = 'localhost'
PORT = 12345  # Server port

# Load keys
public_key = load_public_key("keys/Bob_public.pem")
private_key = load_private_key("keys/Alice_private.pem")

# Original and compressed image sizes
original_size = path.getsize("logo_nitp.jpg")
print(f"[📦] Original Image Size: {original_size} bytes")

img_data = compress_image("logo_nitp.jpg")
compressed_size = len(img_data)
print(f"[🗜️] Compressed Image Size: {compressed_size} bytes")

# AES encryption
print("[🔒] Encrypting image with AES...")
aes_key = urandom(32)
iv = urandom(16)
cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
encrypted_img = cipher_aes.encrypt(pad(img_data, AES.block_size))
print(f"[🔐] AES encryption done. Encrypted size: {len(encrypted_img)} bytes")

# Signing
print("[✍️] Signing the image...")
h = SHA256.new(img_data)
signature = pkcs1_15.new(private_key).sign(h)
print(f"[✔️] Signature created. Size: {len(signature)} bytes")

# Encrypt AES key using RSA
cipher_rsa = PKCS1_OAEP.new(public_key)
enc_aes_key = cipher_rsa.encrypt(aes_key)
print(f"[📤] AES key encrypted. Size: {len(enc_aes_key)} bytes")

# Sending to server
print("[📡] Sending data to server...")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(enc_aes_key)
    s.sendall(iv)
    s.sendall(len(signature).to_bytes(4, 'big'))
    s.sendall(signature)
    s.sendall(len(encrypted_img).to_bytes(8, 'big'))
    s.sendall(encrypted_img)

print("[✅] Image sent to server successfully.")
