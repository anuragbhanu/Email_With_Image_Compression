# Sender.py
import socket
from os import urandom, path
from PIL import Image
import io
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad

def load_public_key(filename):
    with open(filename, "rb") as f:
        return RSA.import_key(f.read())

def load_private_key(filename):
    with open(filename, "rb") as f:
        return RSA.import_key(f.read())

def compress_image_lossless(input_path):
    img = Image.open(input_path).convert("RGB")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return buffer.getvalue()

# ---- Configuration ----
HOST = 'localhost'
PORT = 12345
# -----------------------

# Get user input
message_input = input("Enter your message: ").strip()
image_path_input = input("Enter path to image file (leave empty to skip): ").strip()

# Load RSA keys
print("[🔑] Loading RSA keys...")
public_key = load_public_key("keys/Bob_public.pem")
private_key = load_private_key("keys/Alice_private.pem")

# Prepare message
message_bytes = message_input.encode('utf-8')
message_len = len(message_bytes)
print(f"[✉] Message size: {message_len} bytes")

# Optional image
if image_path_input and path.exists(image_path_input):
    print("[🖼] Compressing image...")
    image_data = compress_image_lossless(image_path_input)
    print(f"[🗜] Compressed image size: {len(image_data)} bytes")
else:
    image_data = b""
    if image_path_input:
        print(f"[⚠] Warning: File not found at '{image_path_input}'. Skipping image.")
    else:
        print("[ℹ] No image attached.")

# Format data: [4-byte message length][message][image]
msg_len_bytes = message_len.to_bytes(4, 'big')
full_payload = msg_len_bytes + message_bytes + image_data

# Encrypt payload with AES
aes_key = urandom(32)
iv = urandom(16)
cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
encrypted_data = cipher_aes.encrypt(pad(full_payload, AES.block_size))
print(f"[🔐] Encrypted payload size: {len(encrypted_data)} bytes")

# Sign original (plaintext) payload
hash_obj = SHA256.new(full_payload)
signature = pkcs1_15.new(private_key).sign(hash_obj)
print(f"[✍] Signature created: {len(signature)} bytes")

# Encrypt AES key using RSA
cipher_rsa = PKCS1_OAEP.new(public_key)
enc_aes_key = cipher_rsa.encrypt(aes_key)

# Send data
print("[📡] Sending data to server...")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(enc_aes_key)                               # 256 bytes
    s.sendall(iv)                                        # 16 bytes
    s.sendall(len(signature).to_bytes(4, 'big'))         # Signature length (4 bytes)
    s.sendall(signature)                                 # Signature
    s.sendall(len(encrypted_data).to_bytes(8, 'big'))    # Payload length (8 bytes)
    s.sendall(encrypted_data)                            # Encrypted payload

print("[✅] Message and image (if any) sent successfully.")
