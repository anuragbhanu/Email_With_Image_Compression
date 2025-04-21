# Receiver.py
import socket
from PIL import Image
import io
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad

def load_private_key(filename):
    with open(filename, "rb") as f:
        return RSA.import_key(f.read())

def load_public_key(filename):
    with open(filename, "rb") as f:
        return RSA.import_key(f.read())

def save_image_from_bytes(byte_data, output_path="received_image.png"):
    buffer = io.BytesIO(byte_data)
    img = Image.open(buffer)
    img.save(output_path, format="PNG")
    print(f"[💾] Image saved as '{output_path}'")

HOST = 'localhost'
PORT = 12346

print("[🔌] Connecting to server...")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("[🔗] Connected.")

    private_key = load_private_key("keys/Bob_private.pem")
    sender_pub_key = load_public_key("keys/Alice_public.pem")

    encrypted_key = s.recv(256)
    aes_key = PKCS1_OAEP.new(private_key).decrypt(encrypted_key)
    print("[🔓] AES key decrypted.")

    iv = s.recv(16)

    sig_len = int.from_bytes(s.recv(4), 'big')
    signature = s.recv(sig_len)

    payload_len = int.from_bytes(s.recv(8), 'big')
    encrypted_payload = b""
    while len(encrypted_payload) < payload_len:
        part = s.recv(2048)
        if not part:
            break
        encrypted_payload += part

    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    full_payload = unpad(cipher_aes.decrypt(encrypted_payload), AES.block_size)
    print(f"[✅] Payload decrypted. Total size: {len(full_payload)} bytes")

    # Verify signature
    hash_obj = SHA256.new(full_payload)
    try:
        pkcs1_15.new(sender_pub_key).verify(hash_obj, signature)
        print("[✔] Signature verified successfully.")
    except (ValueError, TypeError):
        print("[❌] Signature verification failed.")

    # Parse payload: [4-byte msg len][msg][img]
    msg_len = int.from_bytes(full_payload[:4], 'big')
    message = full_payload[4:4+msg_len].decode('utf-8')
    image_data = full_payload[4+msg_len:]

    print(f"[📨] Message received:\n\"{message}\"")

    if image_data:
        save_image_from_bytes(image_data)
    else:
        print("[ℹ] No image attached.")
