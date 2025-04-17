import socket

HOST = 'localhost'
SENDER_PORT = 12345
RECEIVER_PORT = 12346

def main():
    print("[🖥️] Secure Image Transfer Server Starting...")

    # Step 1: Connect to Receiver
    print("[📥] Waiting for receiver to connect...")
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    recv_sock.bind((HOST, RECEIVER_PORT))
    recv_sock.listen(1)
    conn_receiver, addr_r = recv_sock.accept()
    print(f"[✅] Receiver connected from {addr_r}")
    recv_sock.close()

    # Step 2: Connect to Sender
    print("[📤] Waiting for sender to connect...")
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    send_sock.bind((HOST, SENDER_PORT))
    send_sock.listen(1)
    conn_sender, addr_s = send_sock.accept()
    print(f"[✅] Sender connected from {addr_s}")
    send_sock.close()

    # Step 3: Relay Data
    print("[🔄] Relaying data from sender to receiver...")
    data = b''
    while True:
        chunk = conn_sender.recv(4096)
        if not chunk:
            break
        data += chunk
    conn_sender.close()

    conn_receiver.sendall(data)
    conn_receiver.close()

    print("[🏁] Data relay complete. Transfer successful.")

if __name__ == "__main__":
    main()
