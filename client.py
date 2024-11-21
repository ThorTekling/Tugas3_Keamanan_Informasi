import socket
from main import encrypt_block, key_schedule, pad_message, encrypt_rsa, bin_to_hex, hex_to_bin
from Crypto.Random import get_random_bytes


def fetch_public_key(pka_ip, pka_port):
    """Fetch the server's public key from the Public Key Authority."""
    try:
        pka_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        pka_socket.connect((pka_ip, pka_port))
        public_key = pka_socket.recv(1024)
        if not public_key:
            raise ValueError("No public key received from PKA.")
        print("Public key fetched from PKA.")
        return public_key
    except Exception as e:
        print(f"Failed to fetch public key from PKA: {e}")
        exit(1)
    finally:
        pka_socket.close()


server_ip = '127.0.0.1'
server_port = 5000
pka_ip = '127.0.0.1'
pka_port = 6000

try:
    server_public_key = fetch_public_key(pka_ip, pka_port)

    des_key = get_random_bytes(8)  
    des_keys = key_schedule(hex_to_bin(des_key.hex()))  
    print(f"Generated DES Key (hex): {des_key.hex()}")

    encrypted_des_key = encrypt_rsa(server_public_key, des_key)
    print(f"Encrypted DES Key (hex): {encrypted_des_key.hex()}")

    plaintext = "Test message!"
    padded_plaintext = pad_message(plaintext).encode('utf-8')  
    binary_plaintext = ''.join(format(byte, '08b') for byte in padded_plaintext)  

    print(f"Padded binary plaintext: {binary_plaintext}, Length: {len(binary_plaintext)} bits")

    if len(binary_plaintext) % 64 != 0:
        raise ValueError("Binary plaintext length is not a multiple of 64 bits.")

    encrypted_message = ''
    for i in range(0, len(binary_plaintext), 64):
        block = binary_plaintext[i:i + 64]
        print(f"Encrypting block: {block}, Length: {len(block)} bits")
        encrypted_message += encrypt_block(block, des_keys)

    encrypted_message_hex = bin_to_hex(encrypted_message)
    print(f"Encrypted message (hex): {encrypted_message_hex}")

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))
    client_socket.send(encrypted_des_key)
    client_socket.send(encrypted_message_hex.encode())
    print("Encrypted DES key and message sent to the server.")

except ValueError as e:
    print(f"ValueError: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")

finally:
    if 'client_socket' in locals() and client_socket:
        client_socket.close()
        print("Client socket closed.")
