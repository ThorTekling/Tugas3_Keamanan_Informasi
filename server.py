import socket
from main import decrypt_block, key_schedule, decrypt_rsa, generate_rsa_keys, hex_to_bin, bin_to_hex, unpad_message

server_ip = '127.0.0.1'
server_port = 5000

try:
    private_key, public_key = generate_rsa_keys()
    print("RSA keys generated successfully.")

    with open("server_public.pem", "wb") as pub_file:
        pub_file.write(public_key)
    print("Public key saved to server_public.pem.")
except Exception as e:
    print(f"Error generating or saving RSA keys: {e}")
    exit(1)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((server_ip, server_port))
server_socket.listen(1)
print(f"Server is listening on {server_ip}:{server_port}...")

try:
    client_socket, addr = server_socket.accept()
    print(f"Connection from {addr} established.")

    encrypted_des_key = client_socket.recv(256)  
    if not encrypted_des_key:
        raise ValueError("No encrypted DES key received.")
    des_key = decrypt_rsa(private_key, encrypted_des_key)  
    print(f"Decrypted DES Key (hex): {des_key.hex()}")

    des_keys = key_schedule(hex_to_bin(des_key.hex()))

    encrypted_message = client_socket.recv(1024).decode()
    if not encrypted_message:
        raise ValueError("No encrypted message received.")
    print(f"Encrypted message received (hex): {encrypted_message}")

    binary_encrypted_message = hex_to_bin(encrypted_message)  
    decrypted_binary_message = decrypt_block(binary_encrypted_message, des_keys)
    decrypted_message = unpad_message(bytes.fromhex(bin_to_hex(decrypted_binary_message)).decode())
    print(f"Decrypted message: {decrypted_message}")

except ValueError as e:
    print(f"ValueError: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")

finally:
    client_socket.close()
    server_socket.close()
    print("Connection closed.")
