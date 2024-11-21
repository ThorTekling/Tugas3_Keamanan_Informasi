import socket

pka_ip = '127.0.0.1'
pka_port = 6000

with open("server_public.pem", "rb") as pub_file:
    server_public_key = pub_file.read()

pka_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
pka_socket.bind((pka_ip, pka_port))
pka_socket.listen(5)
print(f"PKA Server is running on {pka_ip}:{pka_port}...")

try:
    while True:
        client_socket, addr = pka_socket.accept()
        print(f"Connection from {addr} established.")

        client_socket.send(server_public_key)
        print(f"Sent public key to {addr}")

        client_socket.close()

except Exception as e:
    print(f"An error occurred in PKA server: {e}")

finally:
    pka_socket.close()
    print("PKA Server shut down.")
