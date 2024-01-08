import socket
import random

def diffie_hellman():
    prime = 23
    generator = 5
    private_key = random.randint(2, 10)
    public_key = (generator ** private_key) % prime
    return prime, generator, public_key, private_key

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("129.206.5.206", 30300))

    prime, generator, public_key, private_key = diffie_hellman()
    s.send(str(public_key).encode())

    # Empfangen der Nachricht vom Server
    server_response = s.recv(1024).decode()

    # Extrahieren des Server-Public-Keys
    start_index = server_response.find("Server-Public-Key: ") + len("Server-Public-Key: ")
    end_index = server_response.find("\n", start_index)
    server_public_key = int(server_response[start_index:end_index])

    shared_key = (server_public_key ** private_key) % prime

    # Empfangen der Flag
    flag_data = s.recv(1024).decode()

    # Überprüfen, ob die Flag in den empfangenen Daten enthalten ist
    flag_start = flag_data.find("Flag: ")
    if flag_start != -1:
        flag = flag_data[flag_start + 6:]
        print("Flag:", flag)
    else:
        print("Flag nicht gefunden:", flag_data)

    s.close()

if __name__ == "__main__":
    main()
