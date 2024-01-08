from hashlib import sha1
from binascii import hexlify
import dpkt

# Lade den Netzwerkverkehr aus der dump.pcap-Datei
pcap_file = 'dump.pcap'
try:
    with open(pcap_file, 'rb') as file:
        pcap = dpkt.pcap.Reader(file)

    # Nehme an, dass 'password' das abgefangene Passwort-Hash ist
    password_hash = b'2c735b9b4b3a7a6e5bc8e6b6a540980106b26b99'

    # Konvertiere den Hex-Hash zurück in Binärdaten
    password_binary = hexlify(password_hash).decode('utf-8')

    # Durchsuche den Netzwerkverkehr nach MySQL-Anfragen
    for ts, pkt in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(pkt)
            ip = eth.data
            tcp = ip.data
            if tcp.dport == 3306 and len(tcp.data) > 4:
                # Extrahiere den MySQL-Authentifizierungspaket-Teil
                mysql_data = tcp.data[4:]
                
                # Extrahiere den Salt-Wert aus dem MySQL-Authentifizierungspaket
                salt = mysql_data[15:23].decode('utf-8')
                
                # Hier wird das Originalpasswort mit Salz erzeugt
                original_password = sha1((salt + 'password').encode('utf-8')).hexdigest()
                
                # Überprüfe, ob das Originalpasswort mit dem abgefangenen Hash übereinstimmt
                if original_password == password_binary:
                    print("Passwort gefunden:", original_password)
                    break  # Beende die Schleife, wenn das Passwort gefunden wurde
        except Exception as e:
            print(f"Error in packet processing: {e}")
except Exception as e:
    print(f"Error opening pcap file: {e}")

print("Passwort nicht gefunden.")
