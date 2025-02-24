#!/usr/bin/env python3
import socket

def get_local_ip():
    """Récupère l'adresse IP locale de la machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Se connecter à une adresse publique pour obtenir l'IP locale
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def run_server(host, port, output_file):
    # Création d'un socket TCP
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    
    # Affichage de l'adresse IP et du port sur lesquels le serveur écoute
    local_ip = get_local_ip()
    print(f"[Server] Démarrage du serveur sur {local_ip}:{port} (écoute sur toutes les interfaces)")

    # Acceptation d'une connexion entrante
    conn, addr = server_socket.accept()
    print(f"[Server] Connexion établie avec {addr}.")

    # Ouverture du fichier de sortie en mode binaire
    with open(output_file, "wb") as f:
        while True:
            # Lecture des données par blocs (ici 4096 octets)
            data = conn.recv(4096)
            if not data:
                break
            f.write(data)

    print(f"[Server] Données enregistrées dans {output_file}.")
    conn.close()
    server_socket.close()

if __name__ == '__main__':
    # Paramètres du serveur
    host = "0.0.0.0"  # Écoute sur toutes les interfaces
    port = 8080       # Port d'écoute (à adapter selon vos besoins)
    output_file = "dump_memory.bin"  # Nom du fichier de sortie

    run_server(host, port, output_file)
