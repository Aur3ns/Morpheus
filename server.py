#!/usr/bin/env python3
import socket
import struct
import sys
import zlib
import logging
import time

# Configuration du logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def print_progress(current, total):
    """Affiche une barre de progression dans la console."""
    percent = int((current / total) * 100) if total > 0 else 0
    bar_length = 20
    filled_length = int(bar_length * percent // 100)
    bar = '=' * filled_length + '-' * (bar_length - filled_length)
    print(f"\r[Reconstitution] [{bar}] {percent}% ({current}/{total})", end='')

def run_receiver(host, port, output_file, timeout=30):
    """
    Attend des paquets UDP (format NTP) sur le port donné.
    Le premier paquet (header) contient :
      - 4 octets : nombre total de fragments (big-endian)
      - 4 octets : taille totale du flux compressé (big-endian)
    Chaque paquet suivant contient :
      - 4 octets : numéro de séquence (big-endian)
      - 4 octets : fragment de données compressées
    Une fois tous les fragments reçus ou le timeout expiré, le flux est reconstitué et décompressé.
    Le dump final est sauvegardé dans output_file.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.settimeout(5)  # Timeout de 5 secondes pour chaque réception
    logging.info(f"En écoute sur {host}:{port} (timeout global: {timeout} s)")

    header_received = False
    total_fragments = 0
    total_size = 0
    fragments = {}
    start_time = time.time()

    while True:
        try:
            data, addr = sock.recvfrom(1024)  # On attend des paquets NTP
        except socket.timeout:
            if time.time() - start_time > timeout:
                logging.warning("Timeout global atteint, arrêt de la réception.")
                break
            else:
                logging.debug("Timeout sur la réception d'un paquet, réessai...")
                continue

        if len(data) < 48:
            logging.debug("Paquet trop court, ignoré.")
            continue

        # Extraction du champ 'transmit timestamp' (octets 40 à 47)
        payload = data[40:48]

        if not header_received:
            # Le premier paquet est le header
            total_fragments = struct.unpack(">I", payload[:4])[0]
            total_size = struct.unpack(">I", payload[4:8])[0]
            header_received = True
            logging.info(f"Header reçu : {total_fragments} fragments, {total_size} octets compressés.")
        else:
            # Extraction du numéro de séquence et du fragment
            seq = struct.unpack(">I", payload[:4])[0]
            fragment = payload[4:8]
            if seq not in fragments:
                fragments[seq] = fragment
                current = len(fragments)
                print_progress(current, total_fragments)
            else:
                logging.debug(f"Fragment {seq} déjà reçu, ignoré.")

            # Si tous les fragments sont reçus, on arrête la réception
            if len(fragments) == total_fragments:
                logging.info("\nTous les fragments ont été reçus.")
                break

        # Vérifier le délai global
        if time.time() - start_time > timeout:
            logging.warning("Le délai global est dépassé, fin de la réception.")
            break

    sock.close()
    print()  # Pour passer à la ligne après la barre de progression

    if not header_received:
        logging.error("Aucun header reçu. Arrêt du programme.")
        sys.exit(1)

    if len(fragments) != total_fragments:
        logging.warning(f"Fragments attendus: {total_fragments} | Fragments reçus: {len(fragments)}")
        logging.warning("Le dump pourra être incomplet.")

    # Reconstitution du flux compressé en respectant l'ordre des fragments
    compressed_data = bytearray()
    for i in range(total_fragments):
        fragment = fragments.get(i, b'\0'*4)
        compressed_data.extend(fragment)
    # Tronquer le flux à la taille attendue
    compressed_data = compressed_data[:total_size]

    # Décompression
    try:
        dump_data = zlib.decompress(compressed_data)
        with open(output_file, "wb") as f:
            f.write(dump_data)
        logging.info(f"Dump décompressé et sauvegardé dans {output_file}.")
    except Exception as e:
        logging.error(f"La décompression a échoué : {e}")
        with open(output_file + ".compressed", "wb") as f:
            f.write(compressed_data)
        logging.info(f"Dump compressé sauvegardé dans {output_file}.compressed.")

if __name__ == '__main__':
    host = "0.0.0.0"   # Écoute sur toutes les interfaces
    port = 123         # Port UDP d'écoute (comme trafic NTP)
    output_file = "dump_memory.bin"  # Fichier de sortie pour le dump
    run_receiver(host, port, output_file)
