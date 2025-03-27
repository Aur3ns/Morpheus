#!/usr/bin/env python3
import socket
import struct
import sys
import zlib
import logging
import time

# Configuration du logging (system messages in English)
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def print_progress(current, total):
    """Affiche une barre de progression dans la console."""
    percent = int((current / total) * 100) if total > 0 else 0
    bar_length = 20
    filled_length = int(bar_length * percent // 100)
    bar = '=' * filled_length + '-' * (bar_length - filled_length)
    print(f"\r[Reassembly] [{bar}] {percent}% ({current}/{total})", end='', flush=True)

def run_receiver(host, port, output_file, base_timeout=120):
    """
    Écoute les paquets UDP au format NTP sur le port spécifié.
    Le premier paquet (header) contient :
      - 4 octets : total de fragments (big-endian)
      - 4 octets : total size of compressed stream (big-endian)
    Chaque paquet suivant contient :
      - 4 octets : sequence number (big-endian)
      - 4 octets : fragment of compressed data
    Après réception, le flux est reassemblé, decompressed and saved to output_file.
    À la fin, le récepteur envoie un feedback indiquant les fragments manquants.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.settimeout(5)  # Timeout per packet
    logging.info(f"Listening on {host}:{port} (base timeout: {base_timeout}s)")

    header_received = False
    total_fragments = 0
    total_size = 0
    fragments = {}
    start_time = time.time()
    dynamic_timeout = base_timeout  # Default timeout if no header is received
    first_sender_addr = None  # Adresse de l'expéditeur

    while True:
        try:
            data, addr = sock.recvfrom(1024)
        except socket.timeout:
            if time.time() - start_time > dynamic_timeout:
                logging.warning("Global timeout reached, stopping reception.")
                break
            else:
                continue

        # Sauvegarder l'adresse du premier expéditeur
        if first_sender_addr is None:
            first_sender_addr = addr

        if len(data) < 48:
            continue  # Ignorer les paquets mal formés

        # Extraction du champ "transmit timestamp" (octets 40 à 47)
        payload = data[40:48]

        if not header_received:
            total_fragments = struct.unpack(">I", payload[:4])[0]
            total_size = struct.unpack(">I", payload[4:8])[0]
            header_received = True
            # Ajuster le timeout en fonction d'un taux minimal de fragments attendu
            min_rate = 1000  # fragments per second
            estimated_time = total_fragments / min_rate
            dynamic_timeout = int(estimated_time * 1.5)
            logging.info(f"Header received: {total_fragments} fragments, {total_size} compressed bytes.")
            logging.info(f"Timeout adjusted to {dynamic_timeout} seconds.")
        else:
            seq = struct.unpack(">I", payload[:4])[0]
            fragment = payload[4:8]
            if seq not in fragments:
                fragments[seq] = fragment
                print_progress(len(fragments), total_fragments)

            if len(fragments) == total_fragments:
                logging.info("\nAll fragments received.")
                break

        if time.time() - start_time > dynamic_timeout:
            logging.warning("Global timeout exceeded, ending reception.")
            break

    sock.close()
    print()  # Saut de ligne après la barre de progression

    if not header_received:
        logging.error("No header received. Exiting.")
        sys.exit(1)

    if len(fragments) != total_fragments:
        logging.warning(f"Expected fragments: {total_fragments} | Received: {len(fragments)}")
        logging.warning("The dump may be incomplete.")

    # Réassembler le flux compressé dans l'ordre
    compressed_data = bytearray()
    for i in range(total_fragments):
        fragment = fragments.get(i, b'\0'*4)  # Remplir avec des zéros si fragment manquant
        compressed_data.extend(fragment)
    compressed_data = compressed_data[:total_size]  # Tronquer à la taille attendue

    # Décompression et sauvegarde du dump
    try:
        dump_data = zlib.decompress(compressed_data)
        with open(output_file, "wb") as f:
            f.write(dump_data)
        logging.info(f"Dump decompressed and saved to {output_file}.")
    except Exception as e:
        logging.error(f"Decompression failed: {e}")
        with open(output_file + ".compressed", "wb") as f:
            f.write(compressed_data)
        logging.info(f"Compressed dump saved to {output_file}.compressed.")

    # Envoi du feedback avec les fragments manquants
    missing_fragments = [i for i in range(total_fragments) if i not in fragments]
    if missing_fragments and first_sender_addr:
        logging.info(f"Missing fragments: {missing_fragments}")
        feedback = struct.pack(">I", len(missing_fragments))
        for seq in missing_fragments:
            feedback += struct.pack(">I", seq)
        feedback_port = 124  # Port de feedback
        feedback_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            feedback_sock.sendto(feedback, (first_sender_addr[0], feedback_port))
            logging.info(f"Feedback sent to {first_sender_addr[0]}:{feedback_port}")
        except Exception as e:
            logging.error(f"Feedback sending error: {e}")
        finally:
            feedback_sock.close()

if __name__ == '__main__':
    host = "0.0.0.0"   # Écoute sur toutes les interfaces
    port = 123         # Port UDP (simulating NTP traffic)
    output_file = "dump_memory.bin"
    run_receiver(host, port, output_file)
