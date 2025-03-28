#!/usr/bin/env python3
import socket
import struct
import sys
import zlib
import logging
import time

# --- Paramètres ---
BLOCK_SIZE = 10         # Nombre de fragments data par bloc pour RS
FRAGMENT_SIZE = 2       # Chaque fragment contient 2 octets utiles
RC4_KEY = b"MySecretKey"  # Même clé que le client

# Timeout et taille du buffer
BASE_TIMEOUT = 120
SOCKET_RCVBUF_SIZE = 1 << 20

# Configuration du logging (messages système en anglais)
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# --- Initialisation de GF(256) pour Reed-Solomon ---
GF_EXP = [0] * 512
GF_LOG = [0] * 256

def init_gf():
    # Initialisation du tableau exponentiel et logarithmique sur GF(256)
    x = 1
    for i in range(255):
        GF_EXP[i] = x
        GF_LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11d
    for i in range(255, 512):
        GF_EXP[i] = GF_EXP[i - 255]

init_gf()

def gf_mul(a, b):
    # Multiplication dans GF(256)
    if a == 0 or b == 0:
        return 0
    return GF_EXP[(GF_LOG[a] + GF_LOG[b]) % 255]

def gf_inv(a):
    # Calcul de l'inverse dans GF(256)
    if a == 0:
        raise ZeroDivisionError("GF(256) inverse of 0")
    return GF_EXP[255 - GF_LOG[a]]

# --- Fonctions RC4 ---
def rc4_init(key):
    # Initialisation de l'état RC4 avec la clé
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def rc4_stream(S, length):
    # Génération d'un flux de clés RC4 de la longueur demandée
    i = j = 0
    stream = []
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        stream.append(S[(S[i] + S[j]) % 256])
    return stream

def rc4_decrypt(encrypted, key, skip):
    # Déchiffrement RC4 après avoir sauté 'skip' octets
    S = rc4_init(key)
    _ = rc4_stream(S, skip)
    keystream = rc4_stream(S, len(encrypted))
    return bytes([b ^ k for b, k in zip(encrypted, keystream)])

def try_decrypt(encrypted, key, skip):
    # Essai de déchiffrement et extraction d'une valeur 32 bits
    decrypted = rc4_decrypt(encrypted, key, skip)
    val = struct.unpack(">I", decrypted)[0]
    return val, decrypted

def deduce_skip(encrypted, key, total_fragments, is_fec=False):
    # Déduire le nombre d'octets à sauter (skip) pour déchiffrer correctement le paquet
    for skip in range(256):
        val, _ = try_decrypt(encrypted, key, skip)
        if not is_fec:
            # Pour les paquets data, le numéro de séquence (16 bits de poids fort) doit être inférieur à total_fragments
            if (val >> 16) < total_fragments:
                return skip, val
        else:
            # Pour les paquets FEC, le numéro (issu du calcul client) doit être supérieur ou égal à total_fragments
            if (val >> 16) >= total_fragments:
                return skip, val
    return None, None

# --- Décodage RS (Élimination de Gauss sur GF(256)) ---
def rs_solve(equations, k):
    # equations est une liste de tuples (ligne, y) où ligne est une liste de k coefficients, y est la valeur
    n = len(equations)
    # Construction d'une copie de la matrice augmentée A|b
    A = [list(eq[0]) + [eq[1]] for eq in equations]
    for col in range(k):
        pivot_row = None
        for row in range(col, n):
            if A[row][col] != 0:
                pivot_row = row
                break
        if pivot_row is None:
            raise ValueError("Système singulier, pas assez d'équations indépendantes")
        A[col], A[pivot_row] = A[pivot_row], A[col]
        inv_val = gf_inv(A[col][col])
        for j in range(col, k+1):
            A[col][j] = gf_mul(A[col][j], inv_val)
        for row in range(n):
            if row != col and A[row][col] != 0:
                factor = A[row][col]
                for j in range(col, k+1):
                    A[row][j] ^= gf_mul(factor, A[col][j])
    solution = [A[i][k] for i in range(k)]
    return solution

def build_equations(block_data, fec_data, k_block, pos):
    # Construit les équations pour un bloc donné pour une position (0 = octet fort, 1 = octet faible)
    equations = []
    for i in range(k_block):
        if i in block_data:
            row = [0] * k_block
            row[i] = 1
            y = block_data[i][pos]
            equations.append((row, y))
    for j in fec_data:
        row = [GF_EXP[(i * (j+1)) % 255] for i in range(k_block)]
        y = fec_data[j][pos]
        equations.append((row, y))
    return equations

def rs_decode_block(block_data, fec_data, k_block):
    # Décodage RS d'un bloc en deux positions et récupération des fragments manquants
    eq = build_equations(block_data, fec_data, k_block, pos=0)
    if len(eq) < k_block:
        raise ValueError("Pas assez d'équations pour résoudre RS")
    sol0 = rs_solve(eq[:k_block], k_block)
    
    eq = build_equations(block_data, fec_data, k_block, pos=1)
    sol1 = rs_solve(eq[:k_block], k_block)
    recovered = {}
    for i in range(k_block):
        if i not in block_data:
            recovered[i] = bytes([sol0[i], sol1[i]])
    return recovered

# --- Réception et réassemblage du dump ---
def run_receiver(host, port, output_file, base_timeout=120):
    # Création du socket UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((host, port))
    except Exception as e:
        logging.error(f"Error binding to port {port} : {e}")
        sys.exit(1)
    sock.settimeout(5)
    logging.info(f"Listening on {host}:{port} ...")
    
    header_received = False
    total_fragments = 0
    total_size = 0
    data_packets = {}   # Dictionnaire : numéro global -> 2 octets
    fec_packets = {}    # Dictionnaire : (index bloc, index dans bloc) -> 2 octets
    start_time = time.time()
    sender_addr = None

    logging.info("Waiting for header...")
    while True:
        try:
            data, addr = sock.recvfrom(1024)
        except socket.timeout:
            if time.time() - start_time > base_timeout:
                logging.warning("Global timeout reached, stopping reception.")
                break
            continue

        if sender_addr is None:
            sender_addr = addr

        if len(data) < 48:
            continue

        # Extraction du payload dans le champ Transmit Timestamp (8 octets)
        payload = data[40:48]
        if not header_received:
            total_fragments = struct.unpack(">I", payload[:4])[0]
            total_size = struct.unpack(">I", payload[4:8])[0]
            header_received = True
            logging.info(f"Header received: {total_fragments} fragments, {total_size} compressed bytes.")
            continue

        encrypted = payload[4:8]
        skip, val = deduce_skip(encrypted, RC4_KEY, total_fragments, is_fec=False)
        if skip is not None:
            seq = val >> 16
            frag = val & 0xFFFF
            data_packets[seq] = frag.to_bytes(2, 'big')
            # Mise à jour de la progression de la réception
            progress = (len(data_packets) / total_fragments) * 100
            logging.info(f"Progress: {len(data_packets)}/{total_fragments} fragments received ({progress:.1f}%)")
        else:
            skip, val = deduce_skip(encrypted, RC4_KEY, total_fragments, is_fec=True)
            if skip is not None:
                fec_seq = val
                seq_high = fec_seq >> 16
                block_index = seq_high // BLOCK_SIZE
                idx_in_block = seq_high % BLOCK_SIZE
                fec_packets[(block_index, idx_in_block)] = (fec_seq & 0xFFFF).to_bytes(2, 'big')
                logging.info(f"FEC packet received: block {block_index}, index {idx_in_block}")
            else:
                logging.warning("Could not deduce skip for a packet; skipping it.")

        if len(data_packets) == total_fragments:
            logging.info("All data packets have been received.")
            break

    sock.close()
    logging.info(f"Reception finished: {len(data_packets)}/{total_fragments} data packets received.")

    # Réassemblage du dump par blocs
    num_blocks = (total_fragments + BLOCK_SIZE - 1) // BLOCK_SIZE
    reconstructed = bytearray(total_fragments * FRAGMENT_SIZE)
    
    logging.info("Reconstructing dump ...")
    # Utilisation d'une barre de progression visible via stdout
    bar_length = 30
    for b in range(num_blocks):
        block_start = b * BLOCK_SIZE
        k_block = min(BLOCK_SIZE, total_fragments - block_start)
        block_data_pos0 = {}
        block_data_pos1 = {}
        for i in range(k_block):
            seq = block_start + i
            if seq in data_packets:
                val = data_packets[seq]
                block_data_pos0[i] = val[0:1]
                block_data_pos1[i] = val[1:2]
        block_fec_pos0 = {}
        block_fec_pos1 = {}
        for j in range(BLOCK_SIZE):
            key = (b, j)
            if key in fec_packets:
                val = fec_packets[key]
                block_fec_pos0[j] = val[0:1]
                block_fec_pos1[j] = val[1:2]
        if len(block_data_pos0) < k_block:
            try:
                recovered0 = rs_decode_block(block_data_pos0, block_fec_pos0, k_block)
                recovered1 = rs_decode_block(block_data_pos1, block_fec_pos1, k_block)
                for i in range(k_block):
                    if i not in block_data_pos0:
                        d0 = recovered0[i][0]
                        d1 = recovered1[i][0]
                        data_packets[block_start + i] = bytes([d0, d1])
                        logging.info(f"Missing fragment {block_start + i} recovered via RS.")
            except Exception as e:
                logging.error(f"RS decoding failed for block {b}: {e}")
        for i in range(k_block):
            seq = block_start + i
            frag = data_packets.get(seq, b'\x00\x00')
            reconstructed[seq*2:seq*2+2] = frag
        
        # Affichage de la barre de progression mise à jour
        progress = ((b + 1) / num_blocks) * 100
        filled_length = int(bar_length * (b + 1) / num_blocks)
        bar = "=" * filled_length + "-" * (bar_length - filled_length)
        sys.stdout.write(f"\r[Reconstruction] [{bar}] {progress:5.1f}%")
        sys.stdout.flush()
    sys.stdout.write("\n")
    
    reconstructed = reconstructed[:total_size]
    try:
        dump_data = zlib.decompress(reconstructed)
        with open(output_file, "wb") as f:
            f.write(dump_data)
        logging.info(f"Dump decompressed and saved to '{output_file}'.")
    except Exception as e:
        logging.error(f"Decompression failed: {e}")
        with open(output_file + ".compressed", "wb") as f:
            f.write(reconstructed)
        logging.info(f"Compressed dump saved to '{output_file}.compressed'.")
    
    # Envoi de feedback pour les fragments manquants, le cas échéant
    missing_fragments = [i for i in range(total_fragments) if i not in data_packets]
    if missing_fragments and sender_addr:
        logging.info(f"Missing fragments after RS: {missing_fragments}")
        feedback = struct.pack(">I", len(missing_fragments))
        for seq in missing_fragments:
            feedback += struct.pack(">I", seq)
        feedback_port = 124
        fb_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            fb_sock.sendto(feedback, (sender_addr[0], feedback_port))
            logging.info(f"Feedback sent to {sender_addr[0]}:{feedback_port}")
        except Exception as e:
            logging.error(f"Error sending feedback: {e}")
        finally:
            fb_sock.close()

if __name__ == '__main__':
    host = "0.0.0.0"      # Écoute sur toutes les interfaces
    port = 123            # Port UDP simulant le trafic NTP (attention: on Linux this port is reserved and may require root privileges)
    output_file = "dump_memory.bin"
    run_receiver(host, port, output_file)
