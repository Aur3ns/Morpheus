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

# Timeout et buffer
BASE_TIMEOUT = 120
SOCKET_RCVBUF_SIZE = 1 << 20

# --- GF(256) pour Reed-Solomon ---
GF_EXP = [0] * 512
GF_LOG = [0] * 256

def init_gf():
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
    if a == 0 or b == 0:
        return 0
    return GF_EXP[(GF_LOG[a] + GF_LOG[b]) % 255]

def gf_inv(a):
    if a == 0:
        raise ZeroDivisionError("GF(256) inverse of 0")
    return GF_EXP[255 - GF_LOG[a]]

# --- RC4 fonctions ---
def rc4_init(key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def rc4_stream(S, length):
    i = j = 0
    stream = []
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        stream.append(S[(S[i] + S[j]) % 256])
    return stream

def rc4_decrypt(encrypted, key, skip):
    S = rc4_init(key)
    _ = rc4_stream(S, skip)
    keystream = rc4_stream(S, len(encrypted))
    return bytes([b ^ k for b, k in zip(encrypted, keystream)])

def try_decrypt(encrypted, key, skip):
    decrypted = rc4_decrypt(encrypted, key, skip)
    val = struct.unpack(">I", decrypted)[0]
    return val, decrypted

def deduce_skip(encrypted, key, total_fragments, is_fec=False):
    for skip in range(256):
        val, _ = try_decrypt(encrypted, key, skip)
        if is_fec:
            if val & 0x80000000:
                return skip, val
        else:
            if val < total_fragments:
                return skip, val
    return None, None

# --- RS Decoding (Gaussian elimination sur GF(256)) ---
def rs_solve(equations, k):
    # equations: list of (row, y) where row is list of k coefficients, y is value.
    n = len(equations)
    # Construire une copie de la matrice augmentée A|b
    A = [list(eq[0]) + [eq[1]] for eq in equations]
    # Elimination de Gauss
    for col in range(k):
        # Chercher le pivot dans la colonne col
        pivot_row = None
        for row in range(col, n):
            if A[row][col] != 0:
                pivot_row = row
                break
        if pivot_row is None:
            raise ValueError("Système singulier, pas assez d'équations indépendantes")
        # Échanger pivot_row et col
        A[col], A[pivot_row] = A[pivot_row], A[col]
        # Normaliser la ligne pivot
        inv_val = gf_inv(A[col][col])
        for j in range(col, k+1):
            A[col][j] = gf_mul(A[col][j], inv_val)
        # Eliminer la colonne col dans les autres lignes
        for row in range(n):
            if row != col and A[row][col] != 0:
                factor = A[row][col]
                for j in range(col, k+1):
                    A[row][j] ^= gf_mul(factor, A[col][j])
    # La solution est dans les colonnes k (dernier élément de chaque ligne)
    solution = [A[i][k] for i in range(k)]
    return solution

# Pour un bloc, construire les équations pour une position (0 ou 1)
def build_equations(block_data, fec_data, k_block, pos):
    # block_data: dict { relative_index: 2-byte value } pour le bloc
    # fec_data: dict { parity index: 2-byte value } pour ce block
    # pos: 0 pour l'octet de poids fort, 1 pour l'octet de poids faible
    equations = []
    # Pour chaque data packet reçu
    for i in range(k_block):
        if i in block_data:
            # Coefficient = une ligne de l'identité (1 à i, 0 ailleurs)
            row = [0] * k_block
            row[i] = 1
            y = block_data[i][pos]
            equations.append((row, y))
    # Pour chaque FEC packet reçu pour ce bloc (index j)
    for j in fec_data:
        # La ligne est: for i=0..k_block-1, coefficient = alpha^(i*(j+1)) (mod GF(256))
        row = [GF_EXP[(i * (j+1)) % 255] for i in range(k_block)]
        y = fec_data[j][pos]
        equations.append((row, y))
    return equations

def rs_decode_block(block_data, fec_data, k_block):
    # block_data: dict { relative index: 2-byte value } (for one byte position, extracted separately)
    # fec_data: dict { parity index: 2-byte value }
    # On suppose qu'on a reçu au moins k_block équations parmi data et FEC.
    eq = build_equations(block_data, fec_data, k_block, pos=0)
    # Si on a exactement k_block data packets, aucune correction n'est nécessaire.
    if len(eq) < k_block:
        raise ValueError("Pas assez d'équations pour résoudre RS")
    # On choisit les k_block premières équations.
    sol0 = rs_solve(eq[:k_block], k_block)
    
    eq = build_equations(block_data, fec_data, k_block, pos=1)
    sol1 = rs_solve(eq[:k_block], k_block)
    # Retourne la liste de 2-byte valeurs reconstituées pour les indices manquants
    recovered = {}
    for i in range(k_block):
        # Si le paquet data était manquant, utiliser la solution
        if i not in block_data:
            recovered[i] = bytes([sol0[i], sol1[i]])
    return recovered

# --- Réception et réassemblage ---
def run_receiver(host, port, output_file, base_timeout=120):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.settimeout(5)
    logging.info(f"Listening on {host}:{port}")
    
    header_received = False
    total_fragments = 0
    total_size = 0
    data_packets = {}   # { global seq: 2-byte value }
    fec_packets = {}    # { (block_index, idx_in_block): 2-byte value }
    start_time = time.time()
    sender_addr = None

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
            seq = val  # data packet
            frag = val & 0xFFFF
            data_packets[seq] = frag.to_bytes(2, 'big')
            logging.debug(f"Data packet: seq {seq}, skip {skip}")
        else:
            skip, val = deduce_skip(encrypted, RC4_KEY, total_fragments, is_fec=True)
            if skip is not None:
                fec_seq = val
                raw = fec_seq & 0x7FFFFFFF
                block_index = raw // BLOCK_SIZE
                idx_in_block = raw % BLOCK_SIZE
                parity = fec_seq & 0xFFFF
                fec_packets[(block_index, idx_in_block)] = parity.to_bytes(2, 'big')
                logging.debug(f"FEC packet: block {block_index}, idx {idx_in_block}, skip {skip}")
            else:
                logging.warning("Cannot deduce skip for a packet; skipping.")

        if len(data_packets) == total_fragments:
            logging.info("All data packets received.")
            break

    sock.close()
    logging.info(f"Data packets received: {len(data_packets)} / {total_fragments}")
    
    # Réassemblage initial en blocs
    # On travaille par blocs de BLOCK_SIZE fragments
    num_blocks = (total_fragments + BLOCK_SIZE - 1) // BLOCK_SIZE
    reconstructed = bytearray(total_fragments * FRAGMENT_SIZE)
    
    for b in range(num_blocks):
        block_start = b * BLOCK_SIZE
        k_block = min(BLOCK_SIZE, total_fragments - block_start)
        # Pour chaque position (0 = high byte, 1 = low byte), on prépare un dictionnaire pour data et FEC
        block_data_pos0 = {}
        block_data_pos1 = {}
        # Remplir avec les données reçues dans le bloc
        for i in range(k_block):
            seq = block_start + i
            if seq in data_packets:
                val = data_packets[seq]
                block_data_pos0[i] = val[0:1]
                block_data_pos1[i] = val[1:2]
        # Pour chaque FEC packet dans le bloc
        block_fec_pos0 = {}
        block_fec_pos1 = {}
        for j in range(BLOCK_SIZE):
            key = (b, j)
            if key in fec_packets:
                val = fec_packets[key]
                block_fec_pos0[j] = val[0:1]
                block_fec_pos1[j] = val[1:2]
        # Si des fragments sont manquants, tenter RS correction
        if len(block_data_pos0) < k_block:
            try:
                recovered0 = rs_decode_block(block_data_pos0, block_fec_pos0, k_block)
                recovered1 = rs_decode_block(block_data_pos1, block_fec_pos1, k_block)
                # Intégrer les valeurs récupérées
                for i in range(k_block):
                    if i not in block_data_pos0:
                        d0 = recovered0[i][0]
                        d1 = recovered1[i][0]
                        # Mettre à jour data_packets pour la reconstruction
                        data_packets[block_start + i] = bytes([d0, d1])
                        logging.info(f"Recovered missing fragment {block_start + i} via RS.")
            except Exception as e:
                logging.error(f"RS decoding failed for block {b}: {e}")
        # Réassembler le bloc
        for i in range(k_block):
            seq = block_start + i
            frag = data_packets.get(seq, b'\x00\x00')
            reconstructed[seq*2:seq*2+2] = frag

    # Tronquer à la taille attendue
    reconstructed = reconstructed[:total_size]
    # Décompression
    try:
        dump_data = zlib.decompress(reconstructed)
        with open(output_file, "wb") as f:
            f.write(dump_data)
        logging.info(f"Dump decompressed and saved to {output_file}.")
    except Exception as e:
        logging.error(f"Decompression failed: {e}")
        with open(output_file + ".compressed", "wb") as f:
            f.write(reconstructed)
        logging.info(f"Compressed dump saved to {output_file}.compressed.")
    
    # Feedback : si des fragments data manquent toujours, on envoie leur numéro
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
            logging.error(f"Feedback sending error: {e}")
        finally:
            fb_sock.close()

if __name__ == '__main__':
    host = "0.0.0.0"      # Écoute sur toutes les interfaces
    port = 123            # Port UDP simulant le trafic NTP
    output_file = "dump_memory.bin"
    run_receiver(host, port, output_file)
