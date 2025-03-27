#!/usr/bin/env python3
import socket
import struct
import sys
import zlib
import logging
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

def print_progress(current, total):
    """Displays a progress bar in the console."""
    percent = int((current / total) * 100) if total > 0 else 0
    bar_length = 20
    filled_length = int(bar_length * percent // 100)
    bar = '=' * filled_length + '-' * (bar_length - filled_length)
    print(f"\r[Reassembly] [{bar}] {percent}% ({current}/{total})", end='', flush=True)

def run_receiver(host, port, output_file, base_timeout=120):
    """
    Listens for UDP packets (NTP format) on the specified port.
    The first packet (header) contains:
      - 4 bytes: total number of fragments (big-endian)
      - 4 bytes: total size of the compressed stream (big-endian)
    Each subsequent packet contains:
      - 4 bytes: fragment sequence number (big-endian)
      - 4 bytes: fragment of compressed data
    Once all fragments are received or the timeout expires, the stream is reassembled and decompressed.
    The final dump is saved to output_file.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.settimeout(5)  # Timeout per packet
    logging.info(f"Listening on {host}:{port} (initial base timeout: {base_timeout}s)")

    header_received = False
    total_fragments = 0
    total_size = 0
    fragments = {}
    start_time = time.time()
    dynamic_timeout = base_timeout  # Default if no header is received

    while True:
        try:
            data, addr = sock.recvfrom(1024)
        except socket.timeout:
            # Stop if overall timeout exceeded
            if time.time() - start_time > dynamic_timeout:
                logging.warning("Global timeout reached, stopping reception.")
                break
            else:
                continue

        if len(data) < 48:
            # Ignore malformed packets
            continue

        # Extract the NTP transmit timestamp (bytes 40 to 47)
        payload = data[40:48]

        if not header_received:
            # This is the first packet (header)
            total_fragments = struct.unpack(">I", payload[:4])[0]
            total_size = struct.unpack(">I", payload[4:8])[0]
            header_received = True

            # Dynamically calculate timeout based on expected fragment rate
            min_rate = 1000  # fragments per second (adjustable)
            estimated_time = total_fragments / min_rate
            dynamic_timeout = int(estimated_time * 1.5)  # add margin of safety
            logging.info(f"Header received: {total_fragments} fragments, {total_size} compressed bytes.")
            logging.info(f"Adjusted timeout to {dynamic_timeout} seconds based on expected fragment rate.")
        else:
            # Extract sequence number and fragment
            seq = struct.unpack(">I", payload[:4])[0]
            fragment = payload[4:8]
            if seq not in fragments:
                fragments[seq] = fragment
                print_progress(len(fragments), total_fragments)

            # If all fragments are received, stop listening
            if len(fragments) == total_fragments:
                logging.info("\nAll fragments received.")
                break

        # Double-check timeout after processing
        if time.time() - start_time > dynamic_timeout:
            logging.warning("Global timeout exceeded, ending reception.")
            break

    sock.close()
    print()  # Newline after progress bar

    if not header_received:
        logging.error("No header received. Exiting.")
        sys.exit(1)

    if len(fragments) != total_fragments:
        logging.warning(f"Expected fragments: {total_fragments} | Received: {len(fragments)}")
        logging.warning("The dump may be incomplete.")

    # Reassemble compressed stream in order
    compressed_data = bytearray()
    for i in range(total_fragments):
        fragment = fragments.get(i, b'\0'*4)  # Pad with nulls if missing
        compressed_data.extend(fragment)

    # Truncate to expected size
    compressed_data = compressed_data[:total_size]

    # Attempt to decompress and save
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

if __name__ == '__main__':
    host = "0.0.0.0"   # Listen on all interfaces
    port = 123         # UDP port (simulating NTP traffic)
    output_file = "dump_memory.bin"
    run_receiver(host, port, output_file)
