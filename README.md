<h1 align="center">Project Morpheus</h1>

## Overview

**Morpheus** is a fully in-RAM Windows memory-dump & exfiltration framework for **`lsass.exe`**, designed to leave zero disk artifacts and blend seamlessly into legitimate NTP network traffic. Unlike tools such as Mimikatz or procdump, Morpheus:

- Uses **indirect syscalls** (via dynamically loaded Advapi32) to enable **SeDebugPrivilege** without on-disk stubs.
- Dumps process memory via **`MiniDumpWriteDump`** from **`DbgHelp.dll`**, into a temporary in-RAM buffer.
- Compresses the dump with **zlib** (in-memory), reducing size and obfuscating entropy.
- Fragments and **RC4-encrypts** the compressed data, adding per‑packet “skip” offsets derived from the sequence number.
- Implements **Reed–Solomon FEC** over GF(256) (primitive polynomial 0x11d) with a Vandermonde generator to recover lost fragments.
- Exfiltrates everything over UDP port 123 as **legitimate NTP requests**, with randomized header fields and decoy traffic to defeat DPI.

---

## Components

1. **Dumper** (`morpheus.c` / `memdump.exe`):  
   - **Privilege elevation** via indirect `OpenProcessToken`/`LookupPrivilegeValueW`/`AdjustTokenPrivileges`.  
   - **Target obfuscation**: `"lsass.exe"` is XOR’d bytewise (key 0x13) in the binary, decoded at runtime.  
   - **Process enumeration** with `CreateToolhelp32Snapshot` + `Process32FirstW`/`NextW`.  
   - **In-RAM dump**: calls `MiniDumpWriteDump` → reads the temporary dump file back into memory.  
   - **Compression**: zlib’s `compress()` → `compressedBuffer`.  
   - **Fragmentation**: split into `FRAGMENT_SIZE`-byte chunks (default 2 bytes each).  
   - **RC4 encryption**: per-packet KSA + PRGA, with a **skip** of `(seq*7)%256` for data packets, `(seq*13)%256` for FEC.  
   - **RFEC**: for each block of `BLOCK_SIZE` fragments, generate parity shards.  
   - **Decoys**: 1/5 chance per data packet to send a pure NTP decoy (timestamp+fraction only).  
   - **Inter‑packet jitter**: `Sleep(rand(BASE_DELAY_MIN…BASE_DELAY_MAX))` ms (e.g. 5–20 ms) → high throughput but randomized.  
   - **NTP header randomization** on each burst:  
     - **Stratum** ∈ [2…4]  
     - **Poll** ∈ [6…10]  
     - **Precision** ∈ [–10…–20]  
     - **Reference ID**: zero or random (1 in 10)  

2. **Python Receiver** (`server.py`):  
   - Listens on UDP port 123 (NTP).  
   - Extracts the 8-byte **Transmit Timestamp** from each 48-byte packet.  
   - **Deduce “skip”** by trying 0…255 until decrypted high‑word < `total_fragments` (data) or ≥ (FEC).  
   - Stores data fragments (`seq → 2 bytes`) and FEC shards (`(block, idx) → 2 bytes`).  
   - **Gauss over GF(256)** to recover missing in each block (pos 0 & pos 1 separately).  
   - Reassembles and **zlib.decompress()** → writes `dump_memory.bin`.  
   - Sends UDP feedback on port 124 listing any remaining missing sequences.

3. **PowerShell Receiver** (`server.ps1`):  
   - Identical logic in PowerShell 7+.  
   - Uses `.NET` GF(256) tables, RC4, RS decode, zlib via `ZLibStream`/`DeflateStream`.  
   - `BASE_TIMEOUT = 432000` seconds (5 days) to cover ~4‑5 day exfiltration.

---

## How NTP Camouflage Works

```text
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
  |                   Reference Timestamp (64 bits)               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                   Originate Timestamp (64 bits)               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Receive Timestamp (64 bits)                |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    Transmit Timestamp (64 bits)               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Bytes 0–3**: LI=0, VN=3, Mode=3; Stratum/Poll/Precision randomized.  
- **Bytes 4–39**: padding/noise.  
- **Bytes 40–47**: covert payload (header, data, or FEC).

---

## Installation & Build

### PowerShell bootstrap

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
./run.ps1
```

### Python Receiver

```bash
chmod +x server.py
```

### PowerShell Receiver

```powershell
.\server.ps1
```

---

## Usage

```powershell
# Dumper
.\memdump.exe
```

```bash
# Python Receiver
./server.py
```

```powershell
# PS Receiver
.\server.ps1
```

---

## Post-Processing with Mimikatz

```powershell
sekurlsa::minidump dump_memory.bin
sekurlsa::logonpasswords
```

---

## Legal Notice

**FOR AUTHORIZED TESTING ONLY.**  
Unauthorized use is illegal and unethical.
