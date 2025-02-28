<h1 align="center"> Project lsassDumper </h1>

Description
-----------
lsassDumper is a tool designed to dump the memory of the Windows process "lsass.exe" without using mimikatz. The dump is performed entirely in RAM, then compressed using the zlib library and fragmented for transmission via UDP packets disguised as NTP packets. This method helps reduce detection by security solutions such as Windows Defender and advanced Endpoint Detection and Response (EDR) tools.

Key Features
------------
1. **Process Identification**
   - The target process name ("lsass.exe") is obfuscated within the source code by XOR-ing each character with the key 0x13. This technique hinders static analysis.
   - The tool retrieves the Process ID (PID) of lsass.exe by enumerating running processes using Windows APIs like CreateToolhelp32Snapshot, Process32FirstW, and Process32NextW.

2. **Memory Dump**
   - Once identified, lsass.exe is opened with the necessary privileges.
   - Memory is dumped directly into a RAM buffer using the MiniDumpWriteDump function from DbgHelp.dll. This avoids writing sensitive information to disk.

3. **In-RAM Compression**
   - The memory dump is compressed using the zlib library, keeping the entire operation in RAM. This reduces the data size and further minimizes the footprint on disk.

4. **Data Transmission via UDP (Mimicking NTP)**
   - The compressed memory dump is split into small fragments.
   - A header packet (8 bytes) is first sent, containing:
     • A 4-byte value for the total number of fragments (big-endian).
     • A 4-byte value for the total size of the compressed data (big-endian).
   - Each subsequent packet (8 bytes) contains:
     • A 4-byte sequence number (big-endian).
     • A 4-byte fragment of the compressed data.
   - These packets are crafted to mimic NTP packets by inserting the payload in the “transmit timestamp” field.

5. **Receiver Script **
   - A separate Python script (receiver.py) listens on a specified UDP port.
   - It reconstructs the data by receiving the header and fragments, then reassembles, truncates to the correct size, decompresses the stream, and saves the final memory dump to a file.

6. Multi-Language Implementations & Automation
   - Two versions of the tool are provided: one written in C (memdump.c) and one in Python (memdump.py), both implementing the same functionality.
   - A Bash script (run.sh) is included to automate dependency installation, compilation (for the C version) or packaging (for the Python version using PyInstaller), and execution.

Prerequisites
-------------
Environment:
- **Operating System:** Windows (required to access and dump lsass.exe memory).
- **Compiler/Interpreter:** 
  - For the C version: a compiler that supports Windows API (e.g., MinGW or Visual Studio).
  - For the Python version: Python 3.x with required modules.

Required Libraries:
- **zlib:** Used for compressing the memory dump.
- **DbgHelp:** Provides access to the MiniDumpWriteDump functionality.
- **Winsock2:** Enables network communication (UDP transmission).

Repository Contents
-------------------
- **memdump.c**  
  C source code that identifies lsass.exe, dumps its memory, compresses the data in RAM using zlib, and transmits it via UDP packets mimicking NTP.
  
- **memdump.py**  
  Python implementation that performs the same operations as the C version, utilizing modules such as psutil and ctypes for Windows API calls.
  
- **run.sh**  
  A Bash script that automates the entire process:
    • Installation of C dependencies.
    • Compilation of memdump.c (or conversion of memdump.py to an executable via PyInstaller).
    • Execution of the chosen version (C or Python).
  
- **receiver.py**  
  A Python script that acts as a receiver. It listens on a specified UDP port, reassembles the received fragments, decompresses the data, and saves the resulting memory dump to a file.

How It Works
------------
1. Process Identification:
   - The tool decodes the obfuscated string for "lsass.exe" using an XOR key (0x13).
   - It then enumerates running processes to locate lsass.exe and retrieves its PID using Windows API functions.

2. Memory Dump:
   - With the necessary privileges, the tool opens the target process and uses MiniDumpWriteDump to dump the process's memory directly into a RAM buffer via a memory-mapped file.

3. In-RAM Compression:
   - The dumped memory is compressed using zlib. This step is performed entirely in RAM, ensuring that no sensitive data is written to disk.

4. Data Transmission via UDP:
   - The compressed dump is split into small fragments.
   - The first packet sent is a header containing:
     • The total number of fragments.
     • The total compressed data size.
   - Each subsequent packet includes a sequence number and a fragment of the compressed data, formatted to mimic the "transmit timestamp" field of an NTP packet.
   - Packets are sent over UDP to a user-specified remote server.

5. Data Reception and Reassembly (Receiver Script):
   - The receiver script listens on a defined UDP port (default is port 123).
   - It first receives the header and then the data fragments.
   - After receiving all fragments (or upon timeout), the script reassembles the data in the correct order, truncates it to the expected size, decompresses it, and writes the memory dump to a file.

Compilation and Execution
-------------------------
With MinGW (for C version):
1. Ensure MinGW is installed and properly configured on your system.
2. Compile memdump.c with the following command:

   ```bash
   g++ -o memdump.exe memdump.c -lz -lws2_32 -ldbghelp
   ```

With Visual Studio (for C version):
1. Open memdump.c in Visual Studio.
2. Add the necessary libraries (DbgHelp.lib, ws2_32.lib) to your project settings.
3. Build the project to generate memdump.exe.

For the Python version:
- Ensure all required Python modules (psutil, ctypes, zlib, socket, etc.) are installed.
- Optionally, use PyInstaller to convert memdump.py to an executable:
  
  ```bash
  pyinstaller --onefile memdump.py --noconsole
  ```

Usage
-----
1. Run the executable as an administrator (administrative privileges are required to access lsass.exe):

   For the C version:
   ```bash
   memdump.exe
   ```

   For the Python version:
   ```bash
   python memdump.py
   ```
   (or run the generated executable if using PyInstaller)

3. When prompted, enter the IP address and port of the remote server that will receive the compressed dump.

4. The program will:
   - Identify lsass.exe and retrieve its PID.
   - Dump the process memory into a RAM buffer.
   - Compress the memory dump using zlib.
   - Fragment the compressed data and send it over UDP using packets formatted to mimic NTP.

5. To reconstruct the dump on the server side, run the receiver script:

   python receiver.py

   The receiver listens on the configured port, reassembles the received fragments, decompresses the data, and saves the final dump to a file.

Example Output
--------------

```bash
[*] Enter server IP: 192.168.1.100
[*] Enter server port: 4444
[+] Process lsass.exe found with PID 1234
[+] Memory dump completed. Size: 16777216 bytes.
[+] Compression completed. Compressed size: 524288 bytes.
[+] Header sent: 131072 fragments, 524288 bytes total.
[+] Packet 1/131072 sent.
...
[+] Transmission completed.
[+] Done!
```

Automation with run.sh
-----------------------
The run.sh script automates the following tasks:
- Installing the required dependencies for the C version (and UPX obfuscation if available).
- Compiling the C code or converting the Python script into an executable using PyInstaller.
- Running the selected version (C or Python) based on user input.

To use run.sh:
1. Make the script executable:
   ```bash
   chmod +x run.sh
   ```

2. Run the script:
   ```bash
   ./run.sh
   ```

You will be prompted to choose between the C and Python versions. The script will then handle dependency installation, compilation (or packaging), and execution.

Warnings and Legal Notice
-------------------------
- **Legal and Educational Use Only:** This tool is intended solely for educational, diagnostic, or authorized testing purposes on systems that you own or manage.
- **Administrator Privileges Required:** The program must be run with administrative rights to access lsass.exe.
- **Security Detection:** Although the tool minimizes its footprint by operating entirely in RAM and using basic obfuscation techniques, advanced security solutions may still detect its activity.

Dependencies
------------
- **zlib:** https://zlib.net – Used for compressing the memory dump.
- **DbgHelp:** Included with the Windows SDK – Provides the MiniDumpWriteDump function.
- **Winsock2:** Built into Windows – Facilitates UDP network communication.

Contributions
-------------
Contributions to improve or optimize lsassDumper are welcome. Please feel free to submit a pull request or open an issue to share your ideas.
