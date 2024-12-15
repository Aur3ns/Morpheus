<h1 align="center"> Project lsassDumper </h1>

## Description

This program is designed to dump the memory of the `lsass.exe` process on a Windows system. The dumped memory is compressed using the **zlib** library and then sent as a compressed file to a remote server via a network connection. The program is particularly useful in situations where tools like Mimikatz cannot be used. All operations, including the memory dump and compression, are performed entirely in RAM to minimize detection by security solutions such as Defender and Endpoint Detection and Response (EDR) tools.

### Key Features

1. **Retrieve PID of `lsass.exe`**: The program identifies the `lsass.exe` process by its name using Windows API functions.
2. **Memory Dump**: It leverages `MiniDumpWriteDump` to extract the memory contents of the process.
3. **Data Compression**: The dumped data is compressed in RAM using the **zlib** library to minimize the file size.
4. **Network Transmission**: The compressed data is transmitted over a TCP connection to a specified remote server.
5. **Obfuscation**: To evade basic analysis, the name of the target process (`lsass.exe`) is obfuscated in the source code.

## Prerequisites

### Environment
- **Windows** operating system.
- **Compiler**: A compiler capable of handling Windows APIs, such as MinGW or Visual Studio.

### Required Libraries
- **zlib**: For compressing the dumped memory.
- **DbgHelp**: For accessing `MiniDumpWriteDump` functionality.
- **Winsock2**: For enabling TCP/IP communication.

## How It Works

1. **Process Identification**:
   - The program takes the encoded string for `lsass.exe` and decodes it.
   - Using `CreateToolhelp32Snapshot` and `Process32First/Next`, it identifies the `lsass.exe` process by name and retrieves its Process ID (PID).

2. **Memory Dump**:
   - It opens the target process using `OpenProcess` with the required privileges.
   - Dumps the process memory directly into a buffer in RAM using `MiniDumpWriteDump`.

3. **Compression**:
   - The dumped data is compressed entirely in RAM using `zlib` to ensure no sensitive data is written to disk.

4. **Data Transmission**:
   - The compressed data is sent to a remote server over a TCP connection.
   - The server's IP and port are provided by the user during execution.

## Compilation

### Steps with MinGW
1. Ensure MinGW is installed and correctly configured on your system.
2. Compile the source file `memdump.c` using the following command:

   ```bash
   g++ -o memdump.exe memdump.c -lz -lws2_32 -ldbghelp
   ```

### Steps with Visual Studio
1. Open the `memdump.c` file in Visual Studio.
2. Add the required libraries (`DbgHelp.lib`, `ws2_32.lib`) to the project settings.
3. Build the project to generate the executable.

## Usage

1. Run the compiled executable as an administrator (administrator rights are required to access `lsass.exe`).

   ```bash
   memdump.exe
   ```

2. When prompted, provide the IP address and port of the remote server to which the compressed dump will be sent.

3. The program:
   - Identifies the `lsass.exe` process.
   - Dumps the memory contents into a buffer stored in RAM.
   - Compresses the data using `zlib`.
   - Transmits the compressed data to the specified remote server.

### Example Output

```plaintext
[*] Enter server IP: 192.168.1.100
[*] Enter server port: 4444
[+] Memory dump completed. Size: 16777216 bytes.
[+] Compression completed. Compressed size: 524288 bytes.
[+] Sent 524288 bytes to server.
[+] Done!
```

## Automating with `run.sh`

The `run.sh` script simplifies the process by automating dependency installation, compilation, and execution. It ensures the necessary libraries are installed and the program is compiled and executed in a streamlined manner.

### Usage of `run.sh`

1. Make the script executable:
   ```bash
   chmod +x run.sh
   ```

2. Execute the script:
   ```bash
   ./run.sh
   ```

The script handles dependency installation, compiles `memdump.c` into `memdump.exe`, and executes it seamlessly.

## Warnings

- **For Legal and Educational Use Only**: This program is intended solely for educational purposes or diagnostic use on systems you own or manage, or as part of authorized audits.
- **Administrator Privileges Required**: Ensure you have administrative rights to run this program.
- **Security Detection**: While the program minimizes detection risks by performing operations entirely in RAM and using basic obfuscation, advanced security solutions may still flag it.

## Dependencies

- **zlib**: [zlib.net](https://zlib.net) - For data compression.
- **DbgHelp**: Included with the Windows SDK - For `MiniDumpWriteDump` functionality.
- **Winsock2**: Built into Windows - For network communication.

## Contributions
Contributions to enhance this program or suggest optimizations are welcome. Please create a pull request or open an issue to share your ideas.
