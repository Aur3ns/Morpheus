# Vérification et installation de Chocolatey
function Install-Chocolatey {
    if (-Not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Host "[*] Chocolatey not found. Installing..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        Invoke-WebRequest -Uri "https://community.chocolatey.org/install.ps1" -UseBasicParsing | Invoke-Expression
        Write-Host "[+] Chocolatey installed successfully."
    } else {
        Write-Host "[+] Chocolatey already installed."
    }
}

# Vérification et installation de GCC via Chocolatey
function Install-GCC {
    if (-Not (Get-Command gcc -ErrorAction SilentlyContinue)) {
        Write-Host "[*] GCC not found. Installing via Chocolatey..."
        choco install mingw -y
        Write-Host "[+] GCC installed successfully."
    } else {
        Write-Host "[+] GCC already installed."
    }
}

# Vérification et installation de Zlib
function Install-Zlib {
    $zlibIncludePath = "C:\mingw64\include\zlib.h"
    $zlibLibPath = "C:\mingw64\lib\libz.a"

    if (-Not (Test-Path $zlibIncludePath) -or -Not (Test-Path $zlibLibPath)) {
        Write-Host "[*] Zlib not found. Downloading and installing..."
        Invoke-WebRequest -Uri "https://zlib.net/zlib1211.zip" -OutFile "zlib.zip"
        Expand-Archive -Path "zlib.zip" -DestinationPath "C:\zlib" -Force
        Move-Item -Path "C:\zlib\zlib.h" -Destination "C:\mingw64\include"
        Move-Item -Path "C:\zlib\zconf.h" -Destination "C:\mingw64\include"
        Move-Item -Path "C:\zlib\libz.a" -Destination "C:\mingw64\lib"
        Move-Item -Path "C:\zlib\zlib1.dll" -Destination "C:\Windows\System32"
        Remove-Item "zlib.zip"
        Remove-Item "C:\zlib" -Recurse
        Write-Host "[+] Zlib installed successfully."
    } else {
        Write-Host "[+] Zlib already installed."
    }
}

# Vérification et installation de UPX
function Install-UPX {
    if (-Not (Test-Path "C:\UPX\upx.exe")) {
        Write-Host "[*] UPX not found. Downloading..."
        Invoke-WebRequest -Uri "https://github.com/upx/upx/releases/latest/download/upx-win64.zip" -OutFile "upx.zip"
        Expand-Archive -Path "upx.zip" -DestinationPath "C:\UPX" -Force
        Remove-Item "upx.zip"
        Write-Host "[+] UPX installed successfully."
    } else {
        Write-Host "[+] UPX already installed."
    }
}

# Compilation du programme C avec GCC
function Compile-CProgram {
    $sourceFile = "dumper.c"
    $executable = "memdump.exe"

    if (-Not (Get-Command gcc -ErrorAction SilentlyContinue)) {
        Write-Host "[!] GCC not found. Make sure MinGW is installed."
        exit 1
    }

    Write-Host "[*] Compiling C program..."
    gcc -o $executable $sourceFile -lz -lws2_32 -lDbgHelp
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Compilation failed."
        exit 1
    } else {
        Write-Host "[+] Compilation successful: $executable"
    }
}

# Obfuscation de l'exécutable avec UPX
function Obfuscate-Executable {
    $exePath = "memdump.exe"
    if (Test-Path "C:\UPX\upx.exe") {
        Write-Host "[*] Obfuscating executable with UPX..."
        Start-Process -FilePath "C:\UPX\upx.exe" -ArgumentList "--best $exePath" -Wait
        Write-Host "[+] Obfuscation completed."
    } else {
        Write-Host "[!] UPX not found. Skipping obfuscation."
    }
}

# Exécution du programme C
function Run-CProgram {
    $exePath = ".\memdump.exe"
    if (Test-Path $exePath) {
        Write-Host "[*] Running C program..."
        Start-Process -FilePath $exePath -Wait
    } else {
        Write-Host "[!] Executable not found."
    }
}

# Lancement des fonctions
Install-Chocolatey
Install-GCC
Install-Zlib
Install-UPX
Compile-CProgram
Obfuscate-Executable
Run-CProgram
