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

# Vérification et installation de vcpkg
function Install-Vcpkg {
    $vcpkgRoot = "C:\vcpkg"
    $vcpkgExe = "$vcpkgRoot\vcpkg.exe"
    if (-Not (Test-Path $vcpkgExe)) {
        Write-Host "[*] vcpkg not found. Installing..."
        # Cloner le dépôt vcpkg dans C:\vcpkg
        git clone https://github.com/Microsoft/vcpkg.git $vcpkgRoot
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[!] Failed to clone vcpkg repository."
            exit 1
        }
        Push-Location $vcpkgRoot
        .\bootstrap-vcpkg.bat
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[!] vcpkg bootstrap failed."
            Pop-Location
            exit 1
        }
        Pop-Location
        Write-Host "[+] vcpkg installed successfully."
    } else {
        Write-Host "[+] vcpkg already installed."
    }
}

# Installation de zlib via vcpkg en configurant l'environnement pour MinGW
function Install-Zlib {
    $vcpkgRoot = "C:\vcpkg"
    $vcpkgExe = "$vcpkgRoot\vcpkg.exe"
    # Choix du triplet pour MinGW
    $triplet = "x64-mingw-dynamic"
    Write-Host "[*] Installing zlib via vcpkg using triplet $triplet..."
    
    # Définir les variables d'environnement pour utiliser le toolchain MinGW
    $env:VCPKG_DEFAULT_TRIPLET = $triplet
    $env:VCPKG_CHAINLOAD_TOOLCHAIN_FILE = "$vcpkgRoot\scripts\buildsystems\mingw.cmake"
    
    & $vcpkgExe install zlib:$triplet
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] zlib installation via vcpkg failed."
        exit 1
    }
    Write-Host "[+] zlib installed successfully via vcpkg."
}

# Vérification et installation de UPX
function Install-UPX {
    if (-Not (Test-Path "C:\UPX\upx.exe")) {
        Write-Host "[*] UPX not found. Downloading..."
        Invoke-WebRequest -Uri "https://github.com/upx/upx/releases/download/v5.0.0/upx-5.0.0-win64.zip" -OutFile "upx-5.0.0-win64.zip"
        Expand-Archive -Path "upx-5.0.0-win64.zip" -DestinationPath "C:\UPX" -Force
        Remove-Item "upx-5.0.0-win64.zip"
        Write-Host "[+] UPX installed successfully."
    } else {
        Write-Host "[+] UPX already installed."
    }
}

# Compilation du programme C avec GCC en utilisant zlib installé via vcpkg
function Compile-CProgram {
    $sourceFile = "dumper.c"
    $executable = "memdump.exe"

    if (-Not (Get-Command gcc -ErrorAction SilentlyContinue)) {
        Write-Host "[!] GCC not found. Make sure MinGW is installed."
        exit 1
    }

    Write-Host "[*] Compiling C program..."
    # Chemins d'inclusion et de librairie depuis vcpkg
    $vcpkgRoot = "C:\vcpkg"
    $triplet = "x64-mingw-dynamic"
    $zlibInclude = "$vcpkgRoot\installed\$triplet\include"
    $zlibLib = "$vcpkgRoot\installed\$triplet\lib"

    gcc -I"$zlibInclude" -L"$zlibLib" -o $executable $sourceFile -lz -lws2_32 -lDbgHelp
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

# Lancement des fonctions
Install-Chocolatey
Install-GCC
Install-Vcpkg
Install-Zlib
Install-UPX
Compile-CProgram
Obfuscate-Executable

Write-Host "[+] Operation Complete"
