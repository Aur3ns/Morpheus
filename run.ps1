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

# Installation de zlib via vcpkg en mode statique pour MinGW
function Install-Zlib {
    $vcpkgRoot = "C:\vcpkg"
    $vcpkgExe = "$vcpkgRoot\vcpkg.exe"
    $triplet = "x64-mingw-static"  # Utilise la version statique
    
    Write-Host "[*] Installing zlib via vcpkg using triplet $triplet..."
    $env:VCPKG_DEFAULT_TRIPLET = $triplet
    $env:VCPKG_CHAINLOAD_TOOLCHAIN_FILE = "$vcpkgRoot\scripts\buildsystems\mingw.cmake"
    
    & $vcpkgExe install zlib:$triplet
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] zlib installation via vcpkg failed."
        exit 1
    }
    Write-Host "[+] zlib installed successfully via vcpkg."
}

# Vérification et installation de UPX (facultatif)
function Install-UPX {
    $upxPath = Get-ChildItem -Path "C:\UPX" -Filter "upx.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-Not $upxPath) {
        Write-Host "[*] UPX not found. Downloading..."
        Invoke-WebRequest -Uri "https://github.com/upx/upx/releases/download/v5.0.0/upx-5.0.0-win64.zip" -OutFile "upx-5.0.0-win64.zip"
        Expand-Archive -Path "upx-5.0.0-win64.zip" -DestinationPath "C:\UPX" -Force
        Remove-Item "upx-5.0.0-win64.zip"
        Write-Host "[+] UPX installed successfully."
    } else {
        Write-Host "[+] UPX already installed at $($upxPath.FullName)."
    }
}

# Compilation du programme C avec GCC en liant statiquement zlib
function Compile-CProgram {
    $sourceFile = "dumper.c"
    $executable = "memdump.exe"
    $triplet = "x64-mingw-static"

    if (-Not (Get-Command gcc -ErrorAction SilentlyContinue)) {
        Write-Host "[!] GCC not found. Make sure MinGW is installed."
        exit 1
    }

    Write-Host "[*] Compiling C program..."
    $vcpkgRoot = "C:\vcpkg"
    $zlibInclude = "$vcpkgRoot\installed\$triplet\include"
    $zlibLib = "$vcpkgRoot\installed\$triplet\lib"

    # Compilation en liant statiquement (-static) et en incluant zlib, ws2_32 et DbgHelp
    gcc -I"$zlibInclude" -L"$zlibLib" -static -o $executable $sourceFile -lzlib -lws2_32 -lDbgHelp
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Compilation failed."
        exit 1
    } else {
        Write-Host "[+] Compilation successful: $executable"
    }
}

# Obfuscation de l'exécutable avec UPX (facultatif)
function Obfuscate-Executable {
    $upxExe = Get-ChildItem -Path "C:\UPX" -Filter "upx.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($upxExe) {
        Write-Host "[*] Obfuscating executable with UPX..."
        Start-Process -FilePath $upxExe.FullName -ArgumentList "--best memdump.exe" -Wait
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
