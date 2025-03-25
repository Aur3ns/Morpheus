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
        
        # Télécharger l'archive tar.gz
        $zlibArchive = "zlib.tar.gz"
        $zlibUrl = "https://zlib.net/current/zlib.tar.gz"
        Invoke-WebRequest -Uri $zlibUrl -OutFile $zlibArchive

        # Créer un dossier temporaire pour l'extraction
        $extractDir = "C:\zlib_extract"
        if (-Not (Test-Path $extractDir)) {
            New-Item -ItemType Directory -Path $extractDir | Out-Null
        }
        
        # Extraire l'archive avec tar (Windows 10/11 intègre tar)
        tar -xzf $zlibArchive -C $extractDir

        # Récupérer le sous-dossier extrait (on suppose qu'il y en a un unique)
        $subFolder = Get-ChildItem -Path $extractDir -Directory | Select-Object -First 1
        if ($null -eq $subFolder) {
            Write-Host "[!] Extraction failed. Exiting."
            exit 1
        }

        # Chemins des fichiers attendus dans le sous-dossier
        $zlibFile = Join-Path $subFolder.FullName "zlib.h"
        $zconfFile = Join-Path $subFolder.FullName "zconf.h"
        $libzFile  = Join-Path $subFolder.FullName "libz.a"
        $dllFile   = Join-Path $subFolder.FullName "zlib1.dll"

        if (-Not (Test-Path $zlibFile) -or -Not (Test-Path $zconfFile) -or -Not (Test-Path $libzFile) -or -Not (Test-Path $dllFile)) {
            Write-Host "[!] Required Zlib files not found. Exiting."
            exit 1
        }

        # Déplacer les fichiers dans les répertoires cibles
        Move-Item -Path $zlibFile -Destination "C:\mingw64\include" -Force
        Move-Item -Path $zconfFile -Destination "C:\mingw64\include" -Force
        Move-Item -Path $libzFile  -Destination "C:\mingw64\lib" -Force
        Move-Item -Path $dllFile   -Destination "C:\Windows\System32" -Force

        # Nettoyer les fichiers temporaires
        Remove-Item $zlibArchive -Force
        Remove-Item $extractDir -Recurse -Force

        Write-Host "[+] Zlib installed successfully."
    } else {
        Write-Host "[+] Zlib already installed."
    }
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

# Lancement des fonctions
Install-Chocolatey
Install-GCC
Install-Zlib
Install-UPX
Compile-CProgram
Obfuscate-Executable


Write-Host "[+] Operation Complete"
