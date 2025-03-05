#!/bin/bash

# Fonction pour installer les dépendances
install_dependencies() {
    echo "[*] Installing dependencies..."
    sudo apt update
    sudo apt install -y gcc zlib1g-dev upx
    if [ $? -ne 0 ]; then
        echo "[!] Failed to install dependencies."
        exit 1
    fi
    echo "[+] All dependencies installed successfully."
}

# Compilation du programme C
compile_c_program() {
    SOURCE_FILE="dumper.c"
    EXECUTABLE="memdump"
    
    echo "[*] Compiling C program..."
    gcc -o "$EXECUTABLE" "$SOURCE_FILE" -lz
    if [ $? -ne 0 ]; then
        echo "[!] Compilation failed."
        exit 1
    fi
    echo "[+] Compilation successful: $EXECUTABLE"
}

# Obfuscation avec UPX
obfuscate_executable() {
    local exe_path="$1"
    if command -v upx &>/dev/null; then
        echo "[*] Obfuscating executable with UPX..."
        upx --best "$exe_path" || { echo "[!] UPX failed."; exit 1; }
        echo "[+] Obfuscation completed."
    else
        echo "[!] UPX not found. Skipping obfuscation."
    fi
}

# Exécution du programme C
run_c_program() {
    EXECUTABLE="./memdump"
    if [ -f "$EXECUTABLE" ]; then
        echo "[*] Running C program..."
        "$EXECUTABLE"
    else
        echo "[!] Executable not found."
        exit 1
    fi
}

# Lancement des fonctions
install_dependencies
compile_c_program
obfuscate_executable "memdump"
run_c_program
