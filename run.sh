#!/bin/bash

# Installation des dépendances pour C et Python
install_dependencies() {
    echo "[*] Installing dependencies..."
    sudo apt update
    sudo apt install -y mingw-w64 upx python3-pip
    pip install --upgrade pyinstaller
    echo "[+] All dependencies installed successfully."
}

# Compilation du programme C avec MinGW
compile_c_program() {
    SOURCE_FILE="dumper.c"
    EXECUTABLE="memdump.exe"
    echo "[*] Compiling C program..."
    
    x86_64-w64-mingw32-g++ -o "$EXECUTABLE" "$SOURCE_FILE" -lz -lws2_32 -lDbgHelp
    if [ $? -ne 0 ]; then
        echo "[!] C compilation failed."
        exit 1
    fi
    echo "[+] C compilation successful: $EXECUTABLE"
}

# Obfuscation avec UPX
obfuscate_executable() {
    local exe_path="$1"
    if command -v upx &>/dev/null; then
        echo "[*] Obfuscating executable with UPX..."
        upx --best "$exe_path" || { echo "[!] UPX failed."; exit 1; }
        echo "[+] Obfuscation completed."
    fi
}

# Lancement du programme C
run_c_program() {
    EXECUTABLE="memdump.exe"
    echo "[*] Running C program..."
    ./"$EXECUTABLE"
}

# Compilation du script Python en exécutable
build_python_executable() {
    PY_SOURCE="memdump.py"
    echo "[*] Building Python executable..."
    pyinstaller --onefile "$PY_SOURCE" --noconsole
}

# Lancement du programme Python
run_python_program() {
    PY_EXECUTABLE="dist/memdump"
    echo "[*] Running Python program..."
    ./"$PY_EXECUTABLE"
}

# Menu de sélection
echo "Which version do you want to use? (C/Python)"
read -r version_choice

if [[ "$version_choice" =~ ^[Cc] ]]; then
    install_dependencies
    compile_c_program
    obfuscate_executable "memdump.exe"
    run_c_program
elif [[ "$version_choice" =~ ^[Pp] ]]; then
    install_dependencies
    build_python_executable
    obfuscate_executable "dist/memdump"
    run_python_program
else
    echo "[!] Invalid choice. Choose 'C' or 'Python'."
    exit 1
fi
