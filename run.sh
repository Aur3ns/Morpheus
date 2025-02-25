#!/bin/bash

# Fonction pour installer les dépendances C
install_c_dependencies() {
    echo "[*] Installing C dependencies..."
    sudo apt-get update
    sudo apt-get install -y g++ zlib1g-dev
    if [ $? -ne 0 ]; then
        echo "[!] Failed to install C dependencies."
        exit 1
    fi
    echo "[+] C dependencies installed successfully."
}

# Vérification des dépendances C
check_c_dependencies() {
    echo "[*] Checking C dependencies..."
    for dep in g++; do
        if ! dpkg -l | grep -q ${dep}; then
            echo "[!] Dependency ${dep} is not installed."
            install_c_dependencies
            return
        fi
    done
    echo "[+] All C dependencies are installed."
}

# Vérification de la présence de UPX pour l'obfuscation
check_upx() {
    if ! command -v upx &>/dev/null; then
        echo "[*] UPX is not installed. Installing UPX..."
        sudo apt-get install -y upx
        if [ $? -ne 0 ]; then
            echo "[!] Failed to install UPX."
            return 1
        fi
    fi
    return 0
}

# Obfuscation de l'exécutable avec UPX
obfuscate_executable() {
    local exe_path="$1"
    echo "[*] Obfuscating executable with UPX..."
    upx --best "$exe_path"
    if [ $? -ne 0 ]; then
        echo "[!] Obfuscation failed."
        exit 1
    fi
    echo "[+] Obfuscation completed."
}

# Compilation du programme C
compile_c_program() {
    SOURCE_FILE="dumper.c"
    EXECUTABLE="memdump.exe"
    echo "[*] Compiling C program..."
    g++ -o "$EXECUTABLE" "$SOURCE_FILE" -lz -lws2_32 -ldbghelp
    if [ $? -ne 0 ]; then
        echo "[!] C compilation failed. Check the source file."
        exit 1
    fi
    echo "[+] C compilation successful: $EXECUTABLE"
    check_upx && obfuscate_executable "$EXECUTABLE"
}

# Lancement du programme C
run_c_program() {
    EXECUTABLE="memdump.exe"
    echo "[*] Running C program..."
    ./"$EXECUTABLE"
    if [ $? -ne 0 ]; then
        echo "[!] The C program encountered an error."
        exit 1
    fi
    echo "[+] C program finished successfully."
}

# Vérification de la présence de PyInstaller pour la version Python
check_pyinstaller() {
    if ! command -v pyinstaller &>/dev/null; then
        echo "[*] PyInstaller is not installed. Installing..."
        pip install pyinstaller
        if [ $? -ne 0 ]; then
            echo "[!] Failed to install PyInstaller."
            exit 1
        fi
    fi
}

# Transformation du script Python en exécutable
build_python_executable() {
    PY_SOURCE="memdump.py"
    echo "[*] Converting Python script to executable with PyInstaller..."
    pyinstaller --onefile "$PY_SOURCE" --noconsole
    if [ $? -ne 0 ]; then
        echo "[!] Python executable conversion failed."
        exit 1
    fi
    echo "[+] Python executable conversion successful."
}

# Lancement du programme Python
run_python_program() {
    PY_EXECUTABLE="dist/memdump"
    if [ ! -f "$PY_EXECUTABLE" ]; then
        echo "[!] Python executable not found."
        exit 1
    fi
    check_upx && obfuscate_executable "$PY_EXECUTABLE"
    echo "[*] Running Python program..."
    ./"$PY_EXECUTABLE"
    if [ $? -ne 0 ]; then
        echo "[!] The Python program encountered an error."
        exit 1
    fi
    echo "[+] Python program finished successfully."
}

# Demande à l'utilisateur quelle version utiliser
echo "Which version do you want to use? (C/Python)"
read -r version_choice

if [[ "$version_choice" =~ ^[Cc] ]]; then
    check_c_dependencies
    compile_c_program
    run_c_program
elif [[ "$version_choice" =~ ^[Pp] ]]; then
    check_pyinstaller
    build_python_executable
    run_python_program
else
    echo "[!] Unrecognized option. Please choose 'C' or 'Python'."
    exit 1
fi
