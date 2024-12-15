#!/bin/bash

# Nom du fichier source
SOURCE_FILE="dumper.c"
# Nom de l'exécutable
EXECUTABLE="memdump.exe"

# Installation des dépendances nécessaires
install_dependencies() {
    echo "[*] Installation des dépendances..."
    sudo apt-get update
    sudo apt-get install -y g++ zlib1g-dev
    if [ $? -ne 0 ]; then
        echo "[!] Échec de l'installation des dépendances."
        exit 1
    fi
    echo "[+] Dépendances installées avec succès."
}

# Vérification des dépendances
check_dependencies() {
    echo "[*] Vérification des dépendances..."
    for dep in g++ zlib1g-dev; do
        if ! dpkg -l | grep -q ${dep}; then
            echo "[!] La dépendance ${dep} n'est pas installée."
            install_dependencies
            return
        fi
    done
    echo "[+] Toutes les dépendances sont installées."
}

# Compilation du programme
compile_program() {
    echo "[*] Compilation du programme..."
    g++ -o "$EXECUTABLE" "$SOURCE_FILE" -lz -lws2_32 -ldbghelp
    if [ $? -ne 0 ]; then
        echo "[!] Échec de la compilation. Vérifiez le fichier source."
        exit 1
    fi
    echo "[+] Compilation réussie : $EXECUTABLE"
}

# Lancement du programme
run_program() {
    echo "[*] Lancement du programme..."
    ./$EXECUTABLE
    if [ $? -ne 0 ]; then
        echo "[!] Le programme a rencontré une erreur."
        exit 1
    fi
    echo "[+] Programme terminé avec succès."
}

# Étapes principales
check_dependencies
compile_program
run_program
