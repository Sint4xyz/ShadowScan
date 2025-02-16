import requests
import ssl
import socket
from urllib.parse import urljoin
from colorama import Fore, Style, init

# Inicializar colorama
init(autoreset=True)

def print_banner():
    """Muestra el banner de ShadowScan."""
    banner = f"""
{Fore.RED}
   ___|   |      |  |        |                    ___|         |  |          
 \___ \   __ \   |  |     _` |   _ \ \ \  \   / \___ \    __|  |  |    __ \  
       |  | | | ___ __|  (   |  (   | \ \  \ /        |  (    ___ __|  |   | 
 _____/  _| |_|    _|   \__,_| \___/   \_/\_/   _____/  \___|    _|   _|  _| 
{Style.RESET_ALL}
{Fore.CYAN}Herramienta de análisis de seguridad web avanzada{Style.RESET_ALL}
{Fore.YELLOW}Desarrollado por Sint4xyz{Style.RESET_ALL}
"""
    print(banner)

def get_headers(url):
    """Obtiene las cabeceras HTTP de un sitio web, siguiendo redirecciones."""
    try:
        response = requests.get(url, allow_redirects=True)
        return response.headers, response.url, response.cookies, response.status_code
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error al conectar con {url}: {e}{Style.RESET_ALL}")
        return None, None, None, None

def analyze_headers(headers):
    """Analiza las cabeceras HTTP en busca de configuraciones inseguras."""
    security_headers = {
        "Content-Security-Policy": {
            "description": "Protección contra ataques XSS e inyección de código.",
            "required": True,
        },
        "X-Frame-Options": {
            "description": "Protección contra clickjacking.",
            "required": True,
            "valid_values": ["DENY", "SAMEORIGIN"],
        },
        "X-Content-Type-Options": {
            "description": "Evita MIME sniffing.",
            "required": True,
            "valid_values": ["nosniff"],
        },
        "Strict-Transport-Security": {
            "description": "Fuerza el uso de HTTPS (HSTS).",
            "required": True,
        },
        "Referrer-Policy": {
            "description": "Control de información de referrer.",
            "required": False,
        },
        "Access-Control-Allow-Origin": {
            "description": "Control de acceso CORS.",
            "required": False,
            "valid_values": ["*"],
        },
        "Cache-Control": {
            "description": "Control de almacenamiento en caché.",
            "required": False,
        },
    }

    print(f"\n{Fore.GREEN}=== Análisis de Cabeceras HTTP ==={Style.RESET_ALL}")
    for header, details in security_headers.items():
        if header not in headers:
            if details["required"]:
                print(f"{Fore.RED}[!] Falta: {header} - {details['description']}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[~] Opcional: {header} no está presente - {details['description']}{Style.RESET_ALL}")
        else:
            value = headers[header]
            if "valid_values" in details and value in details["valid_values"]:
                if value == "*" and header == "Access-Control-Allow-Origin":
                    print(f"{Fore.RED}[!] {header} configurado de manera insegura: {value} - {details['description']}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[+] {header}: {value} - {details['description']}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[~] {header} presente pero con valor no óptimo: {value} - {details['description']}{Style.RESET_ALL}")

def analyze_cookies(cookies):
    """Analiza las cookies en busca de configuraciones inseguras."""
    print(f"\n{Fore.GREEN}=== Análisis de Cookies ==={Style.RESET_ALL}")
    if not cookies:
        print(f"{Fore.YELLOW}[~] No se encontraron cookies.{Style.RESET_ALL}")
        return

    for cookie in cookies:
        print(f"\n{Fore.CYAN}[*] Cookie: {cookie.name}{Style.RESET_ALL}")
        if not cookie.secure:
            print(f"{Fore.RED}[!] Cookie sin atributo 'Secure' - Puede ser transmitida sobre HTTP.{Style.RESET_ALL}")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            print(f"{Fore.RED}[!] Cookie sin atributo 'HttpOnly' - Accesible mediante JavaScript.{Style.RESET_ALL}")

def check_ssl_certificate(domain):
    """Verifica la validez del certificado SSL/TLS."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                print(f"\n{Fore.GREEN}=== Información del Certificado SSL/TLS ==={Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] Certificado válido para: {cert['subject']}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] Emitido por: {cert['issuer']}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[+] Válido desde: {cert['notBefore']} hasta: {cert['notAfter']}{Style.RESET_ALL}")
    except ssl.SSLError as e:
        print(f"{Fore.RED}[!] Error en el certificado SSL/TLS: {e}{Style.RESET_ALL}")
    except socket.error as e:
        print(f"{Fore.RED}[!] Error de conexión: {e}{Style.RESET_ALL}")

def check_robots_txt(url):
    """Verifica la existencia de robots.txt y pregunta si desea guardarlo."""
    robots_url = urljoin(url, "/robots.txt")
    try:
        response = requests.get(robots_url)
        if response.status_code == 200:
            print(f"\n{Fore.BLUE}Se encontró un archivo {Fore.MAGENTA}robots.txt")
            save = input(f"\n{Fore.YELLOW}[?] ¿Deseas guardar el archivo robots.txt? (S/n): {Style.RESET_ALL}").strip().lower()
            if save == "s":
                with open("robots.txt", "w") as file:
                    file.write(response.text)
                print(f"{Fore.GREEN}[+] Archivo robots.txt guardado correctamente.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[~] Archivo robots.txt no guardado.{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[~] No se encontró el archivo robots.txt.{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error al acceder a robots.txt: {e}{Style.RESET_ALL}")

def check_sitemap_xml(url):
    """Verifica la existencia de sitemap.xml y pregunta si desea guardarlo."""
    sitemap_url = urljoin(url, "/sitemap.xml")
    try:
        response = requests.get(sitemap_url)
        if response.status_code == 200:
            print(f"\n{Fore.BLUE}Se encontró un archivo {Fore.MAGENTA}sitemap.xml")
            save = input(f"\n{Fore.YELLOW}[?] ¿Deseas guardar el archivo sitemap.xml? (S/n): {Style.RESET_ALL}").strip().lower()
            if save == "s":
                with open("sitemap.xml.txt", "w") as file:
                    file.write(response.text)
                print(f"{Fore.GREEN}[+] Archivo sitemap.xml guardado correctamente.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[~] Archivo sitemap.xml no guardado.{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[~] No se encontró el archivo sitemap.xml.{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error al acceder a sitemap.xml: {e}{Style.RESET_ALL}")

def check_env(url):
    """Verifica la existencia de .env y pregunta si desea guardarlo."""
    env_url = urljoin(url, "/.env")
    try:
        response = requests.get(env_url)
        if response.status_code == 200:
            print(f"\n{Fore.BLUE}Se encontró un archivo {Fore.MAGENTA}.env")
            save = input(f"\n{Fore.YELLOW}[?] ¿Deseas guardar el archivo .env? (S/n): {Style.RESET_ALL}").strip().lower()
            if save == "s":
                with open(".env.txt", "w") as file:
                    file.write(response.text)
                print(f"{Fore.GREEN}[+] Archivo .env guardado correctamente.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[~] Archivo .env no guardado.{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[~] No se encontró el archivo .env.{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error al acceder a .env: {e}{Style.RESET_ALL}")

def check_wp_config(url):
    """Verifica la existencia de wp-config.php y pregunta si desea guardarlo."""
    wp_config_url = urljoin(url, "/wp-config.php")
    try:
        response = requests.get(wp_config_url)
        if response.status_code == 200:
            print(f"\n{Fore.BLUE}Se encontró un archivo {Fore.MAGENTA}wp-config.php")
            save = input(f"\n{Fore.YELLOW}[?] ¿Deseas guardar el archivo wp-config.php? (S/n): {Style.RESET_ALL}").strip().lower()
            if save == "s":
                with open("wp-config.php.txt", "w") as file:
                    file.write(response.text)
                print(f"{Fore.GREEN}[+] Archivo wp-config.php guardado correctamente.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[~] Archivo wp-config.php no guardado.{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[~] No se encontró el archivo wp-config.php.{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error al acceder a wp-config.php: {e}{Style.RESET_ALL}")

def check_backup_zip(url):
    """Verifica la existencia de backup.zip y pregunta si desea guardarlo."""
    backup_url = urljoin(url, "/backup.zip")
    try:
        response = requests.get(backup_url)
        if response.status_code == 200:
            print(f"\n{Fore.BLUE}Se encontró un archivo {Fore.MAGENTA}backup.zip")
            save = input(f"\n{Fore.YELLOW}[?] ¿Deseas guardar el archivo backup.zip? (S/n): {Style.RESET_ALL}").strip().lower()
            if save == "s":
                with open("backup.zip", "wb") as file:
                    file.write(response.content)
                print(f"{Fore.GREEN}[+] Archivo backup.zip guardado correctamente.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[~] Archivo backup.zip no guardado.{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[~] No se encontró el archivo backup.zip.{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error al acceder a backup.zip: {e}{Style.RESET_ALL}")

def check_security_txt(url):
    """Verifica la existencia de security.txt y pregunta si desea guardarlo."""
    security_url = urljoin(url, "/security.txt")
    try:
        response = requests.get(security_url)
        if response.status_code == 200:
            print(f"\n{Fore.BLUE}Se encontró un archivo {Fore.MAGENTA}security.txt")
            save = input(f"\n{Fore.YELLOW}[?] ¿Deseas guardar el archivo security.txt? (S/n): {Style.RESET_ALL}").strip().lower()
            if save == "s":
                with open("security.txt", "w") as file:
                    file.write(response.text)
                print(f"{Fore.GREEN}[+] Archivo security.txt guardado correctamente.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[~] Archivo security.txt no guardado.{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[~] No se encontró el archivo security.txt.{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error al acceder a security.txt: {e}{Style.RESET_ALL}")

def check_server_technologies(url):
    """Intenta identificar las tecnologías del servidor."""
    try:
        response = requests.get(url)
        server = response.headers.get("Server", "Desconocido")
        powered_by = response.headers.get("X-Powered-By", "Desconocido")
        print(f"\n{Fore.GREEN}=== Tecnologías del Servidor ==={Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Servidor: {server}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Tecnología: {powered_by}{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error al identificar tecnologías del servidor: {e}{Style.RESET_ALL}")

def mini_fuzzing_subdomains(url):
    """Realiza un mini fuzzing de subdominios utilizando un archivo de texto."""
    print(f"\n{Fore.GREEN}=== Mini Fuzzing de Subdominios ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[1] 50 subdominios más comunes")
    print(f"{Fore.YELLOW}[2] 500 subdominios más comunes")
    print(f"{Fore.YELLOW}[3] 5000 subdominios más comunes")
    choice = input(f"{Fore.BLUE}[?] Elige una opción {Fore.RED}(1, 2, 3): {Style.RESET_ALL}").strip()

    if choice == "1":
        file_name = "subdominios_50.txt"
    elif choice == "2":
        file_name = "subdominios_500.txt"
    elif choice == "3":
        file_name = "subdominios_5000.txt"
    else:
        print(f"{Fore.RED}[!] Opción no válida.{Style.RESET_ALL}")
        return

    try:
        with open(file_name, "r") as file:
            subdomains = file.read().splitlines()
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Archivo {file_name} no encontrado.{Style.RESET_ALL}")
        return

    for subdomain in subdomains:
        test_url = f"https://{subdomain}.{url}"
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                print(f"{Fore.GREEN}[+] Subdominio encontrado: {test_url}{Style.RESET_ALL}")
        except requests.exceptions.RequestException:
            pass

def mini_fuzzing_paths(url):
    """Realiza un mini fuzzing de rutas utilizando un archivo de texto."""
    print(f"\n{Fore.GREEN}=== Mini Fuzzing de Rutas ==={Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[1] 50 rutas más comunes")
    print(f"{Fore.YELLOW}[2] 500 rutas más comunes")
    print(f"{Fore.YELLOW}[3] 5000 rutas más comunes")
    choice = input(f"{Fore.BLUE}[?] Elige una opción {Fore.RED}(1, 2, 3): {Style.RESET_ALL}").strip()

    if choice == "1":
        file_name = "rutas_50.txt"
    elif choice == "2":
        file_name = "rutas_500.txt"
    elif choice == "3":
        file_name = "rutas_5000.txt"
    else:
        print(f"{Fore.RED}[!] Opción no válida.{Style.RESET_ALL}")
        return

    try:
        with open(file_name, "r") as file:
            paths = file.read().splitlines()
    except FileNotFoundError:
        print(f"{Fore.RED}[!] Archivo {file_name} no encontrado.{Style.RESET_ALL}")
        return

    for path in paths:
        test_url = f"{url}/{path}"
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                print(f"{Fore.GREEN}[+] Ruta encontrada: {test_url}{Style.RESET_ALL}")
        except requests.exceptions.RequestException:
            pass

def check_login_path_sql_injection(url):
    """
    Verifica si un path de login es vulnerable a inyección SQL.
    """
    # Lista de paths de login comunes
    login_paths = ["wp-login.php", "login", "admin/login", "user/login", "admin"]

    print(f"\n{Fore.GREEN}=== Verificación de Vulnerabilidad SQL en Paths de Login ==={Style.RESET_ALL}")

    for path in login_paths:
        test_url = f"{url}/{path}"
        print(f"{Fore.CYAN}[*] Probando: {test_url}{Style.RESET_ALL}")

        # Payload básico de SQL Injection
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR '1'='1' /*",
        ]

        for payload in payloads:
            try:
                # Envía el payload en el campo de usuario y contraseña
                data = {
                    "username": payload,
                    "password": payload,
                }
                response = requests.post(test_url, data=data, timeout=5)

                # Verifica si la respuesta indica una posible vulnerabilidad
                if "error" in response.text.lower() or "sql" in response.text.lower():
                    print(f"{Fore.RED}[!] Posible vulnerabilidad SQL encontrada en: {test_url} con payload: {payload}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[~] No se detectó vulnerabilidad SQL en: {test_url} con payload: {payload}{Style.RESET_ALL}")
            except requests.exceptions.RequestException as e:
                print(f"{Fore.RED}[!] Error al probar {test_url}: {e}{Style.RESET_ALL}")

def main():
    print_banner()
    while True:
        url = input(f"\n{Fore.YELLOW}[?] Introduce la URL del sitio web (o 'salir' para terminar): {Style.RESET_ALL}").strip()
        if url.lower() == "salir":
            print(f"{Fore.CYAN}[*] Saliendo de ShadowScan...{Style.RESET_ALL}")
            break

        if not url.startswith(("http://", "https://")):
            url = "https://" + url  # Asumimos HTTPS por defecto

        headers, final_url, cookies, status_code = get_headers(url)
        if headers:
            print(f"\n{Fore.CYAN}[*] Analizando: {final_url} (Código de estado: {status_code}){Style.RESET_ALL}")
            analyze_headers(headers)
            analyze_cookies(cookies)
            domain = final_url.split("//")[1].split("/")[0]  # Extrae el dominio de la URL final
            check_ssl_certificate(domain)
            check_robots_txt(final_url)
            check_sitemap_xml(final_url)
            check_env(final_url)
            check_wp_config(final_url)
            check_backup_zip(final_url)
            check_security_txt(final_url)
            check_server_technologies(final_url)
            mini_fuzzing_subdomains(domain)
            mini_fuzzing_paths(final_url)
            check_login_path_sql_injection(final_url)

if __name__ == "__main__":
    main()