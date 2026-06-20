import os
import sys
import socket
import threading
import requests
from urllib.parse import urlparse
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = """
  ____                 _              ____                     
 / ___| _ __   ___  __| |_ _ __ ___  |  _ \\ ___  ___ ___  _ __ 
 \\___ \\| '_ \\ / _ \\/ _` | __| '__/ _ \\ | |_) / _ \\/ __/ _ \\| '_ \\
  ___) | |_) |  __/ (_| | |_| | |  __/ |  _ <  __/ (_| (_) | | | |
 |____/| .__/ \\___|\\__,_|\\__|_|  \___| |_| \\_\\___|\\___\\___/|_| |_|
       |_|                                                      
        ⚡ Passive OSINT & Domain Intelligence Tool v2.0 ⚡
"""

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-ALT"
}

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def print_header(domain):
    clear_screen()
    print(Fore.CYAN + BANNER)
    print(f"{Fore.GREEN}[+] Рабочая цель: {domain}\n")

def clean_domain(domain):
    domain = domain.strip().replace("http://", "").replace("https://", "")
    parsed = urlparse(f"http://{domain}")
    return parsed.netloc if parsed.netloc else domain

def get_subdomains(domain):
    print(f"{Fore.BLUE}[*] Поиск субдоменов для {domain}...")
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            found = set()
            for item in data:
                names = item.get("name_value", "").split("\n")
                for name in names:
                    name = name.strip().lower()
                    if name.endswith(domain) and not name.startswith("*."):
                        found.add(name)
            if found:
                print(f"{Fore.GREEN}[+] Найдено субдоменов (crt.sh): {len(found)}")
                for sub in sorted(list(found)):
                    print(f"  {Fore.GREEN}• {sub}")
                return
    except Exception:
        pass

    try:
        fallback_url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(fallback_url, headers=headers, timeout=8)
        if response.status_code == 200 and "error" not in response.text.lower():
            lines = response.text.strip().split("\n")
            found = set()
            for line in lines:
                parts = line.split(",")
                if parts:
                    sub = parts[0].strip().lower()
                    if sub.endswith(domain):
                        found.add(sub)
            if found:
                print(f"{Fore.YELLOW}[!] crt.sh перегружен. Использован HackerTarget.")
                print(f"{Fore.GREEN}[+] Найдено субдоменов: {len(found)}")
                for sub in sorted(list(found)):
                    print(f"  {Fore.GREEN}• {sub}")
                return
    except Exception as e:
        print(f"{Fore.RED}[- ] Ошибка при подключении к базам: {str(e)}")
        return

    print(f"{Fore.RED}[- ] Не удалось найти активные субдомены.")

def get_dns_records(domain):
    print(f"{Fore.BLUE}[*] Получение DNS-записей для {domain}...")
    records = ["A", "MX", "NS", "TXT"]
    
    for rec_type in records:
        url = f"https://dns.google/resolve?name={domain}&type={rec_type}"
        try:
            response = requests.get(url, timeout=8)
            if response.status_code == 200:
                data = response.json()
                answers = data.get("Answer", [])
                print(f"\n{Fore.CYAN}[{rec_type} Records]")
                if not answers:
                    print("  Записи отсутствуют.")
                    continue
                for ans in answers:
                    print(f"  {Fore.GREEN}• {ans.get('data')}")
            else:
                print(f"{Fore.RED}[- ] Ошибка получения {rec_type} (Код: {response.status_code})")
        except Exception as e:
            print(f"{Fore.RED}[- ] Ошибка запроса к Google DNS: {str(e)}")

def analyze_headers(domain):
    print(f"{Fore.BLUE}[*] Анализ HTTP заголовков безопасности для {domain}...")
    urls = [f"https://{domain}", f"http://{domain}"]
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    
    response = None
    for url in urls:
        try:
            response = requests.get(url, headers=headers, timeout=8, allow_redirects=True)
            break
        except Exception as e:
            last_err = str(e)
            continue

    if not response:
        if "10054" in last_err or "connection aborted" in last_err.lower():
            print(f"{Fore.RED}[- ] Ошибка: Удаленный хост сбросил соединение (Connection Reset).")
            print(f"{Fore.YELLOW}[!] Веб-ресурс защищен Cloudflare или WAF, блокирующим скрипты.")
        else:
            print(f"{Fore.RED}[- ] Не удалось подключиться к серверу: {last_err}")
        return

    print(f"{Fore.GREEN}[+] Успешное подключение: {response.url}")
    print(f"{Fore.GREEN}[+] Сервер: {response.headers.get('Server', 'Скрыт/Не определен')}\n")

    sec_headers = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "Clickjacking protection",
        "X-Content-Type-Options": "MIME-sniffing protection",
        "Referrer-Policy": "Referrer leak protection"
    }

    print(f"{Fore.CYAN}[HTTP Headers Audit]")
    for h_name, desc in sec_headers.items():
        val = response.headers.get(h_name)
        if val:
            short_val = val if len(val) < 50 else val[:47] + "..."
            print(f"  {Fore.GREEN}[+] {h_name}: {short_val}")
        else:
            print(f"  {Fore.RED}[- ] {h_name} ОТСУТСТВУЕТ ({desc})")

def scan_ports(domain):
    print(f"{Fore.BLUE}[*] Запуск сканирования популярных портов для {domain}...")
    try:
        ip = socket.gethostbyname(domain)
        print(f"{Fore.GREEN}[+] IP-адрес цели: {ip}\n")
    except Exception as e:
        print(f"{Fore.RED}[- ] Не удалось разрешить домен в IP: {str(e)}")
        return

    open_ports = []
    
    def check_port(port, service):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.2)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"  {Fore.GREEN}[+] Порт {port:<5} | {service:<10} | ОТКРЫТ")
                open_ports.append(port)
            sock.close()
        except Exception:
            pass

    threads = []
    for port, service in COMMON_PORTS.items():
        t = threading.Thread(target=check_port, args=(port, service))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    if not open_ports:
        print(f"{Fore.YELLOW}[!] Все проверяемые стандартные порты закрыты или фильтруются.")
    else:
        print(f"\n{Fore.GREEN}[+] Сканирование завершено. Обнаружено открытых портов: {len(open_ports)}")

def get_ip_geo(domain):
    print(f"{Fore.BLUE}[*] Определение геолокации и WHOIS-информации для {domain}...")
    try:
        ip = socket.gethostbyname(domain)
    except Exception as e:
        print(f"{Fore.RED}[- ] Не удалось получить IP-адрес хоста: {str(e)}")
        return

    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=8)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "fail":
                print(f"{Fore.RED}[- ] Сервер API вернул ошибку анализа IP.")
                return

            print(f"\n{Fore.CYAN}[IP Intelligence & Geolocation]")
            print(f"  IP Address:   {Fore.GREEN}{ip}")
            print(f"  Страна:       {data.get('country')} ({data.get('countryCode')})")
            print(f"  Регион/Штат:  {data.get('regionName')}")
            print(f"  Город:        {data.get('city')}")
            print(f"  Провайдер:    {data.get('isp')}")
            print(f"  Организация:  {data.get('org')}")
            print(f"  ASN:          {data.get('as')}")
            print(f"  Координаты:   {data.get('lat')}, {data.get('lon')}")
        else:
            print(f"{Fore.RED}[- ] Не удалось связаться с API геолокации.")
    except Exception as e:
        print(f"{Fore.RED}[- ] Ошибка получения данных: {str(e)}")

def main():
    clear_screen()
    print(Fore.CYAN + BANNER)
    
    target = ""
    while not target:
        target = input(f"{Fore.WHITE}Введите целевой домен (например, example.com): ").strip()
    
    domain = clean_domain(target)

    while True:
        print_header(domain)
        print(f"{Fore.CYAN}--- ГЛАВНОЕ МЕНЮ РАЗВЕДКИ ---")
        print(f"  {Fore.WHITE}[1] Поиск субдоменов (crt.sh & HackerTarget)")
        print(f"  {Fore.WHITE}[2] Запрос DNS записей (A, MX, NS, TXT)")
        print(f"  {Fore.WHITE}[3] Аудит HTTP заголовков безопасности")
        print(f"  {Fore.WHITE}[4] Быстрый сканер популярных портов")
        print(f"  {Fore.WHITE}[5] IP-геолокация и WHOIS")
        print(f"  {Fore.WHITE}[6] Сменить целевой домен")
        print(f"  {Fore.RED}[0] Выход")
        
        choice = input(f"\n{Fore.WHITE}Выберите опцию (0-6): ").strip()

        if choice == "0":
            print(f"\n{Fore.YELLOW}[*] Выход из программы. До встречи!")
            break

        if choice in ["1", "2", "3", "4", "5"]:
            print_header(domain)

        if choice == "1":
            get_subdomains(domain)
        elif choice == "2":
            get_dns_records(domain)
        elif choice == "3":
            analyze_headers(domain)
        elif choice == "4":
            scan_ports(domain)
        elif choice == "5":
            get_ip_geo(domain)
        elif choice == "6":
            clear_screen()
            print(Fore.CYAN + BANNER)
            target = input(f"\n{Fore.WHITE}Введите новый домен: ").strip()
            if target:
                domain = clean_domain(target)
            continue
        else:
            print(f"{Fore.RED}[- ] Некорректный выбор. Пожалуйста, введите цифру от 0 до 6.")
            input(f"\n{Fore.YELLOW}Нажмите Enter для продолжения...")
            continue
            
        input(f"\n{Fore.YELLOW}Нажмите Enter, чтобы вернуться в меню...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Процесс прерван пользователем.")
        sys.exit(0)