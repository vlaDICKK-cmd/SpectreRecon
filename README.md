# SpectreRecon 🛡️⚙️

Modern, high-speed CLI passive OSINT and Domain Reconnaissance tool built with Python.

SpectreRecon позволяет безопасно собирать информацию о целевых доменах, проверять их сетевые конфигурации, сканировать порты и анализировать настройки безопасности веб-сервера без прямого агрессивного сканирования.

## ✨ Ключевые функции
* **Passive Subdomain Enumeration:** Сбор поддоменов из нескольких OSINT-источников (crt.sh API + резервный канал HackerTarget).
* **Smart DNS Recon:** Опрос записей A, MX, NS, TXT через шифрованные HTTPS-запросы к Google DNS API.
* **HTTP Headers Security Audit:** Парсинг веб-заголовков безопасности (HSTS, CSP, X-Frame-Options) и выявление потенциальных уязвимостей конфигурации сервера с автоматическим обходом TLS-блокировок.
* **Port Checker:** Быстрое сканирование популярных стандартных портов (FTP, SSH, Web, RDP, DB) с определением служб в многопоточном режиме.
* **IP Intelligence:** Сбор геолокационных и WHOIS данных по IP-адресу хоста.

## 🚀 Установка и запуск

1. Клонируйте этот репозиторий:
   ```bash
   git clone https://github.com/vlaDICKK-cmd/SpectreRecon.git
   cd SpectreRecon
   ```
2. Установите необходимые библиотеки:
   ```bash
   pip install -r requirements.txt
   ```
3. Запустите инструмент:
   ```bash
   python main.py
   ```

## 🛠️ Стек технологий
* **Python 3**
* **Requests**
* **Colorama**
