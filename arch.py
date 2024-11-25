#!/usr/bin/python3
from threading import Lock, Thread
from requests import get
from requests.exceptions import ConnectionError as hata
from requests.exceptions import MissingSchema as eksik_schema
from queue import Queue
from time import sleep
from sys import argv
import os

os.system('clear' if os.name == 'posix' else 'cls')
proxy_aktif = False
admin_panelleri = []  # Bulunan admin panelleri için liste
print("""
**************************************************

     █████╗ ██████╗  ██████╗██╗  ██╗
     █████╗ ██████╗  ██████╗██╗  ██╗
    ██╔══██╗██╔══██╗██╔════╝██║  ██║
    ███████║██████╔╝██║     ███████║
    ██╔══██║██╔══██╗██║     ██╔══██║
    ██║  ██║██║  ██║╚██████╗██║  ██║
    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝

***** ❤️ This project was coded @archescyber ******

  Usage: arch.py [OPTIONS]

  Options:
    +site <website URL>
  •• Website to scan.
    +proxy <protocol>://<proxyserverip:port>
  •• Use proxy server.
    +t <seconds>
  •• Delay for scanning.
    +w <custom/wordlist/path>
  •• Custom wordlist file for scanning.

  Examples:
   arch.py +site http://example.com
   arch.py +proxy http://1.2.3.4:8080 +site http://example.com
   arch.py +site https://example.com +t 1
   arch.py +site https://example.com +w /custom/wordlist/list.txt
""")

if len(argv) < 3 or '+site' not in argv:
    print('[<>] Which site do you want to scan...')
    exit()

gecikme = 0
dosya_ismi = 'list.txt'

if '+proxy' in argv[1:]:
    proxy_aktif = True
    proxy_protokol, proxy_sunucu = argv[argv.index('+proxy') + 1].split('://')
    print('Using Proxy - True')

if '+t' in argv[1:]:
    gecikme = int(argv[argv.index('+t') + 1])

web_siteleri = []
for arg in argv[argv.index('+site') + 1:]:
    if arg.startswith('+'):
        break
    web_siteleri.append(arg)

if '+w' in argv[1:]:
    dosya_ismi = argv[argv.index('+w') + 1]

# Dosyanın varlığını kontrol et
if not os.path.exists(dosya_ismi):
    print(f"ERROR: '{dosya_ismi}' file not found. Please ensure the file exists.")
    exit()

# Kullanılan iş parçacığı yapıları #
yazma_lock = Lock()
kuyruk = Queue()

# Proxy doğrulama fonksiyonu
def proxy_dogrula(proxy):
    try:
        get('http://example.com', proxies={'http': proxy, 'https': proxy}, timeout=5)
        return True
    except:
        return False

# Kuyruk ve İş Parçacığı kullanarak işlevi çalıştır
def is_parcacigi(web_site):
    isci = kuyruk.get()
    try:
        # Proxy kullanımı
        if proxy_aktif:
            proxy = f'{proxy_protokol}://{proxy_sunucu}'
            if not proxy_dogrula(proxy):
                print('Invalid proxy:', proxy)
                kuyruk.task_done()
                return

            r = get('{}{}'.format(web_site, isci), proxies={'http': proxy, 'https': proxy}, allow_redirects=True)
        else:
            r = get('{}{}'.format(web_site, isci))

        if r.ok:
            with yazma_lock:
                print('    [{}] Success: '.format(r.status_code), isci)
            if r.status_code == 200:  # Eğer durum kodu 200 ise
                admin_panelleri.append('{}{}'.format(web_site, isci))

        else:
            with yazma_lock:
                print('    [{}] Failed: '.format(r.status_code), isci)

    except hata:
        print('Connection Error, please check your proxy settings.')
    except eksik_schema:
        print('ERROR: Where is the URL scheme? Use http:// or https://.')
    finally:
        kuyruk.task_done()  # İşlem tamamlandığında kuyruktan çıkar

# Tarama işlemini başlat
if type(web_siteleri) is str:
    web_siteleri = [web_siteleri]

for web_site in web_siteleri:
    if web_site[-1] != '/':
        web_site = web_site + '/'

    with open(dosya_ismi, 'r') as f:
        for line in f:
            kuyruk.put(line.strip())

    print('Results for {}:'.format(web_site))

    is_parcaciklari = []
    # İş parçacığı sayısını belirle
    max_is_parcacik = 10  # Aynı anda çalışacak iş parçacığı sayısı

    while not kuyruk.empty():
        for _ in range(max_is_parcacik):
            if not kuyruk.empty():
                t = Thread(target=is_parcacigi, args=(web_site,), daemon=True)
                t.start()
                is_parcaciklari.append(t)
                sleep(gecikme)

        # İş parçacıklarının tamamlanmasını bekle
        for t in is_parcaciklari:
            t.join()

# Admin panellerini çıktı olarak göster
if admin_panelleri:
    print('\n[<>] Admin panel found:')
    for panel in admin_panelleri:
        print(panel)
else:
    print('\n[<>] ERROR: No admin panels found.')
