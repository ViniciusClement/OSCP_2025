import socket
import subprocess
import threading
import time

REDE = "192.168.0"
PORTAS = [80, 443, 22, 21, 23, 8080, 8443]  # reduzida por brevidade, você pode colar a lista completa
MAX_HOST_THREADS = 10
MAX_PORT_THREADS = 20
HOSTS_ATIVOS = "hosts_ativos.txt"
RESULTADOS = "resultado_enum.txt"

open(HOSTS_ATIVOS, 'w').close()
open(RESULTADOS, 'w').close()

host_lock = threading.Semaphore(MAX_HOST_THREADS)
port_lock = threading.Semaphore(MAX_PORT_THREADS)


def banner_grab(host, port):
    try:
        s = socket.create_connection((host, port), timeout=1)
        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = s.recv(1024).decode(errors='ignore').split('\r\n')[0]
        s.close()
        return data
    except:
        return ""


def scan_porta(host, port):
    with port_lock:
        try:
            sock = socket.socket()
            sock.settimeout(1)
            sock.connect((host, port))
            banner = banner_grab(host, port)
            with open(RESULTADOS, "a") as f:
                f.write(f"    Porta {port} aberta - {banner}\n")
            sock.close()
        except:
            pass


def scan_host(host):
    with open(RESULTADOS, "a") as f:
        f.write(f"\n[+] Verificando {host}\n")
    threads = []
    for port in PORTAS:
        t = threading.Thread(target=scan_porta, args=(host, port))
        threads.append(t)
        t.start()
        if len(threads) >= MAX_PORT_THREADS:
            [x.join() for x in threads]
            threads = []
    [x.join() for x in threads]


def check_host(ip):
    with host_lock:
        if subprocess.call(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
            with open(HOSTS_ATIVOS, "a") as f:
                f.write(ip + "\n")


# Detecta hosts ativos
threads = []
for i in range(1, 255):
    ip = f"{REDE}.{i}"
    t = threading.Thread(target=check_host, args=(ip,))
    threads.append(t)
    t.start()
    if len(threads) >= MAX_HOST_THREADS:
        [x.join() for x in threads]
        threads = []
[x.join() for x in threads]

print("[*] Hosts ativos encontrados:")
with open(HOSTS_ATIVOS) as f:
    for line in f:
        print(line.strip())

# Escaneia os hosts
with open(HOSTS_ATIVOS) as f:
    hosts = [line.strip() for line in f]

scan_threads = []
for host in hosts:
    t = threading.Thread(target=scan_host, args=(host,))
    scan_threads.append(t)
    t.start()
    if len(scan_threads) >= MAX_HOST_THREADS:
        [x.join() for x in scan_threads]
        scan_threads = []
[x.join() for x in scan_threads]

print(f"[*] Varredura finalizada. Resultados em '{RESULTADOS}'")
