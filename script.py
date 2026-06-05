import socket
import sys
import argparse
from datetime import datetime
import threading
from queue import Queue

print_lock = threading.Lock()

def escanear_puerto(target, puerto):
    """Lógica central: Intenta conectar a un puerto específico."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        resultado = s.connect_ex((target, puerto))
        
        if resultado == 0:
            with print_lock:
                print(f"[+] Puerto {puerto}: ABIERTO")
        s.close()
    except (socket.timeout,OSError) as e:
        print(f"[-] Error al escanear puerto {puerto}: {e}")

def trabajador(target, cola_puertos):
    """El 'trabajador' toma puertos de la cola y los procesa."""
    while not cola_puertos.empty():
        puerto = cola_puertos.get()
        escanear_puerto(target, puerto)
        cola_puertos.task_done()

    # 1. Planificación de Argumentos de Consola
    try:
        parser = argparse.ArgumentParser(description="Escáner de puertos concurrente para auditorías.")
        parser.add_argument("-t", "--target", required=True, help="IP o dominio del objetivo")
        parser.add_argument("-p", "--ports", default="21,22,80,443,8080", help="Puertos separados por comas")
        args = parser.parse_args()
    except Exception as e:
        print(f"[!] Error al parsear argumentos: {e}")
        sys.exit()

    # 2. Resolución de DNS
    try:
        ip_objetivo = socket.gethostbyname(args.target)
    except socket.gaierror:
        print("[!] No se pudo resolver el objetivo.")
        sys.exit()

    # 3. Parsear la lista de puertos
    lista_puertos = [int(p) for p in args.ports.split(",")]

    print(f"[*] Iniciando escaneo rápido sobre: {ip_objetivo}")
    
    # 4. Estructura de Datos para los Hilos (Cola de tareas)
    cola = Queue()
    for puerto in lista_puertos:
        cola.put(puerto)

    # 5. Lanzar los hilos en paralelo (Multithreading)
    # Usamos un máximo de 10 hilos concurrentes para no saturar la red
    num_hilos = min(50, len(lista_puertos))
    for _ in range(num_hilos):
        t = threading.Thread(target=trabajador, args=(ip_objetivo, cola))
        t.daemon = True  # Permite cerrar el script con Ctrl+C limpiamente
        t.start()

    # Esperar a que todos los puertos de la cola sean procesados
    cola.join()
    print("[*] Escaneo finalizado.")

if __name__ == "__main__":
    main()