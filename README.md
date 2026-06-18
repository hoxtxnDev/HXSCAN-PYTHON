# hxscan

Escáner de puertos TCP concurrente para auditorías de ciberseguridad.  
**100% stdlib — sin dependencias externas.**

> © 2026 **@hoxtxnDev** — Todos los derechos reservados.
> Desarrollo profesional para auditorías de ciberseguridad freelance y corporativas.

## Requisitos

- Python 3.10 o superior
- Solo módulos de la biblioteca estándar (`socket`, `threading`, `queue`, `argparse`, `dataclasses`)

## Instalación

```bash
git clone https://github.com/hoxtxnDev/HXSCAN---PYTHON.git
cd HXSCAN---PYTHON
python hxscan.py --help
```

No requiere `pip install` ni ningún paquete de terceros.

## Uso

```bash
python hxscan.py -t <target> [-p <ports>] [--threads N] [--timeout N] [-v]
```

### Argumentos

| Argumento | Descripción | Por defecto |
|---|---|---|
| `-t`, `--target` | IP o dominio del objetivo (requerido) | — |
| `-p`, `--ports` | Puertos separados por coma y/o rangos | `21,22,23,25,80,110,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,27017` |
| `--threads` | Número máximo de hilos concurrentes | `50` |
| `--timeout` | Timeout de conexión en segundos | `1.0` |
| `-v`, `--verbose` | Salida diagnóstica adicional | `False` |
| `-h`, `--help` | Muestra la ayuda | — |

### Ejemplos

```bash
# Escaneo rápido de puertos comunes
python hxscan.py -t 192.168.1.1

# Puertos específicos
python hxscan.py -t scanme.nmap.org -p 22,80,443

# Rango de puertos
python hxscan.py -t 10.0.0.1 -p 8000-8100

# Mixto: puertos sueltos + rangos
python hxscan.py -t ejemplo.com -p "22,80,443,8000-8100"

# Escaneo masivo con 100 hilos y timeout de 0.5s
python hxscan.py -t target.local -p 1-65535 --threads 100 --timeout 0.5 -v
```

## Tutorial de funcionamiento

### 1. Resolución de objetivo

Cuando ejecutas `-t scanme.nmap.org`, el scanner resuelve el nombre a una IP real usando `socket.gethostbyname()`. Si el DNS falla, el programa termina con código `1`.

### 2. Procesamiento de puertos

El argumento `-p "22,80,8000-8100"` se interpreta así:

1. Se divide por comas → tokens `["22", "80", "8000-8100"]`
2. Los tokens con `-` se expanden a rangos → `8000, 8001, ..., 8100`
3. Se eliminan duplicados y se ordenan → `[22, 80, 8000, 8001, ..., 8100]`

```
"22,80,8000-8003"  →  [22, 80, 8000, 8001, 8002, 8003]
```

### 3. Escaneo concurrente

El scanner usa una cola (`Queue`) y un grupo de hilos *worker*:

```
Hilo principal
    │
    ├── Carga todos los puertos en la Queue
    ├── Lanza N hilos worker (daemon)
    │
    ├── Worker 1 ─── toma puerto → connect_ex() → escribe resultado
    ├── Worker 2 ─── toma puerto → connect_ex() → escribe resultado
    ├── Worker 3 ─── toma puerto → connect_ex() → escribe resultado
    │
    └── Queue.join() espera a que se procesen todos
```

Cada worker:
1. Toma un puerto de la `Queue` con `get_nowait()`
2. Crea un socket TCP con `with socket.socket(...)` (context manager)
3. Llama a `connect_ex()` con timeout configurable
4. Guarda el resultado (`ScanResult`) bajo un `threading.Lock`

### 4. Clasificación de resultados

Cada puerto recibe un estado:

| Estado | Significado |
|---|---|
| `open` | Conexión exitosa — el puerto acepta conexiones |
| `closed` | Conexión rechazada o timeout — puerto cerrado o filtrado |
| `error` | Excepción durante el escaneo (red caída, etc.) |

Los puertos abiertos se enriquecen automáticamente con el nombre del servicio probable (SSH, HTTP, MySQL, etc.) usando un mapa interno de puertos well-known.

### 5. Reporte final

El scanner imprime una tabla con todos los resultados, primero los abiertos y luego el resto, más un resumen estadístico:

```
==================================================
Scan Report — 127.0.0.1
==================================================

Port     State      Service
-----------------------------------
22       open       SSH
80       open       HTTP
443      open       HTTPS

Scanned: 50 port(s) | Open: 3
==================================================
```

### 6. Código de salida

El script finaliza con un código que puede usarse en scripts shell o pipelines CI/CD para tomar decisiones automáticas.

## Códigos de salida

| Código | Significado |
|---|---|
| `0` | Se encontraron puertos abiertos |
| `1` | Error (argumentos inválidos, DNS falló, etc.) |
| `2` | Escaneo completado, ningún puerto abierto |
| `130` | Interrupción por usuario (Ctrl+C) |

## Arquitectura

```
hxscan.py
├── ScanResult          # Dataclass: puerto, estado, servicio
├── PortScanner         # Clase principal con toda la lógica encapsulada
│   ├── _scan_port()    # Sonda TCP individual (context manager)
│   ├── _worker()        # Consumidor de la cola (hilo daemon)
│   └── scan()           # Punto de entrada del escaneo concurrente
├── _parse_port_spec()   # Parseo de puertos con soporte de rangos
├── _resolve_target()    # Resolución DNS
└── main()               # CLI entry point + manejo de KeyboardInterrupt
```

### Principios de diseño

- **Sin estado mutable global** — todo el estado vive en la instancia de `PortScanner`
- **Thread-safe** — `Queue` para distribución de trabajo + `threading.Lock` para escritura de resultados
- **Context managers** — todos los sockets usan `with socket.socket(...)`
- **Tipado estático** — anotaciones de tipo en todas las funciones y métodos públicos
- **Sin busy-wait** — sincronización vía `Queue.join()`, no `thread.join()` ni sleeps
- **Sin `except` desnudo** — todas las excepciones están tipadas

## Servicios conocidos

El scanner incluye un mapa integrado de puertos bien conocidos (>40 servicios) para mostrar el nombre del servicio probable junto a cada puerto abierto (SSH, HTTP, HTTPS, MySQL, RDP, etc.).
