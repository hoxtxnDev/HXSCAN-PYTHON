<pre align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=0,2,3,6&height=200&section=header&text=HXSCAN&fontSize=70&fontAlignY=35&desc=TCP%20Port%20Scanner%20—%20Pentesting%20Tool&descAlignY=55" />
</pre>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white" />
  <img src="https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black" />
  <img src="https://img.shields.io/badge/macOS-000000?style=for-the-badge&logo=apple&logoColor=white" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" />
</p>

<p align="center">
  <b>⚡ Escáner de puertos TCP concurrente para auditorías de ciberseguridad</b><br />
  <b>🐍 100% stdlib — 🌍 cero dependencias externas — 💻 multiplataforma</b>
</p>

---

## 🚀 Características

- 🐍 **Sin dependencias** — solo Python estándar (`socket`, `threading`, `queue`, `argparse`, `dataclasses`)
- 💻 **Multiplataforma** — funciona en Windows 🪟, Linux 🐧 y macOS 🍎
- 🧵 **Concurrente** — escaneo multihilo con pool de workers
- 🔧 **Rangos flexibles** — puertos sueltos, rangos (`8000-8100`) y combinaciones
- 🏷️ **Detección de servicios** — mapeo automático de puertos well-known (>40 servicios)
- 🌐 **Resolución DNS** — soporte para IP y dominio
- 📦 **Portátil** — un solo archivo, sin instalación, sin `pip install`

## 📥 Instalación

```bash
git clone https://github.com/hoxtxnDev/HXSCAN-PYTHON.git
cd HXSCAN-PYTHON
python hxscan.py --help
```

> ✅ No requiere `pip install` ni ningún paquete de terceros.  
> ✅ Funciona en **Windows**, **Linux** y **macOS**. Solo necesitas Python 3.10+.

## 🎯 Uso

```bash
python hxscan.py -t <target> [-p <ports>] [--threads N] [--timeout N] [-v]
```

### 📋 Argumentos

| Argumento | Descripción | Por defecto |
|-----------|-------------|-------------|
| `-t`, `--target` | 🎯 IP o dominio del objetivo (requerido) | — |
| `-p`, `--ports` | 🔌 Puertos separados por coma y/o rangos | `21,22,23,25,80,110,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,27017` |
| `--threads` | 🧵 Número máximo de hilos concurrentes | `50` |
| `--timeout` | ⏱️ Timeout de conexión en segundos | `1.0` |
| `-v`, `--verbose` | 📢 Salida diagnóstica adicional | `False` |
| `-h`, `--help` | ❓ Muestra la ayuda | — |

### 💡 Ejemplos

```bash
# 🔍 Escaneo rápido de puertos comunes
python hxscan.py -t 192.168.1.1

# 🔌 Puertos específicos
python hxscan.py -t scanme.nmap.org -p 22,80,443

# 📡 Rango de puertos
python hxscan.py -t 10.0.0.1 -p 8000-8100

# 🔗 Mixto: puertos sueltos + rangos
python hxscan.py -t ejemplo.com -p "22,80,443,8000-8100"

# ⚡ Escaneo masivo con 100 hilos y timeout de 0.5s
python hxscan.py -t target.local -p 1-65535 --threads 100 --timeout 0.5 -v
```

## 🧠 ¿Cómo funciona?

### 1️⃣ 🌐 Resolución de objetivo

```
dominio → socket.gethostbyname() → IP
```

Si el DNS falla, el programa termina con código `1`.

### 2️⃣ 🔧 Procesamiento de puertos

```
"22,80,8000-8003"  →  [22, 80, 8000, 8001, 8002, 8003]
```

1. Se divide por comas → tokens
2. Los tokens con `-` se expanden a rangos
3. Se eliminan duplicados y se ordenan

### 3️⃣ 🧵 Escaneo concurrente

```
🧵 Hilo principal
    │
    ├── 📥 Carga todos los puertos en la Queue
    ├── 🚀 Lanza N hilos worker (daemon)
    │
    ├── 👷 Worker 1 ─── toma puerto → connect_ex() → escribe resultado
    ├── 👷 Worker 2 ─── toma puerto → connect_ex() → escribe resultado
    ├── 👷 Worker 3 ─── toma puerto → connect_ex() → escribe resultado
    │
    └── ⏳ Queue.join() espera a que se procesen todos
```

Cada worker:
1. 📥 Toma un puerto de la `Queue`
2. 🔌 Crea un socket TCP
3. ⚡ Ejecuta `connect_ex()` con timeout configurable
4. 💾 Guarda el resultado bajo un `threading.Lock`

### 4️⃣ 🏷️ Clasificación

| Estado | Significado |
|--------|-------------|
| ✅ `open` | Conexión exitosa — el puerto acepta conexiones |
| ❌ `closed` | Conexión rechazada o timeout |
| ⚠️ `error` | Excepción durante el escaneo |

Los puertos abiertos se enriquecen automáticamente con el nombre del servicio probable.

### 5️⃣ 📊 Reporte final

```
==================================================
📋 Scan Report — 127.0.0.1
==================================================

Port     State      Service
-----------------------------------
22       open       SSH
80       open       HTTP
443      open       HTTPS

📊 Scanned: 50 port(s) | Open: 3
==================================================
```

## 🔢 Códigos de salida

| Código | Significado |
|--------|-------------|
| ✅ `0` | Se encontraron puertos abiertos |
| ❌ `1` | Error (argumentos inválidos, DNS falló, etc.) |
| 📭 `2` | Escaneo completado, ningún puerto abierto |
| 🛑 `130` | Interrupción por usuario (Ctrl+C) |

## 🏗️ Arquitectura

```
📁 hxscan.py
├── 📦 ScanResult          # Dataclass: puerto, estado, servicio
├── 🏭 PortScanner         # Clase principal con toda la lógica encapsulada
│   ├── 🔍 _scan_port()    # Sonda TCP individual (context manager)
│   ├── 👷 _worker()       # Consumidor de la cola (hilo daemon)
│   └── 🎯 scan()          # Punto de entrada del escaneo concurrente
├── 🔧 _parse_port_spec()  # Parseo de puertos con soporte de rangos
├── 🌐 _resolve_target()   # Resolución DNS
└── 🚀 main()              # CLI entry point + manejo de KeyboardInterrupt
```

### 🛡️ Principios de diseño

- 🧼 **Sin estado mutable global** — todo el estado vive en la instancia de `PortScanner`
- 🔒 **Thread-safe** — `Queue` para distribución de trabajo + `threading.Lock` para escritura de resultados
- 📐 **Context managers** — todos los sockets usan `with socket.socket(...)`
- 🏷️ **Tipado estático** — anotaciones de tipo en todas las funciones y métodos públicos
- ⏳ **Sin busy-wait** — sincronización vía `Queue.join()`
- 🚫 **Sin `except` desnudo** — todas las excepciones están tipadas

## 📋 Servicios conocidos

El scanner incluye un mapa integrado de >40 puertos well-known para identificar servicios como SSH, HTTP, HTTPS, MySQL, RDP, PostgreSQL, etc.

---

<p align="center">
  🐍 <b>HXSCAN</b> — Desarrollado por <a href="https://github.com/hoxtxnDev">@hoxtxnDev</a><br />
  <sub>🛡️ Auditorías de ciberseguridad freelance y corporativas</sub>
</p>

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=0,2,3,6&height=120&section=footer" />
</p>
