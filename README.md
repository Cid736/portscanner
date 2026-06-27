<p align="center">
  <a href="#english">🇬🇧 English</a> &nbsp;·&nbsp; <a href="#español">🇪🇸 Español</a>
</p>

---

<a name="english"></a>

# portscanner

TCP port scanner for Windows written in C using Winsock2. Inspired by nmap-style output.

```
PORT       STATE      SERVICE        VERSION
---------- ---------- -------------- -------
22/tcp     open       ssh            OpenSSH_6.6.1p1
80/tcp     open       http           Apache/2.4.7 (Ubuntu)
9929/tcp   open       nping-echo     -
31337/tcp  open       elite          -

SUMMARY
Host scanned   : scanme.nmap.org
Ports          : 4 open  0 closed  65531 filtered
Duration       : 1834 seconds
```

## Features

- Three port states: **open**, **closed**, **filtered**
- Banner grabbing with version detection: SSH, HTTP, FTP, SMTP, POP3, IMAP
- Service database with 80+ port→name mappings
- 4 timing templates (T1–T4) with auto thread-cap for remote hosts
- Multithreaded scanning with Windows threads (CreateThread)
- nmap-style column output with color coding
- Progress bar with ETA
- Interactive menu (double-click .exe) or CLI mode
- Optional results export to timestamped .txt file
- Preset port groups: Web, Remote Access, Databases

## Build

Requires [MSYS2](https://www.msys2.org/) with MinGW-w64:

```bash
gcc portscanner.c -o portscanner.exe -lws2_32
```

## Usage

### Interactive (double-click or run without args)

```
portscanner.exe
```

### CLI mode

```
portscanner.exe <host> <start_port> <end_port>
```

Examples:

```bash
portscanner.exe 192.168.1.1 1 1024
portscanner.exe scanme.nmap.org 1 65535
portscanner.exe 10.0.0.5 22 22
```

## Timing templates

| Mode | Timeout | Threads | Best for |
|---|---|---|---|
| T1 Silent | 2000 ms | 10 | Internet, IDS evasion |
| T2 Polite | 1200 ms | 30 | Internet (recommended) |
| T3 Normal | 700 ms | 75 | Local network (recommended) |
| T4 Aggressive | 350 ms | 100 | Fast local network |

For remote (non-RFC1918) hosts the scanner automatically caps threads to 25 regardless of the chosen template, to avoid packet loss from SYN flooding the path.

## Port ranges (interactive menu)

| Option | Ports |
|---|---|
| Common | 1–1024 |
| Web | 80, 443, 8080, 8443 |
| Remote access | 21, 22, 23, 3389, 5900 |
| Databases | 1433, 3306, 5432, 6379, 27017 |
| All | 1–65535 |
| Single port | custom |
| Manual range | custom |

## Legal

Only scan systems you own or have explicit written permission to test. Unauthorized port scanning may be illegal in your jurisdiction.

Public host authorized for testing: `scanme.nmap.org`

## License

MIT

## Security

Automated security reviews are powered by [Claude](https://claude.ai) (Anthropic AI) and run on every significant change to detect vulnerabilities, insecure patterns and dependency risks. Findings are tracked in [`BUGLOG.md`](BUGLOG.md).

**Last review:** 2026-06-28 (rev 2) — 1 low-severity finding patched. No buffer overflows, format string vulnerabilities, integer overflows, or memory leaks found. Winsock usage is correct throughout.

Found a vulnerability? Open an issue or contact directly.

---

<a name="español"></a>

# portscanner

Escáner de puertos TCP para Windows escrito en C con Winsock2. Inspirado en la salida de nmap.

## Características

- Tres estados de puerto: **open**, **closed**, **filtered**
- Banner grabbing con detección de versión: SSH, HTTP, FTP, SMTP, POP3, IMAP
- Base de datos de servicios con más de 80 mapeos puerto→nombre
- 4 plantillas de velocidad (T1–T4) con límite automático de hilos para hosts remotos
- Escaneo multihilo con hilos de Windows (CreateThread)
- Salida en columnas estilo nmap con colores
- Barra de progreso con ETA
- Menú interactivo (doble clic en .exe) o modo CLI
- Exportación opcional de resultados a fichero .txt con marca de tiempo
- Grupos de puertos predefinidos: Web, Acceso remoto, Bases de datos

## Compilación

Requiere [MSYS2](https://www.msys2.org/) con MinGW-w64:

```bash
gcc portscanner.c -o portscanner.exe -lws2_32
```

## Uso

### Interactivo (doble clic o sin argumentos)

```
portscanner.exe
```

### Modo CLI

```
portscanner.exe <host> <puerto_inicio> <puerto_fin>
```

## Plantillas de velocidad

| Modo | Timeout | Hilos | Recomendado para |
|---|---|---|---|
| T1 Silencioso | 2000 ms | 10 | Internet, evasión de IDS |
| T2 Educado | 1200 ms | 30 | Internet (recomendado) |
| T3 Normal | 700 ms | 75 | Red local (recomendado) |
| T4 Agresivo | 350 ms | 100 | Red local rápida |

Para hosts remotos (no RFC1918) el escáner limita automáticamente los hilos a 25, para evitar pérdida de paquetes por SYN flooding.

## Aviso legal

Solo escanea sistemas de tu propiedad o con permiso escrito explícito. El escaneo de puertos no autorizado puede ser ilegal en tu jurisdicción.

Host público autorizado para pruebas: `scanme.nmap.org`

## Seguridad

Las revisiones de seguridad automatizadas utilizan [Claude](https://claude.ai) (Anthropic AI) y se ejecutan en cada cambio significativo para detectar vulnerabilidades, patrones inseguros y riesgos en dependencias. Los hallazgos se registran en [`BUGLOG.md`](BUGLOG.md).

**Última revisión:** 2026-06-28 (rev 2) — 1 hallazgo de baja severidad parcheado. Sin buffer overflows, format string vulnerabilities, integer overflows ni memory leaks. Uso de Winsock correcto en todos los paths.

¿Encontraste una vulnerabilidad? Abre un issue o contacta directamente.
## Licencia

MIT
