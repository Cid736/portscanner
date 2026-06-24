# portscanner

TCP port scanner for Windows written in C using Winsock2. Inspired by nmap-style output.

```
PORT       STATE      SERVICE        VERSION
---------- ---------- -------------- -------
22/tcp     open       ssh            OpenSSH_6.6.1p1
80/tcp     open       http           Apache/2.4.7 (Ubuntu)
9929/tcp   open       nping-echo     -
31337/tcp  open       elite          -

RESUMEN
Host escaneado : scanme.nmap.org
Puertos        : 4 open  0 closed  65531 filtered
Duracion       : 1834 segundos
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

The menu prompts for host, timing template, and port range:

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
| T1 Silencioso | 2000 ms | 10 | Internet, IDS evasion |
| T2 Educado | 1200 ms | 30 | Internet (recommended) |
| T3 Normal | 700 ms | 75 | Local network (recommended) |
| T4 Agresivo | 350 ms | 100 | Fast local network |

For remote (non-RFC1918) hosts the scanner automatically caps threads to 25 regardless of the chosen template, to avoid packet loss from SYN flooding the path.

## Port ranges (interactive menu)

| Option | Ports |
|---|---|
| Comunes | 1–1024 |
| Web | 80, 443, 8080, 8443 |
| Acceso remoto | 21, 22, 23, 3389, 5900 |
| Bases de datos | 1433, 3306, 5432, 6379, 27017 |
| Todos | 1–65535 |
| Un solo puerto | custom |
| Rango manual | custom |

## Legal

Only scan systems you own or have explicit written permission to test. Unauthorized port scanning may be illegal in your jurisdiction.

Public host authorized for testing: `scanme.nmap.org`

## License

MIT
