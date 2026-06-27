# Bug Log — portscanner

No se han encontrado vulnerabilidades ni bugs significativos en la revisión automatizada de seguridad del 2026-06-25.

---

## 2026-06-28 — Revisión 2 (Auditoría profesional completa)

### [LOW] `strncpy` sin null-terminación explícita — CLI mode y modo interactivo
- **Archivo:** `portscanner.c` líneas 510 y 537
- **Descripción:** `strncpy(host, argv[1], MAX_HOST)` y `strncpy(host, buf, MAX_HOST)` no garantizan null-terminación si el source tiene exactamente `MAX_HOST` bytes. Aunque `host[MAX_HOST+1]={0}` proporciona protección por zero-init del compilador, la garantía es implícita y frágil ante futuros refactors.
- **Severidad:** BAJA (sin explotabilidad directa gracias a la inicialización del array)
- **Fix:** Añadido `host[MAX_HOST]='\0'` explícito inmediatamente tras cada `strncpy`. Defense-in-depth.

### Resultado de la auditoría
- No se encontraron buffer overflows, format string vulnerabilities, integer overflows, memory leaks, ni uso de funciones peligrosas (gets/strcpy sin bounds).
- El manejo de Winsock es correcto: `WSAStartup`/`WSACleanup` están siempre pareados, los sockets se cierran en todos los paths.
- Los buffers de banner grabbing tienen bounds correctos (`recv()` limitado a `BANNER_RAW`, `raw[got]='\0'` siempre válido).
- El input del usuario (host, rangos de puerto) está correctamente validado antes de uso.
