# Métricas de verificación (FASE 5)

Medido en este checkout el 2026-11-25. Entorno: Python 3.11.2, Linux x86-64,
`cryptography 49.0.0`, `fastapi 0.165.0`, `httpx 0.28.1`, `pydantic 2.14.4`,
`PyYAML 6.0.4`, `uvicorn 0.54.0`, `pytest 9.2.0`, `ruff 0.9+`.

## Build e instalación

| Comprobación | ANTES (reconstruido) | DESPUÉS |
| --- | --- | --- |
| `python -m compileall` | exit 0 | exit 0 |
| `python -m build --wheel` | OK (12 archivos) | OK (18 archivos) |
| `rules.yaml` dentro del wheel | **NO** | **SÍ** |
| `safe-exec scan` en venv limpio | **FileNotFoundError** | exit 0 / exit 1 correctos |
| `pip install` en venv limpio | instala, ejecuta roto | instala y funciona |
| Metadatos del paquete | mínimos | autores, URLs, classifiers, licencia |

## Tests

| Métrica | ANTES | DESPUÉS |
| --- | --- | --- |
| Pruebas | 35 | **216** |
| Cobertura (rama) | no medida | **90,44 %** |
| Módulos sin pruebas | `service`, `sandbox`, `orchestrator`, `keygen`, `resources` | ninguno |
| Fallos | 0 | 0 |
| Tiempo de suite | 0,16 s | 0,85 s |

Distribución: `test_policy_aliases` (24), `test_policy_evasions` (49),
`test_policy_internals` (56), `test_protocol` (6), `test_consensus_hardening` (11),
`test_service` (16), `test_sandbox` (6), `test_orchestrator` (8), `test_cli` (11),
`test_cli_scan` (3), `test_cli_streamed_hash` (2), `test_support` (22).

## Seguridad de la política estática

Corpus adversarial de 19 patrones reales contra la política por defecto:

| Métrica | ANTES | DESPUÉS |
| --- | --- | --- |
| Evasiones que pasan sin hallazgo | **18 / 19** | **0 / 19** |
| Corpus ampliado (28 patrones) | no existía | **0 evasiones** |
| Falsos positivos sobre 25 snippets legítimos | 0 | **0** |
| `audit.py` (15 evasiones + 8 legítimos) | no existía | **OK** |

Patrones cerrados: importación comodín, `__import__`, `importlib`, `getattr`
literal, `__dict__`/`vars`/`globals`/`sys.modules`, `for`/`with`/`except`/`match`,
comprensiones, atributos de clase, `lambda`, `functools.partial`, concatenación de
literales y f-strings.

## Rendimiento

| Métrica | ANTES | DESPUÉS |
| --- | --- | --- |
| Escaneo de 9,2 KB | 1,23 s / 1,08 MB (0,9 MB/s) | **8,2 ms (1,12 MB/s)** |
| Escaneo de 1,08 MB (sobre el límite) | 1,23 s, parsea entero | **0,5 ms, rechazo inmediato** |
| `hash` de 257 MB | 0,27 s, RSS 37,7 MB | **0,17 s, RSS +0,07 MB** |
| Presupuesto de nodos AST | ninguno | 400 000, falla cerrado |
| Recarga de reglas por petición | YAML en cada request | caché por `(mtime, tamaño)` |

La mejora del escaneo no viene de micro-optimizar: viene de no parsear un
megabyte de texto que la política va a rechazar de todos modos.

## Accesibilidad y calidad de CLI

| Métrica | ANTES | DESPUÉS |
| --- | --- | --- |
| `scan` aprobado en texto | sin salida | `allowed <archivo> sha256=…` |
| `scan` denegado | `regla:línea:detalle` | tabla alineada + aviso honesto en stderr |
| `--json` | presente en una rama, no en `main` | esquema estable v1, claves ordenadas |
| `--version` | ausente | `safe-exec 1.1.0` |
| `--quiet` | ausente | suprime salida en éxito |
| `--help` por subcomando | genérico | descripción + flag propio |
| Aviso de límites | en README | en stderr de cada denegación |

## Protocolo y servicios

| Comprobación | ANTES | DESPUÉS |
| --- | --- | --- |
| Confianza del voto aplicada | ignorada (aprobaba con 0.0) | umbral 0,5; LOCAL obligatorio |
| Rechazo consumido | sólo aprobaciones | también denegaciones |
| Poda del replay DB | inexistente | `prune()` por retención |
| Cota de votos | ninguna | `MAX_VOTES = 16` |
| Digest remoto verificado | no | sí, aborta antes de ejecutar |
| Red del sandbox | abierta por defecto | denegada por defecto |
| Fallo del analizador | 500 | voto firmado de denegación |
| Fallos de evaluadores | silenciados | visibles en la salida |
| `health` | `{status, role}` | añade `version` |

## Pendiente de verificación externa

Docker no está instalado en este entorno, así que `compose.yaml` se validó como
YAML y como grafo de servicios, no levantando contenedores. E2B y VirusTotal se
verificaron con dobles de prueba, no contra sus API reales. Ambas fronteras están
declaradas en `docs/THREAT-MODEL.md` y `SECURITY.md`.
