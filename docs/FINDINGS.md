# Informe de hallazgos (FASE 1 · diagnóstico forense)

Fecha de auditoría: 2026-11-25. Entorno de verificación: Python 3.11.2, Linux x86-64,
`cryptography 49.0.0`, `fastapi 0.165.0`, `httpx 0.28.1`, `pydantic 2.14.4`,
`PyYAML 6.0.4`, `uvicorn 0.54.0`, `pytest 9.2.0`.

## 0. Estado del repositorio al abrir la sesión

`main` en `bc53faff` contenía **un único archivo** (`.gitignore`): el commit `f2315f0f`
("emptied") vació el árbol y el PR #6 sólo añadió reglas de ignore. El contenido
funcional se recuperó, archivo por archivo, de las ramas remotas que sobrevivieron:

| Rama | Commit | Fecha | Aporta |
| --- | --- | --- | --- |
| `fix/ast-alias-followup-20261022` | `e08d7bdc` | 2026-10-27 | política AST + merge conservador en `if` (base más reciente) |
| `factory/streaming-file-hashes-20261023` | `3ae68293` | 2026-10-26 | `hash_file` por streaming, `scan --json`, tests de CLI |
| `consolidate/safe-exec-drive-gmail-20261022` | `2ecbb3bc` | 2026-10-22 | árbol completo, docs, compose, Dockerfile |

Estado reconstruido (**ANTES** de este trabajo): 35 tests verdes, build de wheel OK.

## 1. Hallazgos

### Críticos

| # | Hallazgo | Evidencia exacta | Causa raíz | Fix |
| --- | --- | --- | --- | --- |
| C1 | **El paquete instalado no funciona**: `rules.yaml` no se incluye en la distribución | `safe-exec scan` en un venv limpio → `FileNotFoundError: .../site-packages/rules.yaml` | `rules.yaml` vive en la raíz del repo y se resuelve con `Path(__file__).parents[1]`, ruta válida sólo en checkout editable | Mover las reglas a `safeexec/rules.yaml` como *package data* y resolverlas con `importlib.resources` |
| C2 | **18 de 19 evasiones de política no se detectan** | `from os import *; system('id')` → `[]`; `__import__('os').system(...)` → `[]`; `getattr(__import__('os'),'system')(...)` → `[]`; `os.__dict__['system']` → `[]`; `vars(os)['system']` → `[]`; `globals()['__builtins__']['eval']` → `[]`; `sys.modules['os'].system` → `[]`; `for f in [os.system]: f('id')` → `[]` | El analizador sólo resuelve `import`/`from`/`Assign`/`AnnAssign`/`If`; no modela *wildcard imports*, `__import__`, `importlib`, subíndices sobre `__dict__`/`vars`/`globals`/`sys.modules`, ni `for`/`with`/`except`/`lambda`/comprensiones | Motor de política reescrito: alcances, merge conservador de ramas, pliegue de literales y reglas de atributo/subíndice |
| C3 | **La frontera bytes-analizados → bytes-ejecutados no se comprueba en el sandbox** | `sandbox.py` escribe el archivo y ejecuta `python3` sin verificar el hash remoto | Confianza en la escritura remota | `sha256sum` remoto comparado con el `file_hash` antes de ejecutar; red del sandbox denegada por defecto |
| C4 | **El voto declara `confidence` y el consenso lo ignora** | `grep -n confidence safeexec/*.py` → sólo `models.py` y `service.py`; `broker.decide(...)` aprueba con `confidence=0.0` (medido) | Campo informativo, nunca consultado | Umbral mínimo de confianza en el broker (fail-closed) |
| C5 | **Recursión/Memoria no se capturan al parsear** | `ast.parse` en fuente adversarial puede lanzar `RecursionError`/`MemoryError` → 500 en `/evaluate` | `except SyntaxError` únicamente | `except (SyntaxError, ValueError, RecursionError, MemoryError)` + presupuesto de nodos AST |

### Altos

| # | Hallazgo | Evidencia | Fix |
| --- | --- | --- | --- |
| A1 | Límites de entrada ausentes en el parser de cable | `/decide` acepta `votes` de longitud arbitraria; `request_id`/`nonce`/`filename` sin cota | Validación explícita de cardinalidad y longitudes, fail-closed |
| A2 | `orchestrator.run` no comprueba que `LOCAL` esté entre los votantes del token | `verify_release` valida firma y binding, no la composición del quórum | Comprobación de defensa en profundidad `"LOCAL" in token.payload.voters` |
| A3 | Los fallos de evaluadores se descartan si hay ≥2 votos | `failures` sólo se imprime cuando `len(votes) < 2` | Los fallos se reportan siempre en la salida |
| A4 | El CLI `scan` en modo texto no emite nada al aprobar; sin `--version` | `safe-exec scan samples/safe_sample.py` → sin salida, exit 0 | Salida humana explícita, `--version`, límite de tamaño |
| A5 | BOM UTF-8 rechazado como `invalid-python` | `evaluate('\ufeffprint(1)')` → `invalid-python` | Decodificación `utf-8-sig` |
| A6 | Reglas re-parseadas en cada petición | 200 construcciones de `StaticPolicyEvaluator` = 0,10 s; `service.evaluate` instancia por request | Caché por `(ruta, mtime, tamaño)` |
| A7 | CI sólo ejecuta `compileall`; no ejecuta la suite | `.github/workflows/ci.yml` en `main` | Matriz 3.11/3.12 + pytest + `ruff` + auditoría de seguridad |

### Medios

| # | Hallazgo | Fix |
| --- | --- | --- |
| M1 | `requirements.txt` vacío (placeholder engañoso) | Eliminado; `pyproject.toml` es la fuente única |
| M2 | Metadatos de paquete incompletos (sin `authors`, `urls`, `license`, classifiers) | Completados |
| M3 | `Dockerfile` copia `rules.yaml` de la raíz e ignora datos de paquete | Reescrito (sin `rules.yaml` suelto, healthcheck, `PYTHONUNBUFFERED`) |
| M4 | Sin `SECURITY.md` pese a ser un proyecto de seguridad | Añadido con canal de advisories |
| M5 | README afirma "6 passed" con 35 reales | Corregido y atado a CI |
| M6 | Sin herramienta de auto-auditoría reproducible | `scripts/audit.py` y `scripts/bench.py` con `--help` |

### Bajos

| # | Hallazgo | Fix |
| --- | --- | --- |
| B1 | `.gitignore` perdió las reglas de artefactos generados | Unión de ambos conjuntos |
| B2 | Hallazgos no deterministas ni deduplicados | Orden `(línea, regla, detalle)` + dedupe |
| B3 | Sin límite de tamaño en `scan` (sí en `run`) | Límite común de 1 MiB configurable por reglas |

## 2. Métricas base (ANTES)

| Métrica | Valor |
| --- | --- |
| `python -m compileall` | exit 0 |
| `pytest` | 35 passed en 0,16 s |
| Instalación de wheel en venv limpio | **falla** (`FileNotFoundError`) |
| Evasiones del corpus de ataque (19) | **18 evitan el bloqueo** |
| Throughput `scan` sobre 1,08 MB | 0,9 MB/s (1,23 s) |
| RSS máximo `hash` sobre 210 MB | 37,7 MB (streaming correcto) |
| Cobertura de `service.py` / `sandbox.py` | 0 tests |
