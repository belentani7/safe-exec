# Plan de restauración (FASE 3)

Ordenado por riesgo × impacto. Cada paso incluye su criterio de verificación
ejecutable. La columna *riesgo* describe el peligro de regresión del cambio.

| # | Cambio | Riesgo | Verificación |
| --- | --- | --- | --- |
| 1 | `safeexec/rules.yaml` como *package data* + `importlib.resources` | bajo | instalar wheel en venv limpio y ejecutar `safe-exec scan` |
| 2 | Reescribir `policy.py`: alcances, `__import__`/`importlib`, wildcard, `__dict__`/`vars`/`globals`/`sys.modules`, subíndices, pliegue de literales, merge conservador en ramas y bucles, presupuesto de nodos, resultados deterministas | alto | corpus de 19 ataques + 30 regresiones nuevas |
| 3 | `service.py`: caché de reglas, captura de `RecursionError`/`MemoryError`, límites de tamaño, fail-closed en LLM/VT | medio | tests de servicio con `TestClient` |
| 4 | `consensus.py`: umbral de confianza, `MAX_VOTES`, validación de campos | medio | tests de protocolo existentes + nuevos casos de confianza |
| 5 | `sandbox.py`: verificación de SHA-256 remoto, red denegada, `allow_internet_access=False` | medio | test con doble falso del SDK |
| 6 | `orchestrator.py`: quórum LOCAL, fallos visibles, timeouts explícitos | medio | test con transport falso de `httpx` |
| 7 | `cli.py`: salida humana, `--version`, `--json` coherente, límite de tamaño | bajo | `tests/test_cli_scan.py` extendido |
| 8 | `pyproject.toml` completo + `ruff` + `coverage` opcional | bajo | `pip install -e '.[test]'` y `ruff check` |
| 9 | CI real (matriz 3.11/3.12, pytest, ruff, `pip-audit`) | bajo | workflow válido (acción local `act` no disponible; validación YAML) |
| 10 | `scripts/audit.py`, `scripts/bench.py` con `--help` | bajo | `python scripts/audit.py --help` |
| 11 | Dockerfile/compose endurecidos, SECURITY.md, README honesto | bajo | `python -c "yaml.safe_load(...)"` sobre compose |

## Decisiones de diseño

- **Fail-closed**: cualquier ambigüedad del análisis (expresión dinámica que
  podría resolver a un símbolo restringido) produce un hallazgo, nunca un pase.
- **Sin ejecución**: el analizador jamás evalúa la entrada; sólo pliega literales
  de tipo `str`/`bytes` con `+` mediante `ast.literal_eval` sobre nodos Constantes.
- **Presupuesto**: 200 000 nodos AST y 1 MiB de fuente por archivo.
- **Comportamiento del usuario primero**: `scan` debe explicar en lenguaje llano
  qué encontró, sin dramatismo y sin falsa aprobación.
