# SAFE-EXEC Protocol

Protocolo de autorización previa para ejecutar Python no confiable dentro de un sandbox E2B. Tres evaluadores separados emiten votos Ed25519; un broker independiente verifica identidad, vínculo, caducidad, duplicados y replay. El orquestador ejecuta únicamente tras validar el token firmado del broker.

## Garantías reales

- El archivo objetivo no se ejecuta durante la evaluación previa.
- Cada evaluador posee una clave privada exclusiva.
- Cada voto queda ligado a `request_id`, nonce, SHA-256, versión de política y expiración.
- El broker conserva solicitudes consumidas en SQLite, exige aprobación LOCAL y firma el token final.
- El orquestador solo recibe la clave pública del broker.
- Los bytes evaluados son exactamente los enviados a E2B; no se relee el archivo después del consenso.
- Broker y orquestador mantienen registros separados contra replay.
- Ollama, broker y evaluador local usan una red interna sin salida exterior.

Esto reduce riesgo; no demuestra tolerancia bizantina frente al compromiso del host, Docker daemon, proveedor del sandbox o dos nodos. El análisis estático y un LLM tampoco prueban que un programa sea seguro.

Para producción faltan mTLS entre servicios, claves en KMS/HSM, registro de transparencia, imágenes fijadas por digest, SBOM, escaneo de dependencias y despliegue de nodos en dominios administrativos distintos.

## Desarrollo local

```powershell
py -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[test,e2b]"
.\.venv\Scripts\pytest
.\.venv\Scripts\safe-exec scan .\samples\safe_sample.py
```

## Identidades y secretos

```powershell
.\.venv\Scripts\safe-exec-keygen .\secrets
Set-Content -NoNewline .\secrets\vt_api_key.txt "TU_CLAVE"
Set-Content -NoNewline .\secrets\e2b_api_key.txt "TU_CLAVE"
```

No añadas secretos a Git. Docker Compose los monta exclusivamente en los servicios autorizados.

## Despliegue

```powershell
docker compose up --build -d local global semantic ollama broker
docker compose --profile run run --rm orchestrator run /work/safe_sample.py
```

Antes del primer uso, descarga el modelo configurado dentro del servicio Ollama. La ejecución E2B exige una clave válida y acceso de red desde `orchestrator`.

## Política

`rules.yaml` usa el AST de Python para bloquear imports, llamadas y literales. No inventa un trace en modo `scan`. El análisis dinámico posterior puede añadirse como telemetría del sandbox, pero nunca sustituye la autorización previa.

## Estado verificado

El núcleo criptográfico y las reglas cuentan con pruebas de firma válida, firma falsificada, vínculo a otro archivo, replay y análisis AST. Docker/E2B/VirusTotal requieren servicios y credenciales externas y deben validarse en el entorno de despliegue.

## Investigación de producto

- [10 ideas, auditoría y propuesta unificada](docs/RESEARCH-TRUST-TRIAL.md)
- [Estrategia GitHub, legal y crecimiento auténtico](docs/GITHUB-LEGAL-GROWTH.md)
- [Decisión sobre una segunda repo](docs/AUDIT-DECISION.md)
