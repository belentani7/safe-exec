# SAFE-EXEC

## Probar una herramienta nueva no debería exigir confianza ciega

Descubres una CLI prometedora, un script compartido en un issue o una herramienta creada por un agente. Puede ahorrarte horas. También puede pedir acceso a tus repositorios, leer variables de entorno, instalar dependencias o conectarse a destinos que no conoces.

La decisión habitual es incómoda: ejecutarla y asumir el riesgo, revisar cientos de líneas antes de empezar o abandonar una herramienta que quizá era útil.

SAFE-EXEC explora una alternativa más humana: **evaluar primero los bytes exactos, reunir evidencia independiente y autorizar una única ejecución dentro de un entorno desechable**. La meta no es declarar que algo es “seguro”. La meta es que desarrolladores y usuarios puedan tomar una decisión informada sin tener que confiar únicamente en la reputación del autor, una estrella verde o la respuesta de un modelo.

Este repositorio es un prototipo de investigación funcional. Buscamos críticas técnicas antes que adopción masiva.

## Para quién estamos construyendo primero

Empezamos por nichos pequeños donde la fricción es concreta y podemos aprender sin fingir universalidad:

- Personas que prueban scripts Python encontrados en GitHub.
- Mantenedores que quieren demostrar qué solicita realmente una nueva release.
- Equipos pequeños que revisan herramientas generadas por IA antes de incorporarlas.
- Educadores y laboratorios que necesitan experimentar sin entregar acceso al equipo personal.
- Autores de CLI que desean recibir observaciones de seguridad útiles, no solo un bloqueo opaco.

No intentamos cubrir todavía instaladores nativos, aplicaciones con interfaz, producción empresarial ni todos los lenguajes.

## La idea en una ejecución

```text
archivo Python
    │
    ├── hash + nonce + política + caducidad
    │
    ├── evaluador LOCAL ─────── firma evidencia determinista
    ├── evaluador GLOBAL ────── firma reputación disponible
    └── evaluador SEMANTIC ──── firma una segunda lectura contextual
                  │
                  ▼
          broker independiente
                  │
         token firmado de un uso
                  │
                  ▼
           sandbox desechable
```

El voto LOCAL debe aprobar y hace falta al menos otra aprobación. El orquestador comprueba el token del broker antes de enviar al sandbox exactamente los mismos bytes que fueron evaluados.

La dirección de producto va más allá del booleano aprobar/bloquear: un futuro **Trust Trial** debería explicar permisos, conexiones, cambios, incertidumbre y posibilidades de reversión mediante un recibo verificable y comprensible.

## Qué existe hoy

- Contratos canónicos para solicitudes, votos y tokens.
- Firmas Ed25519 independientes por evaluador.
- Vínculo a `request_id`, nonce, SHA-256, política y expiración.
- Protección persistente contra replay en broker y orquestador.
- Verificación del hash recibido y eliminación del cambio de archivo entre análisis y ejecución.
- Política estática basada en el AST de Python.
- Evaluadores paralelos con tolerancia a la caída de un nodo opcional.
- Integraciones preparadas para Ollama, VirusTotal y E2B.
- Separación de redes y secretos por servicio en Docker Compose.
- Pruebas contra falsificación, replay, cruce de archivos y anulación indebida del voto LOCAL.

## Qué no afirmamos

Una firma prueba quién emitió un voto y que no fue alterado; no prueba que el código sea inocuo. Un sandbox contiene parte del daño posible; no interpreta intención. Un modelo puede equivocarse o ser manipulado.

Este prototipo tampoco resiste el compromiso del host, Docker daemon, proveedor del sandbox o dos evaluadores que incluyan LOCAL. Para producción todavía hacen falta mTLS, KMS/HSM, transparencia, imágenes fijadas por digest, SBOM, límites de sandbox demostrados y nodos en dominios administrativos separados.

Preferimos que esta sección sea incómodamente honesta. La confianza empieza mostrando dónde termina la garantía.

## Probar el núcleo en menos de cinco minutos

Python 3.12 recomendado.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[test]"
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\safe-exec scan .\samples\safe_sample.py
```

El comando `scan` no ejecuta el archivo ni inventa un trace dinámico. Para integrarlo en CI se puede obtener un recibo JSON de la evaluación estática:

```bash
safe-exec scan samples/safe_sample.py --json
```

La salida incluye `schema_version: 1`, SHA-256 de los bytes inspeccionados, `allowed` y hallazgos con regla, línea y detalle. Devuelve estado 1 ante reglas bloqueadas, código Python inválido o texto que no sea UTF-8; estado 0 cuando no hay hallazgos. **`allowed: true` significa únicamente que estas reglas estáticas no encontraron problemas, no que el archivo sea seguro.** El hash permite comprobar qué versión exacta se analizó; `scan` nunca ejecuta el código.

En Linux o macOS:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m pytest
.venv/bin/safe-exec scan samples/safe_sample.py
```

## Probar la arquitectura distribuida

Genera identidades distintas y crea los dos secretos externos:

```powershell
.\.venv\Scripts\safe-exec-keygen .\secrets
Set-Content -NoNewline .\secrets\vt_api_key.txt "TU_CLAVE"
Set-Content -NoNewline .\secrets\e2b_api_key.txt "TU_CLAVE"
```

Después, con Docker disponible:

```powershell
docker compose up --build -d local global semantic ollama broker
docker compose --profile run run --rm orchestrator run /work/safe_sample.py
```

No añadas secretos a Git. Compose concede cada secreto únicamente al servicio que lo necesita.

La ejecución completa Docker/E2B/VirusTotal aún no está validada en este equipo porque Docker no está instalado y no se proporcionaron credenciales. Esa frontera está documentada deliberadamente.

## Las preguntas difíciles donde buscamos ayuda

No necesitamos un “se ve bien”. Nos sería más útil que personas con experiencia intentaran romper estas decisiones:

### Sandboxing y sistemas

- ¿Qué capacidades mínimas necesita una prueba útil sin convertir el sandbox en una salida de datos?
- ¿Cómo demostrar los límites de red, procesos y filesystem en vez de describirlos?
- ¿Qué telemetría dinámica aporta evidencia sin ejecutarse demasiado tarde para prevenir daño?

### Criptografía y atestaciones

- ¿El vínculo solicitud-voto-token cubre todos los ataques de sustitución relevantes?
- ¿Debemos migrar el formato propio a DSSE/in-toto antes del siguiente prototipo?
- ¿Dónde termina la utilidad de Ed25519 local y empieza la necesidad de identidad de workload o KMS?

### Seguridad de supply chain

- ¿Qué señales existentes de Sigstore, GitHub y OpenSSF deberíamos reutilizar en lugar de duplicar?
- ¿Cómo comparar releases sin convertir la herramienta en otro score opaco?

### Experiencia de mantenedores y usuarios

- ¿Qué tres hechos necesita una persona para decidir si prueba una CLI?
- ¿Cómo presentar incertidumbre sin alarmismo y sin regalar una aprobación falsa?
- ¿Qué evidencia estaría dispuesto un mantenedor pequeño a publicar con cada release?

### Privacidad y regulación

- ¿Qué datos deben permanecer siempre locales?
- ¿Cómo documentar retención, proveedores y finalidad de cada evaluación remota?
- ¿Qué obligaciones aparecen al convertir el prototipo abierto en servicio comercial?

## Colaborar sin ruido

La colaboración puede ser pequeña y discreta. Una revisión de un único modelo, un caso que produzca falso positivo, una nota privada sobre el threat model o una prueba reproducible ya es valiosa. No hace falta respaldar el proyecto públicamente ni comprometerse con su roadmap.

Cuando la repo se publique, organizaremos aportaciones en cuatro etiquetas: `threat-model`, `false-positive`, `sandbox-evidence` y `maintainer-ux`. Los informes que puedan revelar una vulnerabilidad no deben abrirse como issue público. Antes de publicar añadiremos `SECURITY.md` con un canal privado real; hoy ese canal todavía no existe.

La prioridad no será acumular estrellas o insignias. Será conseguir que especialistas independientes puedan decir: “probé esta parte, encontré estos límites y esta evidencia sí se reproduce”.

## Hacia SAFE-EXEC Trust Trial

La investigación identificó diez caminos y los redujo a una propuesta más enfocada:

1. Manifiesto `trust.yaml` con capacidades declaradas.
2. Diferencial de permisos y radio de impacto antes de ejecutar.
3. Prueba remota sin instalación ni secretos.
4. Comparación entre comportamiento declarado y observado.
5. Recibo firmado, reproducible y legible por humanos.
6. Recomendaciones concretas para que el mantenedor reduzca permisos.

No abriremos una repo de producto separada hasta demostrar demanda, tasa aceptable de falsos positivos, reproducibilidad, ausencia de fugas en red-team y revisión externa.

## Investigación y decisiones

- [Diez ideas, auditoría y propuesta unificada](docs/RESEARCH-TRUST-TRIAL.md)
- [Modelo de amenazas](docs/THREAT-MODEL.md)
- [Originalidad y posicionamiento](docs/ORIGINALITY-AND-POSITIONING.md)
- [Estrategia GitHub, legal y crecimiento auténtico](docs/GITHUB-LEGAL-GROWTH.md)
- [Decisión sobre una segunda repo](docs/AUDIT-DECISION.md)

## Estado del proyecto

SAFE-EXEC está en fase de prototipo validado localmente, no de producto certificado. El siguiente hito no es añadir más arquitectura: es conseguir revisiones pequeñas de personas que conocen bien un límite específico, convertirlas en pruebas y descubrir si el Trust Trial resuelve una preocupación real para mantenedores y usuarios.
