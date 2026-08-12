# Cuestionamiento, investigación y conclusión

Fecha de corte: 2026-08-12.

## Cuestionamiento

¿Cómo puede una persona probar una herramienta nueva sin confiar ciegamente en su autor, instalarla con permisos excesivos o entregar código y secretos a terceros, y cómo puede un desarrollador demostrar seguridad sin pedir al usuario que crea en afirmaciones comerciales?

Hipótesis: el problema no se resuelve con una puntuación única ni con otro sandbox aislado. Se resuelve con una prueba progresiva que muestra qué pretende hacer la herramienta, qué hizo realmente, qué cambió, qué datos salieron y cómo revertirlo; todo ligado criptográficamente a los bytes ejecutados.

## Investigación

### Evidencia de necesidad

- NIST AI RMF trata la confianza como combinación de validez, seguridad, resiliencia, transparencia, privacidad y responsabilidad; ninguna característica aislada garantiza confianza.
- GitHub Dependency Review analiza cambios de dependencias y permite políticas de vulnerabilidades y licencias, pero opera principalmente en pull requests.
- OpenSSF Scorecard ayuda a valorar la postura de seguridad de proyectos, no el comportamiento de una ejecución concreta.
- Sigstore e in-toto aportan firmas, identidad, procedencia y atestaciones, pero no explican por sí solos el riesgo de probar una herramienta a una persona no experta.
- Kubernetes Agent Sandbox confirma que ejecutar código no confiable de agentes es una categoría activa; competir solamente como sandbox tendría diferenciación baja.

Fuentes:

- https://www.nist.gov/itl/ai-risk-management-framework/ai-risk-management-framework-faqs
- https://docs.github.com/en/code-security/concepts/supply-chain-security/dependency-review
- https://openssf.org/scorecard/
- https://docs.sigstore.dev/policy-controller/overview/
- https://in-toto.io/docs/specs/
- https://agent-sandbox.sigs.k8s.io/

### Diez ideas

#### 1. Prueba sin instalación

Ejecutar la herramienta en un entorno desechable remoto antes de tocar el equipo. Entregar salida, límites y evidencia. Reduce el miedo inicial, pero necesita una experiencia más comprensible que una consola.

#### 2. Recibo de confianza firmado

Emitir un recibo verificable por ejecución: hash, versión, políticas, votos, permisos observados, destinos de red, cambios y resultado. Permite al desarrollador demostrar y al usuario comprobar.

#### 3. Diferencial de permisos

Traducir código y configuración a preguntas concretas: “leerá estas carpetas”, “contactará estos dominios”, “creará estos procesos”. Comparar permisos declarados con observados.

#### 4. Cápsula reversible

Capturar cambios de archivos, configuración y estado; producir una restauración verificable. La reversibilidad debe ser estructural y ensayada, no una promesa de marketing.

#### 5. Manifiesto de confianza portátil

Definir `trust.yaml`: capacidades solicitadas, dominios, rutas, secretos, duración, outputs y acciones irreversibles. El manifiesto sería legible por humanos y herramientas.

#### 6. Proxy sin secretos

La herramienta nunca recibe credenciales principales. Solicita capacidades breves, limitadas a recurso y acción, revocables y registradas. Es valioso, pero exige integraciones específicas.

#### 7. Vista de radio de impacto

Antes de probar, mostrar dependencias, scripts de instalación, hooks, procesos, red y archivos afectados. Une supply-chain con comportamiento esperado.

#### 8. Modo clínica para mantenedores

El autor sube una versión candidata y recibe una explicación de bloqueos, correcciones mínimas y un paquete de evidencia publicable. Convierte seguridad en ayuda, no solo rechazo.

#### 9. Testimonio comunitario verificable

Usuarios pueden publicar recibos firmados y reproducibles, sin puntuar por popularidad ni recolectar telemetría personal. La confianza procede de resultados repetibles, no de estrellas.

#### 10. Bot de admisión para PR y release

GitHub App que comenta un resumen de permisos y evidencia, compara contra la versión anterior y bloquea releases cuando aumenta el riesgo sin aprobación explícita.

### Auditoría comparativa

Escala 1-5. Puntuación ponderada: dolor 20%, diferenciación 15%, viabilidad 15%, evidencia verificable 15%, encaje GitHub 15%, privacidad/legal 10%, mantenimiento 10%.

| Idea | Dolor | Dif. | Viab. | Evid. | GitHub | Legal | Mant. | Total /100 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Recibo firmado | 5 | 4 | 5 | 5 | 5 | 5 | 4 | 95 |
| Diferencial de permisos | 5 | 5 | 4 | 5 | 5 | 5 | 3 | 93 |
| Prueba sin instalación | 5 | 3 | 4 | 5 | 4 | 4 | 3 | 82 |
| Manifiesto portátil | 4 | 5 | 4 | 5 | 5 | 5 | 3 | 89 |
| Cápsula reversible | 5 | 4 | 3 | 5 | 3 | 4 | 2 | 77 |
| Vista de impacto | 4 | 4 | 4 | 4 | 5 | 5 | 3 | 83 |
| Clínica de mantenedores | 4 | 4 | 4 | 4 | 5 | 5 | 4 | 85 |
| Bot PR/release | 4 | 3 | 5 | 4 | 5 | 4 | 4 | 83 |
| Proxy sin secretos | 5 | 4 | 2 | 5 | 3 | 4 | 2 | 74 |
| Testimonio verificable | 3 | 5 | 3 | 4 | 5 | 3 | 3 | 75 |

Las cifras son una priorización razonada, no resultados de mercado. Deben sustituirse por entrevistas, pruebas de uso y métricas públicas.

### Debilidades comunes

- Una firma demuestra origen e integridad, no seguridad.
- Un sandbox limita consecuencias, no interpreta intención.
- Un LLM puede sufrir prompt injection o aprobar código ofuscado.
- Una puntuación pública puede convertirse en reputación falsa o incentivo para manipulación.
- La reversión no cubre efectos externos como correos, pagos o publicaciones.
- Subir código privado a servicios de análisis puede violar confidencialidad.
- Un host compartido sigue siendo dominio común de fallo.
- La UX puede esconder incertidumbre detrás de un color verde.

## Unificación

Nombre funcional: **SAFE-EXEC Trust Trial**.

No es otro antivirus ni otro sandbox. Es un protocolo de prueba progresiva:

1. `trust.yaml` declara capacidades y límites.
2. Un análisis previo produce el diferencial de permisos y radio de impacto.
3. Evaluadores independientes firman evidencia ligada al hash.
4. La herramienta se prueba sin instalación en un entorno desechable.
5. Se registra comportamiento real y discrepancias con lo declarado.
6. Se emite un recibo firmado, legible y verificable.
7. El usuario decide instalar, rechazar o pedir una versión con menos permisos.
8. El mantenedor recibe correcciones concretas y evidencia para su release.

### MVP que merece construirse

- Python y repositorios públicos, sin binarios nativos.
- CLI local y GitHub Action.
- `trust.yaml` versión 0.1.
- Análisis AST, dependencias, scripts y permisos declarados.
- Sandbox remoto sin secretos y con red denegada por defecto.
- Recibo JSON DSSE/in-toto más resumen HTML.
- Comparación entre dos releases.
- Ninguna puntuación universal “seguro/inseguro”; mostrar evidencia, incertidumbre y política aplicada.

### Puertas para una repo de producto independiente

No existe certeza superior al 100%. Se recomienda separar una nueva repo solo cuando se cumplan todas:

1. 20 entrevistas: al menos 12 confirman haber evitado probar una herramienta por desconfianza.
2. 10 mantenedores aceptan generar un recibo para una release.
3. 30 repositorios evaluados con menos de 10% de bloqueos falsos críticos.
4. Reproducción determinista del recibo en 90% de muestras compatibles.
5. Ninguna fuga de secretos en red-team documentado.
6. Tiempo mediano inferior a 90 segundos y coste declarado.
7. Revisión externa del modelo de amenazas.
8. Nombre, licencia y tratamiento de datos resueltos.

## Conclusión

La idea tiene relevancia alta porque reduce una fricción creciente: probar software nuevo escrito o recomendado por agentes sin entregar confianza total al autor, al modelo o al sandbox. La oportunidad defendible es el **recibo de prueba comprensible y reproducible**, unido a permisos declarados, comportamiento observado y reversibilidad. El producto debe competir por claridad y verificabilidad, no por afirmar seguridad absoluta.

Recomendación: mantener la investigación en `safe-exec`, validar las ocho puertas y después decidir si SAFE-EXEC Trust Trial merece una repo propia.
