# Estrategia GitHub, legal y crecimiento auténtico

## Cuestionamiento

¿Cómo maximizar relevancia y reconocimiento sin manipular estrellas, contribuciones, insignias ni actividad?

## Investigación

GitHub indica que los Achievements celebran eventos y acciones concretas y que la función está en vista previa. GitHub también prohíbe interacción inauténtica, abuso de ranking, estrellas o follows automatizados y actividad masiva. Por tanto, no existe una ruta legítima para “desbloquear el máximo” mediante automatización.

Fuentes:

- https://docs.github.com/en/account-and-profile/reference/profile-reference
- https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies
- https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/about-community-profiles-for-public-repositories
- https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/classifying-your-repository-with-topics

## Optimización legítima

### Relevancia del repositorio

1. Problema verificable en la primera frase del README.
2. Demo reproducible en menos de cinco minutos.
3. Recibo de ejemplo y comparación visual antes/después.
4. Roadmap gobernado por issues con criterios de aceptación.
5. Releases pequeñas, firmadas y con changelog.
6. Topics precisos, máximo recomendado menor que el límite de 20: `ai-agent-security`, `sandbox`, `software-attestation`, `supply-chain-security`, `zero-trust`, `developer-tools`, `python`.
7. `README`, `LICENSE`, `SECURITY`, `CONTRIBUTING`, código de conducta, plantillas de issue y PR.
8. CI pública para pruebas, tipos, dependencias, secretos y Scorecard.
9. Paquetes con SBOM y procedencia firmada.
10. Comparativas reproducibles frente a alternativas, sin afirmaciones comerciales imposibles.

### Reconocimientos legítimos

- Community Profile completo: señal de madurez, no un Achievement.
- OpenSSF Best Practices badge: solicitarlo cuando los criterios sean reales.
- OpenSSF Scorecard: publicar el resultado y corregir controles, sin perseguir un número mediante excepciones cosméticas.
- Developer Program Member: solo si se crea realmente la GitHub App y el titular se registra en el programa.
- Security advisory credit: únicamente mediante vulnerabilidades reales y divulgación coordinada.
- Achievements por PR, discusión o colaboración: consecuencia del trabajo comunitario auténtico, nunca objetivo automatizado.

### Acciones prohibidas o contraproducentes

- Autoestrellas, cuentas secundarias, intercambios de stars/follows.
- PR vacías, merges artificiales o discusiones fabricadas para insignias.
- Spam promocional en issues ajenas.
- Recompensas a cambio de interacción no auténtica.
- Afirmar “certificado seguro” cuando solo existe un análisis heurístico.

## Marco legal preliminar

No constituye asesoramiento jurídico.

### Licencia

No seleccionar licencia automáticamente. Para una herramienta de infraestructura, comparar Apache-2.0, que incluye concesión expresa de patentes, con MPL-2.0, que exige compartir modificaciones de archivos cubiertos. La decisión depende del modelo comercial y de contribución.

### Privacidad y confidencialidad

- Procesar localmente por defecto.
- Enviar a VirusTotal únicamente hashes; no subir código privado automáticamente.
- Mostrar destino, finalidad, retención y base jurídica antes de cualquier análisis remoto.
- No conservar código, logs o nombres de repositorio más tiempo del necesario.
- Ofrecer eliminación, exportación y modo completamente local.

### Cyber Resilience Act

La Comisión Europea indica que FOSS no monetizado normalmente queda fuera como actividad comercial, mientras fabricantes comerciales y ciertos stewards tienen obligaciones diferenciadas. Si el producto se comercializa, será necesario revisar requisitos de seguridad, documentación, gestión de vulnerabilidades y reporte.

Fuente: https://digital-strategy.ec.europa.eu/en/policies/cra-open-source

### Uso dual y divulgación

- Declarar propósito defensivo.
- No distribuir malware funcional ni automatizar ataques.
- Incluir política de uso aceptable y canal privado de vulnerabilidades.
- Seguir divulgación coordinada y safe harbor del programa afectado.

### Marca y afirmaciones

- Buscar nombre y marca antes del lanzamiento.
- Usar “evidencia de prueba” o “evaluado bajo política X”.
- Reservar “certificado”, “garantizado” y “seguro” para esquemas formales que realmente lo permitan.

## Conclusión

La máxima relevancia sostenible no procede de insignias. Procede de una demo útil, evidencia reproducible, documentación honesta, seguridad visible y contribuciones externas reales. Las insignias deben aparecer como efecto secundario de esas prácticas.
