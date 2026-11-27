# Modelo experimental distribuido

`joint-v2.pt` proviene de `artifacts/joint-2026-11-27/best.pt`, época 25.
Su SHA-256 coincide con el checkpoint del entrenamiento anterior: esta ejecución
reprodujo exactamente sus pesos. `manifest.json` registra identidad, hashes,
contrato de representación y métricas. No hay un modelo v3 entrenado.

El CLI verifica este hash antes de cargar el checkpoint con `weights_only=True`.
Esto detecta discrepancias con el manifiesto; no autentica por sí solo al editor.
No sustituyas los pesos sin actualizar y evaluar el paquete completo.

La prueba mixta tiene 660 archivos: 40 falsos positivos y 42 falsos negativos.
Detectó 48/90 muestras maliciosas recolectadas y 270/270 inserciones controladas.
Los patrones de inserción se comparten entre particiones. El conjunto de prueba
ya se utilizó para diagnóstico; no es una evaluación externa ciega.

Una comprobación manual con `<?php echo 123;` produjo un falso positivo con
puntuación cercana a 0.997. `SIN_INDICIOS` tampoco garantiza ausencia de malware.
Las puntuaciones no están calibradas. Las líneas devueltas son candidatas para
revisión; no constituyen prueba de comportamiento malicioso.

Solo se analizan archivos individuales de hasta 200000 bytes. No se ejecuta PHP,
no se resuelven dependencias entre archivos ni se realiza taint formal.
Los errores de parseo se reportan como `NO_ANALIZABLE` en el CLI distribuible.

El código propio tiene licencia MIT; consulta `LICENSE` en la raíz. Esa licencia
excluye expresamente los pesos del modelo. Las condiciones de distribución de los
pesos aún no están resueltas y deben revisarse antes de publicarlos. El inventario
de fuentes de entrenamiento está en
`dataset/sources.json` del repositorio de investigación; no se distribuye el corpus
con el paquete Composer.
