# PHPGuard-GNN (MVP)

Detección y localización de código malicioso en scripts PHP con redes neuronales de grafos.
Solo análisis estático: el código PHP nunca se ejecuta.

## Pipeline
PHP → AST (tree-sitter) → grafo (nodo = tipo AST + función sensible + banderas; aristas padre↔hijo)
→ GNN (3 capas GATv2 + pooling por atención) → probabilidad de malicioso
→ localización por nodo (atención + saliencia gradiente×entrada) → líneas sospechosas.

## Uso

Para el modelo v2 ya entrenado, con supervisión por línea y sus resultados,
consulta [`../dataset/JOINT_TRAINING.md`](../dataset/JOINT_TRAINING.md).
Los comandos de esta sección corresponden al baseline anterior.

Los datasets locales están organizados y documentados en
[`../dataset/README.md`](../dataset/README.md). Todos los comandos siguientes se
ejecutan desde la raíz del proyecto. Se requiere Python 3.13 y `uv`.

```bash
uv venv --python 3.13.12 .venv
uv pip install --python .venv/bin/python --index-strategy unsafe-best-match -r requirements.txt
# Comprobaciones con ejemplos sintéticos; no se evalúa el corpus de prueba.
.venv/bin/python -m unittest discover -s src -p 'test_*.py'
python3 dataset/test_build_corpus.py
# Preparar los 4276 grafos con particiones fijas y sin límite de archivos por repo.
.venv/bin/python src/prepare_data.py dataset/processed/php/malicious dataset/processed/php/benign dataset/processed/graphs.pt
# Entrenar 25 épocas en CPU; guardar un modelo nuevo y evaluar test al final.
.venv/bin/python src/train.py dataset/processed/graphs.pt artifacts/baseline/phpguard.pt --epochs 25
# Demo con el checkpoint anterior, conservado en src/phpguard.pt.
.venv/bin/python src/detect.py archivo.php
.venv/bin/python src/app.py     # http://localhost:5000
```

## Protocolo reproducible

La separación fija contiene 3102 archivos de entrenamiento, 382 de validación y
792 de prueba. Los repositorios y hashes son disjuntos. El vocabulario de tipos
AST se construye únicamente con entrenamiento.

Se mantiene la arquitectura original: GATv2 de 3 capas, dimensión 64, 4 cabezas
y dropout 0.2. El entrenamiento usa CPU con 4 hilos, semillas 0, algoritmos
deterministas, lotes de 16, AdamW (lr 0.002, weight decay 0.0001) y ponderación de
clases calculada solo sobre entrenamiento. Se selecciona el checkpoint con mayor
F1 de validación; los empates conservan la primera época. El umbral permanece en
0.5 (`p > 0.5`). Test se evalúa una vez al finalizar, con el checkpoint seleccionado.

El argumento `--epochs` permite cambiar el número de épocas (por defecto 25).
El preparador y el entrenador rechazan sobrescribir artefactos existentes;
para otra ejecución debe elegirse otro destino. Los datasets antiguos sin
validación deben regenerarse. No se ajustan parámetros a partir de test.

Cada ejecución guarda junto al checkpoint:

- `parameters.json`: configuración, hash del dataset y hashes del código.
- `environment.json` y `requirements.txt`: Python, plataforma y versiones instaladas.
- `manifest.csv`: ruta, repositorio, partición, etiqueta, hashes, nodos y truncamiento.
- `history.json` y `training.log`: pérdidas y métricas de validación por época.
- `test_predictions.csv`: etiqueta, probabilidad y predicción de cada archivo de test.
- `phpguard_metrics.json`: métricas finales, matriz de confusión, época seleccionada
  y comprobación de recarga. La matriz tiene filas reales y columnas predichas,
  ambas en orden `[legítimo, malicioso]`.

El nuevo checkpoint conserva las claves `state`, `vocab`, `n_types`, compatibles
con el detector. La demo sigue cargando `src/phpguard.pt`; esta ejecución no lo
sustituye. Los artefactos, el entorno virtual y los grafos quedan excluidos de Git.
La reproducibilidad exacta se comprueba en el mismo entorno CPU; no se promete
igualdad bit a bit entre versiones de librerías o máquinas diferentes.

## Baseline reproducible ejecutado — 20 de noviembre de 2026

Se completaron 25 épocas en CPU (Python 3.13.12, PyTorch 2.11.0+cpu), en unos
27,4 minutos incluyendo validación y prueba. Se seleccionó la época 10, con
F1 de validación de 1.0. La evaluación final sobre PHP-backdoors y phpMyAdmin,
792 archivos, produjo:

| Métrica de prueba | Valor |
|---|---:|
| Exactitud | 0.994949 |
| Precisión (malicioso) | 0.987261 |
| Recall (malicioso) | 0.987261 |
| F1 (malicioso) | 0.987261 |
| AUC ROC | 0.999358 |

Matriz de confusión `[legítimo, malicioso]`: `[[633, 2], [2, 155]]`.
Hay 2 falsos positivos y 2 falsos negativos. Las métricas se recalcularon desde
las 792 filas de `test_predictions.csv` y coinciden con el JSON final.

Artefactos locales:

- [Checkpoint seleccionado](../artifacts/baseline/phpguard.pt).
- [Métricas finales](../artifacts/baseline/phpguard_metrics.json).
- [Predicciones de prueba](../artifacts/baseline/test_predictions.csv).
- [Historial de validación](../artifacts/baseline/history.json).

Las cuatro pruebas del pipeline verifican vocabulario congelado, particiones,
truncamiento, entrenamiento, desempates, recarga y reproducibilidad con datos
sintéticos. La ejecución real verificó los hashes y los conteos del corpus.
No se repitió el entrenamiento completo de 25 épocas para comparar pesos.

Estos resultados corresponden a la nueva partición, con etiquetas por
procedencia y AST parciales para 891 archivos. No evalúan localización por línea
ni garantizan generalización a backdoors insertados en aplicaciones legítimas.

## Resultados históricos del MVP (repos NO vistos en entrenamiento)

Resultados históricos declarados; la nueva recolección en `dataset/` no reproduce
automáticamente los mismos archivos ni estas métricas.

- Entrenamiento: 1231 archivos · Test: 760 archivos (repos de test: PHP-backdoors, tennc/webshell, phpMyAdmin)
- Exactitud 0.950 · Precisión 0.998 · Recall 0.920 · F1 0.957 · AUC 0.999
- Localización (proxy, sin anotación humana): en 53 % de 200 webshells de test, alguna de las 3 líneas
  top contiene una función sensible o superglobal (top-1: 46.5 %). Es la parte más débil del MVP.

## Limitaciones del modelo original
- Los benignos son frameworks/CMS (WordPress, Laravel, Composer, phpMyAdmin): separar eso de webshells es más fácil
  que detectar backdoors incrustados en código legítimo. Falta un benchmark con inyecciones dentro de archivos reales.
- Solo aristas AST (sin flujo de control ni de datos); la localización no está validada con etiquetas por línea.
- Dataset construido con colecciones públicas sin revisión manual: puede haber ruido de etiquetas.

## Evolución posterior
La evaluación diagnóstica real/controlada y las comparaciones están documentadas
en [`../dataset/LOCALIZATION.md`](../dataset/LOCALIZATION.md). Los resultados
de clasificación del baseline anterior no validan por sí solos la localización.

El benchmark de inserciones, los controles y las comparaciones con reglas y
regresión logística ya están implementados. El modelo conjunto v2 añade AST
completos, enlaces léxicos definición/uso y supervisión por línea. Su F1 global es
0,8858; detectó 270/270 inserciones y 48/90 muestras maliciosas recolectadas.
Las cohortes y objetivos difieren del baseline anterior: no son una comparación
directa entre arquitecturas.

La siguiente corrección de representación distingue identidades de fuentes y
formas de llamada. Tiene pruebas, pero todavía no tiene un modelo entrenado.
Consulta la [auditoría de representación](../dataset/REPRESENTATION_AUDIT.md).
Antes de otra evaluación deben fijarse las versiones PHP objetivo y reservar
datos nuevos con familias de payload separadas entre particiones.
