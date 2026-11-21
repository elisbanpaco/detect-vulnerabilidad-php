# PHPGuard-GNN

Proyecto experimental de detección y localización de código malicioso PHP mediante
grafos AST y redes GATv2. El análisis es estático: PHP nunca se ejecuta.
El entrenamiento conjunto v2 está completado. El extractor experimental de la
siguiente representación tiene pruebas, pero no hay un modelo v3 entrenado.

## Estado y resultados

La prueba v2 contiene 660 archivos: 270 inserciones maliciosas, 270 controles
constantes, 30 originales legítimos y 90 muestras maliciosas recolectadas.

| Resultado de prueba v2 | Valor |
|---|---:|
| Exactitud global | 0,8758 |
| F1 de la clase maliciosa | 0,8858 |
| AUC ROC | 0,9267 |
| Inserciones maliciosas detectadas | 270/270 |
| Muestras maliciosas recolectadas detectadas | 48/90 |
| Falsos positivos entre los 300 negativos | 40/300 |
| Localización Hit@1, solo inserciones anotadas | 267/270 |
| Localización Hit@3, solo inserciones anotadas | 270/270 |

Fuente local: `artifacts/joint/metrics.json`; checkpoint seleccionado en la época
25, semilla 0. Los patrones de inserción se comparten entre particiones:
se evalúan bases nuevas, no familias de payload desconocidas. Las muestras
recolectadas tienen etiquetas por procedencia y carecen de anotaciones por línea.
El 100 % de Hit@3 no demuestra localización en webshells reales.
El test ya se utilizó para diagnosticar errores; la siguiente iteración necesita
una evaluación nueva reservada.

## Instalación y comprobaciones

Desde la raíz, con Python 3.13 y `uv` disponibles:

```bash
uv venv --python 3.13.12 .venv
uv pip install --python .venv/bin/python --index-strategy unsafe-best-match -r requirements.txt
.venv/bin/python -m unittest discover -s src -p 'test_*.py' -v
python3 dataset/test_build_corpus.py
```

Los datos descargados, grafos, pesos y resultados están excluidos de Git.
Un clon contiene código, inventarios, anotaciones y documentación de las fuentes;
no contiene el corpus ni checkpoints. Consulta las instrucciones de datos para
reconstruirlos. Los programas rechazan sobrescribir destinos existentes.

## Uso con los checkpoints locales

Con `artifacts/joint/best.pt` disponible:

```bash
.venv/bin/python src/predict_joint.py archivo.php
```

La demo Flask corresponde al modelo original y requiere `src/phpguard.pt`:

```bash
.venv/bin/python src/app.py
```

Abre `http://localhost:5000`. La demo no carga automáticamente v2 y utiliza
Cytoscape desde un CDN. Las puntuaciones no están calibradas como riesgo de
producción.

## Organización y documentación

- [Datasets: fuentes, organización, filtros y uso](dataset/README.md).
- [Modelo, entrenamiento y demo web](src/README.md).
- [Protocolo reproducible y comandos](src/README.md#protocolo-reproducible).
- [Benchmark de detección y localización: protocolo, anotaciones y comandos](dataset/LOCALIZATION.md).
- [Entrenamiento conjunto v2: protocolo, resultados y comandos](dataset/JOINT_TRAINING.md).
- [Auditoría posterior: errores de representación y compatibilidad PHP](dataset/REPRESENTATION_AUDIT.md).

El baseline anterior utiliza 3102 archivos para entrenamiento, 382 para
validación y 792 para prueba. Los artefactos locales se guardan en
`artifacts/baseline/`; el checkpoint anterior de `src/phpguard.pt` se conserva.

La cohorte v2 usa 1389/358/660 archivos, AST completos, conexiones léxicas
definición/uso y supervisión por línea. Sus datos y salidas están separados en
`dataset/processed/joint/` y `artifacts/joint/`. Son protocolos diferentes y sus
métricas no son directamente comparables. Los enlaces léxicos no constituyen un
análisis formal de taint.
