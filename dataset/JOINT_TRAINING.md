# Entrenamiento conjunto v2: ejecución manual

Esta versión experimental aprende detección de archivo y localización por línea.
El baseline y su diagnóstico se conservan sin modificar. El rendimiento nuevo
solo se conocerá al terminar el entrenamiento y su evaluación.

## Lo que debes ejecutar

Desde la raíz del proyecto, con el dataset conjunto ya preparado:

```bash
.venv/bin/python src/train_joint.py --epochs 25
```

No requiere instalar dependencias nuevas. Usa CPU, cuatro hilos y un grafo por
paso para procesar archivos completos con memoria acotada al archivo actual.
Informa progreso cada 50 pasos y al cerrar cada época. La duración dependerá
del equipo y del tamaño de los grafos; no debe estimarse con el entrenamiento
anterior, que recortaba los archivos.

La ejecución terminó correctamente cuando aparecen **`FINAL`** y **`FINISHED`**.
Después comparte el contenido de:

```text
artifacts/joint/metrics.json
```

Si falla, se interrumpe o se cierra sin `FINISHED`, comparte las últimas líneas de:

```bash
tail -n 80 artifacts/joint/training.log
```

Si el fallo ocurre antes de crearse el log, comparte la salida de la terminal.
No elimines ni sobrescribas los artefactos para intentar ocultar el fallo.
El programa conserva el mejor checkpoint obtenido, pero no implementa reanudación
del optimizador. Una repetición completa requiere otro destino:

```bash
.venv/bin/python src/train_joint.py --epochs 25 --out artifacts/joint-run2
```

## Qué cambia

- **AST completo:** para archivos de hasta 200000 bytes, sin límite de 2500 nodos.
  Los archivos mayores se rechazan expresamente; no se recortan.
- **Conexiones definición/uso:** se enlaza la última asignación léxica de una
  variable con expresiones que la consumen, dentro del mismo ámbito de función
  o método. Las aristas se agregan al AST en ambas direcciones.
- **Cabeza supervisada por línea:** agrega las representaciones de nodos que
  empiezan en una línea y aprende sus etiquetas binarias. El mayor logit de línea
  determina la detección del archivo, para conservar la señal de fragmentos pequeños.
- **Pérdida conjunta:** BCE de archivo + BCE por línea en casos con anotación.
  Las muestras recolectadas sin anotación por línea solo contribuyen a detección.
  Las ponderaciones positivas se calculan exclusivamente con entrenamiento.

Los enlaces léxicos no son un análisis formal de taint: no resuelven todos los
caminos de ramas y bucles, alias, propiedades, capturas de closures ni dependencias
entre funciones. Son una aproximación explícita que debe evaluarse.

## Datos y separación

Se parte del inventario auditado. Se excluyen los grupos del diagnóstico anterior,
grupos que cruzan particiones y grupos con etiquetas incompatibles bajo la
normalización. Las variantes de una base permanecen juntas.

Las bases legítimas se seleccionan por tamaño y semilla 0, sin consultar
predicciones: 30 de WordPress y 30 de Laravel para entrenamiento, 15 de Composer
para validación y 30 nuevas de phpMyAdmin para prueba. Cada base genera 19 casos:
un original, nueve inserciones positivas y nueve controles con constantes.

Se incorporan además muestras maliciosas recolectadas: una por grupo elegible,
sin errores de parseo. Sus etiquetas son por procedencia, no por revisión humana
independiente; no se inventan objetivos por línea para ellas.

El vocabulario crece solo en entrenamiento. La preparación verifica que no
existan hashes de bytes, tokens normalizados o entradas completas a la GNN
compartidos entre particiones. Registra todos los archivos, transformaciones,
hashes, cantidades, exclusiones y tamaños en:

```text
dataset/processed/joint/manifest.json
```

Datos preparados en esta ejecución:

| Partición | Archivos | Positivos controlados | Controles constantes | Originales | Maliciosos por procedencia |
|---|---:|---:|---:|---:|---:|
| Entrenamiento | 1389 | 540 | 540 | 60 | 249 |
| Validación | 358 | 135 | 135 | 15 | 73 |
| Prueba | 660 | 270 | 270 | 30 | 90 |

Son 2407 grafos en disco (aproximadamente 587 MiB), cargados de uno en uno.
El mayor grafo de entrenamiento tiene 53796 nodos y el mayor de prueba 65383;
ninguno fue recortado. Se comprobaron los hashes de todos los archivos preparados
y la separación de grupos respecto al diagnóstico previo.

Los tres patrones controlados se comparten entre particiones: esto evalúa bases
nuevas, no familias de payload desconocidas. Tampoco es una prueba externa ciega.
La alcanzabilidad en ejecución de las inserciones no se comprueba; PHP no se ejecuta.

## Selección y evaluación

Se entrena desde cero con semilla 0, AdamW, lr 0.002, weight decay 0.0001,
dimensión 64, cuatro cabezas, tres capas GATv2 y dropout 0.2. Se usan algoritmos
deterministas en CPU y umbral fijo de 0.5.

El checkpoint se selecciona con:

```text
0.5 × F1 de validación + 0.5 × Hit@3 de extremo a extremo en validación
```

Los empates conservan la primera época. La localización se calcula solo donde
existen etiquetas conocidas; una detección fallida aporta cero a extremo a
extremo. Test se evalúa una vez al final, después de recargar el mejor checkpoint.
Se guardan métricas agregadas y conteos por tipo de caso para inspeccionar
inserciones, controles y muestras recolectadas por separado.

Esto cambia datos, cobertura, aristas y objetivo de entrenamiento conjuntamente.
Si mejora, harán falta ablaciones para atribuir la mejora a cada componente.
No se debe presentar el rendimiento de una sola semilla como robustez general.

## Archivos de salida

`artifacts/joint/` contendrá `best.pt`, `metrics.json`, `history.json`,
`test_predictions.json`, `parameters.json`, `environment.json` y `training.log`.
Los hashes del código y del dataset se guardan para detectar cambios entre
preparación y entrenamiento. El programa rechaza una salida existente.

El checkpoint v2 tiene un formato distinto del baseline. Para analizar un archivo
después de entrenar:

```bash
.venv/bin/python src/predict_joint.py archivo.php
```

La app Flask anterior sigue utilizando su modelo anterior; no se cambia
automáticamente al v2. Las puntuaciones sigmoid no están calibradas como riesgo
de producción.

## Preparación y comprobaciones

La preparación la realiza el agente antes de entregar el comando de entrenamiento.
Para reconstruir en otro destino si cambia el código:

```bash
.venv/bin/python src/prepare_joint.py --out dataset/processed/joint-run2
.venv/bin/python src/train_joint.py --dataset dataset/processed/joint-run2 --out artifacts/joint-run2
```

Pruebas sin entrenamiento largo ni evaluación anticipada del test real:

```bash
.venv/bin/python -m unittest discover -s src -p 'test_*.py' -v
```

Incluyen cobertura del final de archivos largos, aislamiento de ámbitos,
reasignaciones, gradientes de la cabeza por línea, recarga del checkpoint y un
entrenamiento pequeño de dos épocas exclusivamente con datos sintéticos.

Las 13 pruebas pasaron. También se verificó un paso de gradientes en el caso
de entrenamiento de mayor tamaño y cantidad de aristas: 53796 nodos, 110296
aristas, unos 2,53 segundos y pico observado de 1306 MiB en ese proceso. Esta
medición aislada no estima la duración completa. No se guardó un modelo ni se
evaluó el test real durante la comprobación; el registro está en
`artifacts/joint_preflight/checks.json`.
