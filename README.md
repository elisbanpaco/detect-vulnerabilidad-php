# PHPGuard-GNN

Proyecto experimental de detección y localización de código malicioso PHP mediante
grafos AST y redes GATv2. El análisis es estático: PHP nunca se ejecuta.
El entrenamiento conjunto v2 está completado. El extractor experimental de la
siguiente representación tiene pruebas, pero no hay un modelo v3 entrenado.

## Comando PHP y paquete Composer experimental

La distribución autónoma v0.2.0 está en preparación. Incluye el intérprete Python,
las bibliotecas CPU y el modelo; el usuario no instala Python, uv ni PyTorch,
ni configura `PHPGUARD_PYTHON`. Requiere PHP CLI >=8.2 con `proc_open` y Linux
x86-64 con glibc. El ZIP local se construyó en glibc 2.42; no se garantiza su uso
en distribuciones anteriores. Windows, macOS, ARM y Alpine/musl no están soportados.
El entorno de construcción se registra en `runtime/build.json` del ZIP.

Después de publicar v0.2.0, desde un proyecto PHP o Laravel:

```bash
composer require elisbanpaco/phpguard:^0.2
vendor/bin/phpguard archivo.php
```

Reemplaza `archivo.php` por un archivo existente. Composer crea el comando en
`vendor/bin`; usar solo `phpguard` exige que esa carpeta esté en el PATH.
No requiere Artisan, un ServiceProvider ni un servicio remoto. El análisis se
realiza localmente y no envía el código a Internet.

El resultado es JSON. Los códigos son `0` = `SIN_INDICIOS`, `1` = `SOSPECHOSO`,
`2` = error o `NO_ANALIZABLE`. Se rechazan archivos mayores de 200000 bytes,
sin apertura PHP o con errores de parseo. El puente PHP limita cada ejecución
a 120 segundos. Se pasan argumentos directamente al proceso, sin un shell.
Solo se procesa un archivo por invocación. El archivo inspeccionado no se ejecuta
ni se modifica. `SIN_INDICIOS` no certifica seguridad; las puntuaciones no están
calibradas. Un archivo con `<?php` en la primera línea y `echo 123;` en la segunda
produce una falsa alarma conocida; el mismo programa en una sola línea no la
produce. Esa sensibilidad al formato es una limitación del modelo actual.

El modelo sigue siendo el de la ejecución del 27 de noviembre de 2026 y su
SHA-256 se verifica antes de cargarlo. Esa ejecución reprodujo exactamente el
checkpoint anterior; el empaquetado no mejora su precisión.

El archivo completo se distribuirá como un ZIP de GitHub Releases. El campo
`dist` de `composer.json` apunta al archivo de v0.2.0; todavía debe publicarse.
Los binarios grandes no se versionan en Git. Una instalación desde código fuente
(`--prefer-source`) no incluye ese motor. Para construirlo y revisar el ZIP antes
de publicar, consulta `packaging/README.md`.

Para desarrollar desde el código fuente, con las dependencias Python instaladas:

```bash
PHPGUARD_PYTHON="$PWD/.venv/bin/python" php bin/phpguard archivo.php
```

Esta variable es una alternativa para desarrollo cuando falta el motor incluido.
Si existe un motor empaquetado, tiene prioridad sobre cualquier variable antigua.

La versión v0.1.0 ya publicada mantiene su instalación manual de Python. La nueva
versión no estará disponible en Packagist hasta subir sus fuentes, etiqueta y ZIP.
El corpus y los artefactos de investigación se excluyen de la distribución.
Consulta `models/README.md` y `models/manifest.json` para conocer la procedencia y
limitaciones del modelo. Sus condiciones de distribución siguen pendientes.

## Licencia

El código propio y la documentación original están bajo la licencia MIT de
`LICENSE`, con titular `elisbanpaco` y año 2026. El campo `license` de
`composer.json` describe ese código. Se permite el uso comercial, modificación
y redistribución conservando el aviso de copyright y la licencia.

Esta licencia no cubre los pesos de `models/joint-v2.pt`, el corpus ni materiales
de terceros. Todavía no se ha establecido una licencia de distribución de los
pesos. El inventario de entrenamiento incluye fuentes MIT, GPL, CC0 y una fuente
sin licencia declarada; no se concluye que sus condiciones se transfieran
automáticamente al modelo ni que los pesos estén libres de obligaciones.
Antes de publicar el paquete con pesos debe revisarse este punto y documentarse
su licencia y los avisos que correspondan. La nueva distribución autónoma aún no se ha publicado.

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

Los datos descargados, grafos, pesos de investigación y resultados están excluidos de Git.
Un clon contiene código, inventarios, anotaciones y documentación de las fuentes;
también incluye el checkpoint de inferencia de `models/`, pero no el corpus ni
los checkpoints de `artifacts/`. Consulta las instrucciones de datos para
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
