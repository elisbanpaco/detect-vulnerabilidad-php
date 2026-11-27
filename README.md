# PHPGuard-GNN

Proyecto experimental de detección y localización de código malicioso PHP mediante
grafos AST y redes GATv2. El análisis es estático: PHP nunca se ejecuta.
El entrenamiento conjunto v2 está completado. El extractor experimental de la
siguiente representación tiene pruebas, pero no hay un modelo v3 entrenado.

## Comando PHP y paquete Composer experimental

Requiere PHP CLI >=8.2 con `proc_open`, Python 3.13 y las dependencias de
`requirements.txt`. Composer distribuye el comando y los pesos; no instala Python
ni PyTorch. El paquete incluye `models/joint-v2.pt`, procedente de la ejecución
del 27 de noviembre de 2026, y verifica su SHA-256 antes de cargarlo. Esa ejecución
reprodujo exactamente el checkpoint anterior; no es una mejora de precisión.

Desde este repositorio, después de instalar las dependencias Python:

```bash
printf '%s\n' '<?php' 'echo 123;' > /tmp/phpguard-ejemplo.php
php bin/phpguard /tmp/phpguard-ejemplo.php
echo "Código de salida: $?"
```

Este ejemplo inocuo puede producir una falsa alarma con el modelo actual. El
resultado es JSON. Los códigos son `0` = `SIN_INDICIOS`, `1` = `SOSPECHOSO`,
`2` = error o `NO_ANALIZABLE`. Los archivos mayores de 200000 bytes, sin apertura
PHP o con errores de parseo no reciben clasificación. El puente PHP limita cada
ejecución a 120 segundos. No se ejecuta el archivo inspeccionado ni se modifica.
`SIN_INDICIOS` no certifica seguridad; las puntuaciones no están calibradas.

Para instalar localmente desde otro proyecto PHP o Laravel, sin publicar todavía,
añade a su `composer.json` (conservando las demás propiedades) el repositorio:

```json
"repositories": [
    {
        "type": "path",
        "url": "/ruta/real/al/repositorio/app-detect-vulnerabilidad-php",
        "options": {"symlink": true}
    }
]
```

Reemplaza esa ruta por la ubicación real de este repositorio. Desde ese proyecto:

```bash
composer require 'elisbanpaco/phpguard:@dev'
```

Configura una ruta absoluta al intérprete donde instalaste las dependencias y
analiza un archivo existente del proyecto:

```bash
export PHPGUARD_PYTHON="/ruta/real/al/repositorio/app-detect-vulnerabilidad-php/.venv/bin/python"
vendor/bin/phpguard archivo.php
```

`PHPGUARD_PYTHON` debe contener solo el ejecutable, sin argumentos. Si se omite,
el comando usa `.venv/bin/python` dentro del paquete cuando existe, o `python3`
del PATH. Se pasan argumentos directamente al proceso, sin un shell. No requiere
un ServiceProvider ni Artisan para funcionar dentro de Laravel. Esta versión
procesa un archivo por invocación; no implementa escaneo recursivo de proyectos.
Solo se comprobó en Linux; Windows aún no está validado.

Antes de publicar en Packagist deben resolverse las condiciones de distribución
del modelo, confirmar disponibilidad del nombre
`elisbanpaco/phpguard`, versionar los archivos nuevos (incluidos los pesos) y crear
una etiqueta. No se ha publicado el paquete. El corpus, los entornos y los
artefactos de investigación se excluyen de los archivos de distribución.
Consulta `models/README.md` y `models/manifest.json` para conocer las limitaciones
y procedencia del checkpoint incluido.

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
su licencia y los avisos que correspondan. No se ha publicado el paquete.

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
