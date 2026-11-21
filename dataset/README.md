# Datasets PHPGuard-GNN

Recolección de fuentes públicas realizada el 20 de noviembre de 2026. Los archivos
se descargan y leen como datos: no se ejecuta PHP ni se instalan los proyectos.

## Organización

```text
dataset/
├── raw/                         # ZIP originales completos, sin modificar
├── processed/
│   ├── php/
│   │   ├── malicious/           # Etiqueta 1, una carpeta por repositorio
│   │   │   ├── php-webshells/
│   │   │   ├── PHP-backdoors/
│   │   │   └── tennc-webshell/
│   │   └── benign/              # Etiqueta 0, una carpeta por repositorio
│   │       ├── wordpress/
│   │       ├── laravel/
│   │       ├── composer/
│   │       └── phpMyAdmin/
│   └── references/              # No se mezcla con el corpus del MVP
│       ├── PHP-Webshell-Dataset/ # 2917 archivos PHP originales
│       └── mendeley-wt8m6bcwbr-v2/ # d1.csv, d2.csv y d3.csv originales
├── metadata/
│   ├── inventory.csv            # Archivos incluidos y excluidos; motivo y hashes
│   ├── summary.json             # Conteos del corpus; política de preparación de grafos
│   ├── references.json          # Inventario resumido de datasets de referencia
│   ├── reference_inventory.csv  # Hashes de PHP/CSV extraídos de las referencias
│   └── licenses-and-readmes/    # Documentación original de las fuentes
├── sources.json                 # URLs, commits/versiones, licencias y SHA-256 de ZIP
├── build_corpus.py              # Preparación local; solo biblioteca estándar
└── test_build_corpus.py         # Autocomprobación con datos sintéticos inocuos
```

`raw/` y `processed/` están excluidos de Git para evitar versionar cientos de MB
y miles de muestras. Los archivos permanecen disponibles localmente. Los hashes,
el inventario y las versiones de origen sí se pueden versionar.

## Fuentes del corpus del MVP

| Clase | Fuente | Revisión seleccionada |
|---|---|---|
| Maliciosa | [JohnTroony/php-webshells](https://github.com/JohnTroony/php-webshells) | Commit fijado en `sources.json` |
| Maliciosa | [bartblaze/PHP-backdoors](https://github.com/bartblaze/PHP-backdoors) | Commit fijado en `sources.json` |
| Maliciosa | [tennc/webshell](https://github.com/tennc/webshell) | Commit fijado en `sources.json` |
| Legítima | [WordPress/WordPress](https://github.com/WordPress/WordPress) | 6.6.2 |
| Legítima | [laravel/framework](https://github.com/laravel/framework) | v11.0.0 |
| Legítima | [composer/composer](https://github.com/composer/composer) | 2.7.9 |
| Legítima | [phpmyadmin/phpmyadmin](https://github.com/phpmyadmin/phpmyadmin) | RELEASE_5_2_1 |

Son snapshots fijos para investigación; las versiones legítimas no pretenden ser
las últimas disponibles. "Legítimo" describe la procedencia del archivo, no una
garantía de ausencia de vulnerabilidades.

Corpus preparado: **4276 archivos únicos**, con **602 maliciosos** y **3674
legítimos**. Por fuente: PHP-backdoors 157, php-webshells 104, tennc-webshell 341,
WordPress 1475, Laravel 1286, Composer 278 y phpMyAdmin 635.
Se excluyeron 24 duplicados exactos, 60 archivos por tamaño, 45 sin apertura PHP
y 312 archivos de pruebas/fixtures legítimos. No aparecieron conflictos exactos
de etiqueta. Los conteos completos están en `metadata/summary.json`.

## Datasets publicados de referencia

- [PHP-Webshell-Dataset](https://github.com/Cyc1e183/PHP-Webshell-Dataset):
  `raw/PHP-Webshell-Dataset.zip`. Se recuperó el objeto real de Git LFS y se
  verificó su SHA-256 contra el puntero. Sus 2917 archivos `.php` están también
  extraídos en `processed/references/PHP-Webshell-Dataset/`, sin su carpeta `.git`.
- [Multi-language Webshell dataset, Mendeley v2](https://data.mendeley.com/datasets/wt8m6bcwbr/2):
  `raw/mendeley-wt8m6bcwbr-v2.zip`. DOI `10.17632/wt8m6bcwbr.2`;
  autores Abdelhakim Hannousse y Salima Yahiouche; licencia CC BY 4.0.
  Se conserva el ZIP original y sus tres CSV están extraídos en
  `processed/references/mendeley-wt8m6bcwbr-v2/`.

Contenido real del ZIP de Mendeley:

| Tabla | Filas | Etiqueta `webshell` | Etiqueta `normal` | Extensiones de origen |
|---|---:|---:|---:|---|
| d1.csv | 3373 | 1962 | 1411 | PHP |
| d2.csv | 2238 | 1119 | 1119 | PHP |
| d3.csv | 6134 | 3067 | 3067 | PHP, ASP, ASPX, JSP |

Los CSV contienen características, `sourcecode`, `opcode` y `label`.
**`sourcecode` está preprocesado**: ninguna fila conserva la apertura `<?`.
No se convierte en archivos PHP ni se utiliza para entrenar el AST del MVP o
evaluar líneas originales. Las tablas pueden compartir muestras; no se suman
sus filas como si fueran ejemplos independientes.

Estos dos datasets se conservan completos, separados del corpus del MVP. Sus
muestras pueden solaparse con las colecciones originales: no deben tratarse como
un conjunto de prueba independiente sin comprobar primero los duplicados y la
procedencia. En esta recolección, **427 archivos** de PHP-Webshell-Dataset tienen
el mismo SHA-256 que una muestra del corpus del MVP.
`metadata/references.json` describe su contenido y el solapamiento
exacto con el corpus local para PHP-Webshell-Dataset; el texto preprocesado de
Mendeley no permite esa comparación directa por hash de PHP original.
El ZIP PHP-Webshell-Dataset incluye también una
carpeta `.git`; esa carpeta no es parte de las 2917 muestras.

## Criterios de preparación

1. Extensiones compatibles con el MVP: `.php`, `.php5`, `.phtml`, `.inc`.
2. Tamaño mayor que 30 y menor o igual que 200000 bytes, como `prepare_data.py`.
3. Exclusión de `.git`, `vendor`, `node_modules` y enlaces simbólicos.
4. Exclusión de carpetas `test`, `tests`, `fixtures` y `__fixtures__` en fuentes
   legítimas, para no etiquetar automáticamente sus casos de ataque como benignos.
5. Exclusión de punteros LFS y archivos sin etiqueta de apertura `<?`.
6. Exclusión de todos los candidatos cuyo SHA-256 aparezca en ambas clases.
7. Deduplicación global por SHA-256, conservando la primera aparición según el
   orden de fuentes de `sources.json` y la ruta ordenada dentro de cada ZIP.

Se preservan los bytes y las rutas relativas originales de los archivos incluidos.
El inventario registra las apariciones descartadas; los ZIP originales no se
alteran. No hay revisión manual de etiquetas ni validación sintáctica con PHP.
La deduplicación exacta no elimina variantes ofuscadas o familias similares.

## Uso desde la raíz del proyecto

El corpus ya preparado está en `processed/php/`. Para generar los grafos con las
dependencias del proyecto instaladas:

```bash
.venv/bin/python src/prepare_data.py dataset/processed/php/malicious dataset/processed/php/benign dataset/processed/graphs.pt
```

Para reconstruir el corpus desde los ZIP originales, cuando todavía no exista
`dataset/processed/php`:

```bash
python3 dataset/build_corpus.py
```

El preparador comprueba los hashes de los ZIP y rechaza sobrescribir un corpus
existente. Las URLs exactas de descarga están en `sources.json`.

Las referencias extraídas conservan los archivos originales. Si necesitas
extraerlas otra vez a un destino vacío, estos comandos omiten `.git` y `__MACOSX`:

```bash
unzip dataset/raw/PHP-Webshell-Dataset.zip '*.php' -d dataset/processed/references/PHP-Webshell-Dataset
unzip -j dataset/raw/mendeley-wt8m6bcwbr-v2.zip 'mendely data/*.csv' -d dataset/processed/references/mendeley-wt8m6bcwbr-v2
```

Autocomprobación sin PyTorch, Tree-sitter ni acceso a Internet:

```bash
python3 dataset/test_build_corpus.py
```

## Alcance de la evaluación

Esta es una recolección nueva. No reconstruye los archivos ni las métricas del
experimento histórico de 1231 archivos de entrenamiento y 760 de prueba.
`src/prepare_data.py` utiliza todos los archivos y una partición fija:

| Partición | Repositorios | Archivos | Maliciosos | Legítimos |
|---|---|---:|---:|---:|
| Entrenamiento | tennc-webshell, WordPress, Laravel | 3102 | 341 | 2761 |
| Validación | php-webshells, Composer | 382 | 104 | 278 |
| Prueba | PHP-backdoors, phpMyAdmin | 792 | 157 | 635 |

El vocabulario crece solo en entrenamiento; las otras particiones utilizan
`<unk>` para tipos desconocidos. La preparación rechaza duplicados SHA-256,
repositorios desconocidos y particiones incompletas. Junto a `graphs.pt` genera
`graphs.manifest.csv` y `graphs.summary.json`, que incluyen el número de grafos
truncados por el límite de 2500 nodos. Los errores de parseo permanecen como
nodos `ERROR`, igual que en el MVP original.

En la preparación actual se truncaron 581 grafos de entrenamiento, 123 de
validación y 187 de prueba: **891 de 4276 (20,8 %)**. Esos archivos participan
en el experimento con su AST parcial; no se afirma que todo su código haya sido
analizado por la GNN.

Separar repositorios y eliminar duplicados exactos
no garantiza independencia entre familias de webshells.

No se incluyen etiquetas humanas por línea ni se ha construido todavía un
benchmark de inyecciones en archivos legítimos. Las muestras maliciosas deben
permanecer fuera de directorios servidos por PHP.
