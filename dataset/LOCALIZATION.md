# Diagnóstico de detección y localización

Este experimento conserva los pesos del baseline y compara su detección y sus
líneas influyentes con una regla fija y una regresión logística sin aristas.
No es una prueba ciega nueva: los resultados anteriores ya se examinaron.
Solo se leen y parsean archivos; nunca se ejecuta PHP ni se consultan las URLs
contenidas en las muestras.

## Ejecutar desde la raíz

Se utiliza el entorno `.venv` y las versiones de `requirements.txt`. Antes deben
existir el corpus, `dataset/processed/graphs.pt` y el checkpoint entrenado en
`artifacts/baseline/phpguard.pt`.

```bash
.venv/bin/python -m unittest discover -s src -p 'test_*.py' -v
.venv/bin/python src/audit_corpus.py
.venv/bin/python src/build_localization.py
.venv/bin/python src/evaluate_localization.py
```

Cada etapa rechaza sobrescribir su destino. Para otro experimento, usar los
argumentos `--out`, `--audit` y `--benchmark` según corresponda. El evaluador exige
el código, dataset y checkpoint que se registraron al construir el benchmark;
una modificación requiere congelar un benchmark nuevo en otro directorio.

El detector también admite selección explícita de modelo para CLI y Flask:

```bash
PHPGUARD_CHECKPOINT=artifacts/baseline/phpguard.pt .venv/bin/python src/detect.py archivo.php
PHPGUARD_CHECKPOINT=artifacts/baseline/phpguard.pt .venv/bin/python src/app.py
```

Sin esa variable se conserva `src/phpguard.pt`. La saliencia obtiene el gradiente
respecto a las entradas, sin acumular gradientes en los parámetros del modelo.

## Auditoría y exclusiones

La auditoría compara hashes de bytes, de las entradas completas a la GNN
(`type`, `sens`, `flags`, `edge_index`) y de tokens sintácticos normalizados.
Los tokens conservan tipos y operadores, sustituyen identificadores y literales
por categorías y omiten comentarios. Se analizan los tokens del archivo completo,
aunque la representación de la GNN esté truncada.

Las coincidencias se agrupan transitivamente. Un grupo que contiene entrenamiento
queda excluido del nuevo benchmark, también cuando la coincidencia es indirecta.
La normalización puede juntar código semánticamente diferente: esos grupos son
candidatos conservadores, **no familias verificadas ni clones confirmados**.

`artifacts/localization/audit/` contiene inventario, grupos con su clasificación
y conteos. El grupo de auditoría es la unidad de remuestreo; no se cuentan sus
variantes como observaciones independientes.

## Casos controlados

Se seleccionan 30 bases de phpMyAdmin, que no se usaron para entrenar el baseline:
diez por tercil de tamaño entre los candidatos elegibles. Se ordenan por tamaño
y ruta, se barajan con semilla 0 y se aceptan las primeras bases válidas de grupos
distintos. La selección no consulta puntuaciones del modelo.

En cada base se insertan tres patrones: comandos del sistema, `eval` y escritura
de PHP, con entrada POST hacia una asignación y una operación consumidora. Cada
patrón se coloca al principio, centro y final de los límites de sentencias PHP
disponibles. Las posiciones pueden pertenecer a cuerpos de funciones o métodos;
se registra su desplazamiento real dentro del archivo.

Cada caso positivo tiene un control con el mismo guard, variable, función y
posición, pero asignando una constante. Se conservan además las bases originales:
270 positivos + 270 controles + 30 originales = **570 archivos**.

La preparación verifica parseo sin errores, ubicación dentro de PHP, tamaño,
ausencia de coincidencias con entrenamiento y reversibilidad exacta al quitar
la inserción. Los casos descartados y el motivo quedan registrados. Las líneas
positivas son la asignación de la fuente y la operación consumidora; no se
etiquetan el guard ni la llave final. No se escriben marcadores de clase en PHP.

Los controles son benignos respecto al flujo de datos que se altera: las
operaciones usan constantes. La etiqueta del resto del archivo se hereda de su
procedencia legítima, sin una auditoría humana completa. No se demuestra que los
payloads sean alcanzables o funcionales en ejecución; eso queda fuera del análisis
estático y se registra expresamente.

## Muestras reales

[`localization_annotations.json`](localization_annotations.json) contiene la
revisión estática asistida de los 20 archivos desofuscados elegibles más pequeños
de PHP-backdoors: selección por conveniencia, **no representativa**. Cada entrada
conserva hash, líneas, evidencia textual, explicación y autor de la revisión.

- `complete_assisted`: revisión completa según la política de fuente/operación;
  permite calcular las métricas completas, siempre como anotación asistida.
- `partial_assisted`: evidencia positiva parcial; solo se informa una cota
  inferior de Hit@k. No se calcula recall ni IoU completos.
- `ambiguous`: intención maliciosa no confirmada; se conservan predicciones para
  inspección, pero se excluye de las métricas de detección y localización.

Las anotaciones no tienen revisión humana independiente. Las llamadas `mail`,
los formularios de newsletter y la procedencia de una colección no bastan para
confirmar intención maliciosa. Los datos reales carecen de negativos confirmados;
por ello no se presenta precisión, F1, AUC ni especificidad de ese conjunto.
Se informa recall descriptivo respecto a las etiquetas asistidas y sus conteos.

Los ejemplos muy cortos o de una sola línea facilitan la localización; el
manifiesto incluye longitud y proporción de líneas anotadas para inspeccionarlo.

## Comparación y métricas

- **GNN:** checkpoint congelado; atención y gradiente por entrada combinados
  al 50 %. Se conserva la asignación original por nodos de una sola línea.
- **Regla:** positivo si el AST representado contiene algún nombre sensible y
  alguna superglobal. Ordena líneas por `2 × nodos sensibles + superglobales`.
  Es una referencia simple, no un analizador de flujo de datos.
- **Regresión logística:** frecuencias de tipos AST y funciones sensibles y
  medias de banderas, sin aristas. `StandardScaler` y clasificador se ajustan
  solo sobre el entrenamiento original, con `C=1`, clases balanceadas,
  `max_iter=2000` y semilla 0. Ordena líneas por la contribución lineal positiva
  de sus nodos; el intercepto y el desplazamiento constante del escalado no se
  atribuyen a líneas.

Todos usan el vocabulario congelado y el mismo límite de 2500 nodos. Se usa el
umbral `score > 0.5`. Las importancias por línea son rankings, no probabilidades
calibradas de malicia. No se eligen líneas de puntuación cero para completar k.

Se informa detección mediante matriz de confusión, exactitud, precisión, recall,
F1 y FPR cuando sus denominadores y las clases disponibles lo permiten. AUC se
calcula únicamente para puntuaciones continuas y dos clases.

Localización: Hit@1/3/5, Recall@5 e IoU@5. Se separan la evaluación condicionada
a detectar correctamente y la evaluación de extremo a extremo, donde una
detección fallida aporta cero. Las líneas maliciosas fuera del grafo no se
eliminan del denominador: se contabilizan como no localizadas.

Se separan resultados reales/controlados, patrón, posición, clase de variante
y truncamiento. Los intervalos son percentiles de 1000 bootstrap de grupos con
semilla 0: todas las variantes de una base se remuestrean juntas. Describen la
variación entre los grupos observados; no incorporan otras semillas de
entrenamiento, incertidumbre de anotación ni representatividad de producción.
Las réplicas cuyo denominador sea cero se omiten para esa métrica; un intervalo
degenerado no demuestra ausencia de incertidumbre fuera de la muestra observada.

## Resultado de esta ejecución

| Método | Recall controlado | F1 controlado | FPR controlado | Hit@3 de extremo a extremo |
|---|---:|---:|---:|---:|
| GNN | 3,33 % (9/270) | 0,0625 | 3,00 % | 3,33 % |
| Regla | 95,56 % (258/270) | 0,6532 | 87,33 % | 92,22 % |
| Regresión logística | 6,67 % (18/270) | 0,1188 | 5,00 % | 6,67 % |

La GNN asignó el mismo veredicto a los 270 pares malicioso/control. El Hit@3
condicional del 100 % corresponde solo a nueve positivos detectados, de una
única base. No representa la localización de los 270 positivos del benchmark.
El recall de la GNN en los 234 positivos sin truncamiento fue 3,85 % (9/234);
en los 36 truncados fue cero. El truncamiento no explica por sí solo el fallo.

En las 14 muestras reales no ambiguas la GNN detectó las 14, y alcanzó Hit@3 de
11/11 entre las anotaciones completas asistidas. El conjunto es pequeño, de una
colección, seleccionado por legibilidad y sin negativos confirmados; no demuestra
generalización ni reemplaza la revisión independiente.

El [informe local completo](../artifacts/localization/results/REPORT.md) incluye
matrices, intervalos, cobertura y limitaciones. Las métricas y el bootstrap
principal se verificaron independientemente desde las predicciones guardadas.

## Artefactos

- `dataset/processed/localization/`: archivos PHP derivados y manifiesto que
  congela protocolo, hashes, bases, anotaciones, exclusiones y transformaciones.
- `artifacts/localization/results/predictions.jsonl`: predicciones y cinco
  primeras líneas, con cobertura de las anotaciones y truncamiento.
- `metrics.json`: métricas e intervalos, separados por método y ámbito.
- `errors.json`: errores de clasificación y fallos de localización en top-3,
  con las líneas originales para inspección.
- `logreg.joblib`: clasificador auxiliar ajustado, generado localmente.
- `frozen_manifest.json`: copia exacta del manifiesto utilizado.
- `REPORT.md`: resumen de resultados e interpretación limitada a este diagnóstico.
- `environment.json` y `requirements.txt`: entorno registrado al cerrar la ejecución.

Los directorios derivados están excluidos de Git. Las anotaciones asistidas,
scripts y documentación sí pueden versionarse. Las muestras deben permanecer
fuera de directorios servidos por PHP.
