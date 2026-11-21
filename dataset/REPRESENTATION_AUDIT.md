# Auditoría de representación después del entrenamiento conjunto

La ejecución v2 terminó con F1 0.8858 en su cohorte mixta. La auditoría posterior
examina sus 42 falsos negativos y cuatro bases legítimas con falsas alarmas,
sin modificar pesos, etiquetas ni parámetros de decisión.

## Reproducir

```bash
.venv/bin/python -m unittest discover -s src -p 'test_semantic_features.py' -v
.venv/bin/python src/audit_joint_errors.py --out artifacts/joint_error_audit-run2
```

El comando verifica los hashes del dataset y checkpoint y reproduce las
puntuaciones originales de las cuatro bases antes de hacer ablaciones de
características. Los resultados locales originales están en
[`../artifacts/joint_error_audit/REPORT.md`](../artifacts/joint_error_audit/REPORT.md).
No se ejecuta PHP ni se contactan destinos contenidos en sus archivos.

## Hallazgos comprobados

- 40 falsos negativos contienen llamadas dinámicas sin bandera en el nodo de llamada.
- 41 no tienen superglobales visibles como nombres en el AST.
- 40 contienen candidatos a constantes sin comillas; no se determinaron sus valores.
- Se demostró con una prueba que POST y GLOBALS pueden dar entradas exactamente
  iguales al modelo v2 en programas de la misma estructura.

La auditoría también compara características de las muestras recolectadas en
entrenamiento, validación y prueba. Las intervenciones sobre las cuatro falsas
alarmas indican dependencias del modelo, no cambios semánticamente equivalentes
del PHP ni una estimación de rendimiento de otro detector.

## Extractor preparado

`semantic_features.py` agrega dos tensores categóricos alineados con los nodos:

- `source_kind`: identidad de la superglobal, con categoría cero para otros nodos.
- `call_kind`: llamada nominal, variable/array, literal o expresión, con cero para
  los nodos que no son llamadas.

El nuevo grafo tiene versión `full_ast_lexical_def_use_source_call_v3`. Las
identidades no son etiquetas de confianza: GLOBALS puede contener datos del
usuario y SERVER puede contener cabeceras controladas por un atacante.
El extractor no reconstruye aún nombres calculados ni interpreta cadenas PHP.

Es una corrección del contrato de representación con pruebas; **no hay un modelo
v3 entrenado ni mejoras de clasificación medidas**. Los modelos y scripts v2
se conservan para reproducir sus resultados.

## Versiones PHP

Los candidatos a constantes requieren revisión según la versión objetivo. En
PHP anterior a 8, las constantes indefinidas podían tratarse como cadenas; PHP 8
produce un error. Esto no autoriza convertir automáticamente una muestra en
benigna: deben revisarse definiciones externas, versión e intención por separado.
Referencia: [manual de constantes PHP](https://www.php.net/manual/en/language.constants.syntax.php).

La siguiente cohorte debe fijar esta política antes de entrenarse y reservar una
evaluación nueva. La prueba v2 ya fue utilizada para diagnosticar cambios y no
debe presentarse como una prueba ciega del futuro modelo.
