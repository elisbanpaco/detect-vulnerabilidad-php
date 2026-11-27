# Distribución autónoma Linux x86-64

El usuario final solo ejecuta `composer require elisbanpaco/phpguard:^0.2` y
`vendor/bin/phpguard archivo.php`, después de publicarse esa versión. El ZIP
incluye el intérprete, las bibliotecas CPU y el checkpoint. No descarga nada
al analizar archivos ni requiere Python en el equipo del usuario.

## Construcción para el mantenedor

Desde Linux x86-64 con glibc, PHP CLI, Python 3.13.12 y uv:

```bash
uv pip install --python .venv/bin/python --index-strategy unsafe-best-match -r packaging/requirements.txt
.venv/bin/python -m PyInstaller --noconfirm --distpath dist/engine --workpath build/pyinstaller packaging/phpguard.spec
.venv/bin/python packaging/build_release.py
```

La salida es `dist/phpguard-linux-x86_64.zip` y su archivo `.zip.sha256`.
PyInstaller construye el motor. El script incorpora los avisos de licencia y
compara cuatro programas PHP sintéticos con el motor Python original. Una
discrepancia impide generar el ZIP. No se utiliza de nuevo el test del corpus.

Para verificar la instalación desde el ZIP sin publicar, en un sistema con
Bubblewrap y permiso para crear namespaces:

```bash
python3 packaging/check_release.py
```

Esta comprobación usa un proyecto Composer temporal y un repositorio local para
la versión aún no publicada. Ejecuta el comando instalado dentro de una raíz
mínima con PHP y sus bibliotecas del sistema, sin Python externo y sin red.
El informe se guarda en `build/release-check.json`.

El paquete conserva resultados JSON, umbral, modelo y códigos 0/1/2. El binario
incluido tiene prioridad sobre `PHPGUARD_PYTHON`, para que una configuración de
v0.1 no interfiera con la nueva distribución.

PyInstaller no incorpora glibc: construir sobre una distribución nueva no promete
compatibilidad con otras anteriores. La compilación local usa glibc 2.42 y solo
se comprobó con ese sistema. Para ampliar compatibilidad se debe construir en la
distribución glibc más antigua que se quiera soportar y repetir las pruebas.
No se soportan Alpine/musl, Windows, macOS ni ARM en esta versión.

Los ejecutables grandes no se suben a Git. El `dist` de `composer.json` dirige
Composer al ZIP adjunto a la versión de GitHub, evitando plugins o instaladores
que ejecuten pip en el equipo del usuario. Las instalaciones `--prefer-source`
no incluyen los binarios. No se han publicado estos cambios ni la versión v0.2.0.

## Publicación, después de revisar el artefacto

1. Revisar la licencia de los pesos y los avisos de terceros. La licencia MIT
   del proyecto excluye los pesos; empaquetarlos no resuelve sus condiciones.
2. Versionar fuentes y configuración, sin `build/`, `dist/` ni `runtime/`.
3. Crear y subir la etiqueta `v0.2.0` del commit revisado.
4. Crear una versión de GitHub para esa etiqueta y adjuntar exactamente
   `phpguard-linux-x86_64.zip` y `phpguard-linux-x86_64.zip.sha256`.
5. Actualizar Packagist y comprobar que la URL `dist` de v0.2.0 apunta al ZIP
   adjunto, no al ZIP de código fuente generado por GitHub.
6. Probar `composer require elisbanpaco/phpguard:^0.2` en otro proyecto.

No reutilizar la etiqueta ni reemplazar archivos publicados: cualquier cambio
necesita otra versión y actualizar el `dist` correspondiente.
