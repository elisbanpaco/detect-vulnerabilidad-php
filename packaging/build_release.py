"""Construye y verifica el ZIP Composer autónomo para Linux x86-64; no publica."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parent.parent


def main():
    if platform.system() != "Linux" or platform.machine() != "x86_64" or platform.libc_ver()[0] != "glibc":
        raise RuntimeError("La compilación requiere Linux x86-64 con glibc")
    engine = ROOT / "dist/engine/phpguard-engine"
    if not (engine / "phpguard-engine").is_file():
        raise RuntimeError("Primero construye el motor con PyInstaller; consulta packaging/README.md")
    with tempfile.TemporaryDirectory(prefix="phpguard-release-", dir=ROOT / "build") as temporary:
        package = Path(temporary) / "phpguard"
        package.mkdir()
        for name in ("composer.json", "LICENSE", "README.md"):
            shutil.copy2(ROOT / name, package / name)
        shutil.copytree(ROOT / "bin", package / "bin")
        shutil.copytree(engine, package / "runtime/linux-x86_64", symlinks=True)
        # El libpython de esta distribución marca la pila ejecutable; CPython no la necesita para esta inferencia.
        subprocess.run([str(Path(sys.executable).parent / "patchelf"), "--clear-execstack",
                        str(package / "runtime/linux-x86_64/_internal/libpython3.13.so.1.0")], check=True)
        shutil.copytree(ROOT / "models", package / "models")
        notices = package / "runtime/linux-x86_64/_internal/licenses/system"
        notices.mkdir(parents=True, exist_ok=True)
        python_license = Path(sys.base_prefix) / "lib/python3.13/LICENSE.txt"
        if not python_license.is_file():
            raise RuntimeError(f"Falta el aviso de licencia de Python: {python_license}")
        shutil.copy2(python_license, notices / "PYTHON-LICENSE.txt")
        for directory in (Path("/usr/share/licenses/gcc"), Path("/usr/share/licenses/libgcc"), Path("/usr/share/licenses/openssl-libs")):
            if directory.is_dir():
                shutil.copytree(directory, notices / directory.name, dirs_exist_ok=True)
        metadata = dict(platform="linux-x86_64", libc="glibc", build_glibc=platform.libc_ver()[1],
                        python=platform.python_version(), model=json.loads((ROOT / "models/manifest.json").read_text())["sha256"])
        (package / "runtime/build.json").write_text(json.dumps(metadata, indent=2) + "\n")
        environment = dict(os.environ, PATH="/nonexistent")
        for key in ("PHPGUARD_PYTHON", "PYTHONHOME", "PYTHONPATH"):
            environment.pop(key, None)
        with tempfile.TemporaryDirectory(prefix="phpguard-fixtures-") as samples:
            for name, content in (("echo.php", b"<?php\necho 123;\n"),
                                  ("inline.php", b"<?php echo 123;"),
                                  ("assignment.php", b"<?php\n$value = 42;\necho $value;\n"),
                                  ("suspicious.php", b"<?php\neval($_POST['command']);\n")):
                source = Path(samples) / name
                source.write_bytes(content)
                expected = subprocess.run([sys.executable, str(ROOT / "src/scan.py"), str(source)], capture_output=True, text=True, timeout=120)
                actual = subprocess.run([shutil.which("php"), str(package / "bin/phpguard"), str(source)],
                                        env=environment, capture_output=True, text=True, timeout=120)
                if actual.returncode != expected.returncode or json.loads(actual.stdout) != json.loads(expected.stdout):
                    raise RuntimeError(f"Diferencia entre Python y motor autónomo en {name}: {actual.stderr}")
                print(f"PARITY OK: {name}, exit={actual.returncode}", flush=True)
        target = ROOT / "dist/phpguard-linux-x86_64.zip"
        with ZipFile(target, "w", ZIP_DEFLATED, compresslevel=6) as archive:
            for file in sorted(package.rglob("*")):
                if file.is_file():
                    archive.write(file, file.relative_to(package))
        with target.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        target.with_suffix(".zip.sha256").write_text(f"{digest}  {target.name}\n")
        print(json.dumps(dict(archive=str(target), bytes=target.stat().st_size, sha256=digest, build=metadata), indent=2))


if __name__ == "__main__":
    main()
