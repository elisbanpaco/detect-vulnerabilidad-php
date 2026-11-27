"""Instala el ZIP con Composer y verifica el comando sin Python externo ni red."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    for command in ("composer", "php", "ldd", "bwrap"):
        if not shutil.which(command):
            raise RuntimeError(f"Falta herramienta de comprobación: {command}")
    archive = ROOT / "dist/phpguard-linux-x86_64.zip"
    work = Path(tempfile.mkdtemp(prefix="release-check-", dir=ROOT / "build"))
    consumer = work / "consumer"
    consumer.mkdir()
    package = json.loads((ROOT / "composer.json").read_text())
    with archive.open("rb") as stream:
        sha1 = hashlib.file_digest(stream, "sha1").hexdigest()
    package.update(version="0.2.0", dist=dict(type="zip", url=archive.as_uri(), shasum=sha1))
    configuration = dict(name="local/phpguard-check", repositories=[dict(type="package", package=package),
                         {"packagist.org": False}])
    (consumer / "composer.json").write_text(json.dumps(configuration))
    environment = dict(os.environ, COMPOSER_HOME=str(work / "composer-home"), COMPOSER_CACHE_DIR=str(work / "composer-cache"))
    environment.pop("PHPGUARD_PYTHON", None)
    subprocess.run(["composer", "require", "elisbanpaco/phpguard:^0.2", "--no-interaction", "--no-plugins", "--no-scripts"],
                   cwd=consumer, env=environment, check=True)
    installed = consumer / "vendor/elisbanpaco/phpguard"
    if not os.access(installed / "runtime/linux-x86_64/phpguard-engine", os.X_OK):
        raise RuntimeError("Composer no conservó los permisos del motor")
    jail = work / "root"
    jail.mkdir()
    shutil.copy2(shutil.which("php"), jail / "php")
    libraries = subprocess.check_output(["ldd", shutil.which("php")], text=True)
    libraries += subprocess.check_output(["ldd", str(installed / "runtime/linux-x86_64/phpguard-engine")], text=True)
    libraries += subprocess.check_output(["ldd", str(installed / "runtime/linux-x86_64/_internal/libpython3.13.so.1.0")], text=True)
    for name in re.findall(r"(?:=>\s+)?(/[^\s]+)", libraries):
        library = Path(name)
        if library.is_file():
            destination = jail / library.relative_to("/")
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(library, destination)
    for name in ("app", "proc", "dev", "tmp"):
        (jail / name).mkdir()
    if list(jail.rglob("python*")):
        raise RuntimeError("El entorno aislado contiene un Python externo")
    cases = (("sample.php", b"<?php\necho 123;\n", 1, "SOSPECHOSO"),
             ("inline.php", b"<?php echo 123;", 0, "SIN_INDICIOS"),
             ("invalid.php", b"<?php echo ;", 2, "NO_ANALIZABLE"),
             ("large.php", b"<?php " + b"x" * 200000, 2, "NO_ANALIZABLE"),
             ("missing.php", None, 2, "NO_ANALIZABLE"))
    results = []
    for filename, content, status, verdict in cases:
        if content is not None:
            (consumer / filename).write_bytes(content)
        command = ["bwrap", "--ro-bind", str(jail), "/", "--ro-bind", str(consumer), "/app",
                   "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--unshare-net",
                   "--chdir", "/app", "--setenv", "PATH", "/no-python", "--unsetenv", "PHPGUARD_PYTHON",
                   "--unsetenv", "PYTHONHOME", "--unsetenv", "PYTHONPATH",
                   "/php", "-n", "/app/vendor/bin/phpguard", "/app/" + filename]
        result = subprocess.run(command, capture_output=True, text=True, timeout=130)
        try:
            output = json.loads(result.stdout or result.stderr)
        except ValueError:
            raise RuntimeError(f"Sin JSON en {filename}: {result.stderr}")
        if result.returncode != status or output["verdict"] != verdict:
            raise RuntimeError(f"Fallo aislado en {filename}: {result.stdout} {result.stderr}")
        results.append(dict(file=filename, exit=status, verdict=verdict))
        print(f"ISOLATED OK: {filename}, exit={status}", flush=True)
    report = dict(composer_install=True, no_external_python=True, network=False,
                  consumer=str(consumer), cases=results,
                  build=json.loads((installed / "runtime/build.json").read_text()))
    (ROOT / "build/release-check.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
