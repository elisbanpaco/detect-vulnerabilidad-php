"""Autocomprobación sin dependencias ni muestras maliciosas: python3 dataset/test_build_corpus.py."""
import csv
import hashlib
import json
import tempfile
from pathlib import Path
from zipfile import ZipFile

import build_corpus


def test_corpus():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "metadata").mkdir()
        code = b"<?php echo 'ejemplo de prueba suficientemente largo';"
        conflict = b"<?php echo 'contenido con etiquetas contradictorias';"
        sources = []
        for name, label, files in [
            ("a", 1, {"one.php": code, "duplicate.php": code, "conflict.php": conflict}),
            ("b", 0, {"safe.php": code + b"\n", "conflict.php": conflict,
                      "tiny.php": b"<?php", "tests/fixture.php": code}),
        ]:
            archive = root / f"{name}.zip"
            with ZipFile(archive, "w") as z:
                for path, content in files.items():
                    z.writestr(f"snapshot/{path}", content)
            sources.append(dict(id=name, label=label, role="mvp", archive=archive.name,
                                archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest()))
        (root / "sources.json").write_text(json.dumps(dict(sources=sources)))
        original = build_corpus.HERE
        try:
            build_corpus.HERE = root
            build_corpus.main()
            rows = list(csv.DictReader((root / "metadata/inventory.csv").open()))
            statuses = [r["status"] for r in rows]
            assert statuses.count("included") == 2
            assert statuses.count("duplicate") == 1
            assert statuses.count("label_conflict") == 2
            assert statuses.count("size_limit") == 1
            assert statuses.count("benign_test_or_fixture") == 1
            for row in rows:
                if row["status"] == "included":
                    assert hashlib.sha256((root / row["path"]).read_bytes()).hexdigest() == row["sha256"]
            try:
                build_corpus.main()
            except SystemExit:
                pass
            else:
                raise AssertionError("No debe sobrescribir el corpus")
        finally:
            build_corpus.HERE = original
    for name in ["../escape.php", "/absolute.php", "x/../../escape.php", "x\\escape.php"]:
        try:
            build_corpus.safe_path(name)
        except ValueError:
            pass
        else:
            raise AssertionError(f"Ruta insegura aceptada: {name}")


if __name__ == "__main__":
    test_corpus()
    print("OK: filtros, duplicados, conflictos, hashes, rutas y protección contra sobrescritura")
