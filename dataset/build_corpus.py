"""Construye el corpus PHP desde snapshots ZIP locales, sin ejecutar las muestras."""
import csv
import hashlib
import json
import stat
import tempfile
from collections import Counter
from pathlib import Path, PurePosixPath
from zipfile import ZipFile

HERE = Path(__file__).resolve().parent
EXT = {".php", ".php5", ".phtml", ".inc"}
SKIP = {".git", "vendor", "node_modules"}
TESTS = {"test", "tests", "fixtures", "__fixtures__"}


def safe_path(name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name:
        raise ValueError(f"Ruta insegura en ZIP: {name!r}")
    return path


def main():
    sources = json.loads((HERE / "sources.json").read_text())["sources"]
    output = HERE / "processed" / "php"
    if output.exists():
        raise SystemExit(f"Ya existe {output}; no se sobrescribe el corpus.")
    candidates, rows = [], []
    for source in sources:
        if source["role"] != "mvp":
            continue
        archive = HERE / source["archive"]
        if hashlib.sha256(archive.read_bytes()).hexdigest() != source["archive_sha256"]:
            raise ValueError(f"SHA-256 incorrecto: {archive}")
        with ZipFile(archive) as z:
            for info in sorted(z.infolist(), key=lambda i: i.filename):
                path = safe_path(info.filename)
                if info.is_dir() or path.suffix.lower() not in EXT:
                    continue
                rel = PurePosixPath(*path.parts[1:])
                row = dict(source=source["id"], label=source["label"],
                           original_path=str(rel), bytes=info.file_size,
                           sha256="", md5="", status="", path="")
                rows.append(row)
                if stat.S_ISLNK(info.external_attr >> 16):
                    row["status"] = "symlink"
                elif SKIP.intersection(rel.parts):
                    row["status"] = "excluded_directory"
                elif source["label"] == 0 and TESTS.intersection(p.lower() for p in rel.parts):
                    row["status"] = "benign_test_or_fixture"
                elif not 30 < info.file_size <= 200_000:
                    row["status"] = "size_limit"
                else:
                    code = z.read(info)
                    row["sha256"] = hashlib.sha256(code).hexdigest()
                    row["md5"] = hashlib.md5(code).hexdigest()
                    if code.startswith(b"version https://git-lfs.github.com/spec/v1"):
                        row["status"] = "lfs_pointer"
                    elif b"<?" not in code:
                        row["status"] = "no_php_open_tag"
                    else:
                        candidates.append((row, code))

    labels = {}
    for row, _ in candidates:
        labels.setdefault(row["sha256"], set()).add(row["label"])
    seen = set()
    # shortcut: solo duplicados exactos; agrupar familias antes de evaluar resistencia a variantes.
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".php-", dir=output.parent) as tmp:
        staging = Path(tmp) / "php"
        staging.mkdir()
        for row, code in candidates:
            digest = row["sha256"]
            if len(labels[digest]) > 1:
                row["status"] = "label_conflict"
            elif digest in seen:
                row["status"] = "duplicate"
            else:
                seen.add(digest)
                group = "malicious" if row["label"] else "benign"
                rel = Path(group) / row["source"] / row["original_path"]
                target = staging / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(code)
                row["status"] = "included"
                row["path"] = str(Path("processed/php") / rel)
        staging.rename(output)

    with (HERE / "metadata" / "inventory.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    included = [r for r in rows if r["status"] == "included"]
    summary = dict(
        files=len(included),
        by_source=dict(sorted(Counter(r["source"] for r in included).items())),
        by_label=dict(Counter(r["label"] for r in included)),
        filtering=dict(Counter(r["status"] for r in rows)),
        graph_preparation=dict(partitions_defined_in="src/prepare_data.py", per_repository_cap=None),
    )
    (HERE / "metadata" / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
