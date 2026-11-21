"""PHP -> grafos con partición fija por repositorio y vocabulario exclusivo de train.
Uso: python3 src/prepare_data.py <malicious_dir> <benign_dir> <out.pt>
"""
import csv
import hashlib
import json
import os
from pathlib import Path
import sys

import torch
import phpgraph

EXT = (".php", ".php5", ".phtml", ".inc")
MAX_BYTES = 200_000
SPLIT_REPOS = {
    "train": ["tennc-webshell", "wordpress", "laravel"],
    "validation": ["php-webshells", "composer"],
    "test": ["PHP-backdoors", "phpMyAdmin"],
}
MALICIOUS_REPOS = {"tennc-webshell", "php-webshells", "PHP-backdoors"}


def collect(root, label):
    out = []
    for repo in sorted(Path(root).iterdir()):
        if repo.is_symlink():
            raise ValueError(f"No se admiten enlaces simbólicos: {repo}")
        if not repo.is_dir():
            continue
        if not any(repo.name in repos for repos in SPLIT_REPOS.values()):
            raise ValueError(f"Repositorio sin partición definida: {repo.name}")
        if label != int(repo.name in MALICIOUS_REPOS):
            raise ValueError(f"Clase incorrecta para {repo.name}")
        for dp, dn, fn in os.walk(repo):
            dn[:] = sorted(d for d in dn if d not in {".git", "vendor", "node_modules"})
            if any((Path(dp) / d).is_symlink() for d in dn):
                raise ValueError(f"Directorio simbólico en {dp}")
            for name in sorted(fn):
                if not name.lower().endswith(EXT):
                    continue
                path = Path(dp) / name
                if path.is_symlink():
                    raise ValueError(f"No se admiten enlaces simbólicos: {path}")
                code = path.read_bytes()
                if not 30 < len(code) <= MAX_BYTES or b"<?" not in code:
                    raise ValueError(f"Archivo fuera de los criterios del corpus: {path}")
                out.append((repo.name, path, label, code))
    return out


def validate_graphs(graphs):
    """Falla antes de entrenar si faltan clases o se comparten muestras/repositorios."""
    labels = {split: set() for split in SPLIT_REPOS}
    seen = set()
    repos = set()
    for g in graphs:
        split = g["split"]
        if split not in SPLIT_REPOS or g["repo"] not in SPLIT_REPOS[split]:
            raise ValueError(f"Partición incorrecta: {g['repo']} / {split}")
        if g["y"] != int(g["repo"] in MALICIOUS_REPOS):
            raise ValueError(f"Etiqueta incorrecta: {g['repo']}")
        if g["sha256"] in seen:
            raise ValueError(f"SHA-256 repetido: {g['path']}")
        seen.add(g["sha256"])
        repos.add(g["repo"])
        labels[split].add(g["y"])
    if any(values != {0, 1} for values in labels.values()):
        raise ValueError("Cada partición debe contener ambas clases")
    if repos != {repo for group in SPLIT_REPOS.values() for repo in group}:
        raise ValueError("Faltan repositorios de la partición fija")


def main(mal_dir, ben_dir, out_path):
    output = Path(out_path)
    outputs = [output, output.with_suffix(".manifest.csv"), output.with_suffix(".summary.json")]
    if any(p.exists() for p in outputs):
        raise FileExistsError(f"El destino ya contiene artefactos: {output}")
    items = collect(mal_dir, 1) + collect(ben_dir, 0)
    rows = []
    for repo, path, label, code in items:
        split = next(s for s, repos in SPLIT_REPOS.items() if repo in repos)
        rows.append(dict(repo=repo, path=os.path.relpath(path), y=label, split=split,
                         sha256=hashlib.sha256(code).hexdigest(), md5=phpgraph.file_md5(code)))
    validate_graphs(rows)
    ordered = sorted(zip(rows, items), key=lambda pair: (
        list(SPLIT_REPOS).index(pair[0]["split"]), pair[0]["repo"], pair[0]["path"]))
    phpgraph.load_vocab({"<unk>": 0})
    graphs, manifest = [], []
    for i, (row, (_, _, _, code)) in enumerate(ordered, 1):
        graph = phpgraph.build_graph(code, grow_vocab=row["split"] == "train")
        graph.update(row)
        graphs.append(graph)
        manifest.append(dict(**row, n_nodes=graph["type"].numel(), truncated=graph["truncated"]))
        if i % 250 == 0:
            print(f"graphs {i}/{len(ordered)}", flush=True)
    summary = {}
    for split in SPLIT_REPOS:
        subset = [r for r in manifest if r["split"] == split]
        summary[split] = dict(files=len(subset), malicious=sum(r["y"] for r in subset),
                              benign=sum(1 - r["y"] for r in subset),
                              truncated=sum(r["truncated"] for r in subset),
                              repositories=SPLIT_REPOS[split])
    summary.update(vocab_size=len(phpgraph.vocab_state()), max_nodes=phpgraph.MAX_NODES)
    output.parent.mkdir(parents=True, exist_ok=True)
    torch.save(dict(graphs=graphs, vocab=phpgraph.vocab_state(), split_repos=SPLIT_REPOS,
                    test_repos=SPLIT_REPOS["test"], summary=summary), output)
    with outputs[1].open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(manifest[0]))
        writer.writeheader()
        writer.writerows(manifest)
    outputs[2].write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main(*sys.argv[1:4])
