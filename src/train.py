"""Entrenamiento CPU reproducible; selección por validación y una evaluación final de test.
Uso: python3 src/train.py dataset.pt artifacts/baseline/phpguard.pt [--epochs 25]
"""
import argparse
import csv
import hashlib
from importlib.metadata import distributions
import json
import math
from pathlib import Path
import platform
import random
import time

import torch
import torch.nn.functional as F
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from torch_geometric.data import Data
from torch_geometric.loader import DataLoader

from model import PHPGuard
from prepare_data import SPLIT_REPOS, validate_graphs


def to_data(g):
    return Data(type=g["type"], sens=g["sens"], flags=g["flags"], edge_index=g["edge_index"],
                y=torch.tensor([float(g["y"])]), num_nodes=g["type"].numel())


def evaluate(model, loader):
    model.eval()
    ys, ps = [], []
    with torch.no_grad():
        for batch in loader:
            ps += torch.sigmoid(model(batch)).tolist()
            ys += batch.y.tolist()
    if not all(math.isfinite(p) for p in ps):
        raise ValueError("Predicciones no finitas")
    pred = [int(p > 0.5) for p in ps]
    return dict(acc=accuracy_score(ys, pred), precision=precision_score(ys, pred, zero_division=0),
                recall=recall_score(ys, pred, zero_division=0), f1=f1_score(ys, pred, zero_division=0),
                auc=roc_auc_score(ys, ps), confusion_matrix=confusion_matrix(ys, pred, labels=[0, 1]).tolist(),
                n=len(ys)), ps


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, allow_nan=False) + "\n")


def main(ds_path, out_path, epochs=25):
    if epochs < 1:
        raise ValueError("epochs debe ser mayor que cero")
    output = Path(out_path)
    run_dir = output.parent
    metrics_path = output.with_name(output.stem + "_metrics.json")
    artifacts = [output, output.with_suffix(".tmp"), metrics_path] + [run_dir / name for name in (
        "parameters.json", "environment.json", "requirements.txt", "manifest.csv",
        "history.json", "test_predictions.csv", "training.log")]
    if any(p.exists() for p in artifacts):
        raise FileExistsError(f"El destino ya contiene artefactos: {run_dir}")
    ds = torch.load(ds_path, weights_only=True, map_location="cpu")
    if ds.get("split_repos") != SPLIT_REPOS:
        raise ValueError("Regenera los grafos con la partición train/validation/test actual")
    validate_graphs(ds["graphs"])
    if ds["vocab"].get("<unk>") != 0 or sorted(ds["vocab"].values()) != list(range(len(ds["vocab"]))):
        raise ValueError("Vocabulario inválido")
    for graph in ds["graphs"]:
        if graph["type"].numel() == 0 or graph["type"].min() < 0 or graph["type"].max() >= len(ds["vocab"]):
            raise ValueError(f"Tipos de nodo inválidos: {graph['path']}")
    random.seed(0)
    torch.manual_seed(0)
    torch.set_num_threads(4)
    torch.use_deterministic_algorithms(True)
    train_graphs = [g for g in ds["graphs"] if g["split"] == "train"]
    val_graphs = [g for g in ds["graphs"] if g["split"] == "validation"]
    test_graphs = [g for g in ds["graphs"] if g["split"] == "test"]
    train_data = [to_data(g) for g in train_graphs]
    val_data = [to_data(g) for g in val_graphs]
    positive = sum(g["y"] for g in train_graphs)
    pos_weight = (len(train_graphs) - positive) / positive
    parameters = dict(seed=0, device="cpu", threads=4, deterministic_algorithms=True,
                      epochs=epochs, batch_size=16, learning_rate=0.002, weight_decay=0.0001,
                      pos_weight=pos_weight, threshold=0.5, selection="validation_f1; earliest tie",
                      split_repos=SPLIT_REPOS, dataset_path=str(ds_path),
                      dataset_sha256=hashlib.sha256(Path(ds_path).read_bytes()).hexdigest(),
                      model=dict(hid=64, heads=4, layers=3, drop=0.2),
                      source_sha256={name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                                     for name in ("train.py", "model.py", "phpgraph.py", "prepare_data.py")})
    packages = dict(sorted((d.metadata["Name"], d.version) for d in distributions()))
    environment = dict(python=platform.python_version(), platform=platform.platform(), packages=packages)
    run_dir.mkdir(parents=True, exist_ok=True)
    write_json(run_dir / "parameters.json", parameters)
    write_json(run_dir / "environment.json", environment)
    (run_dir / "requirements.txt").write_text(
        "--extra-index-url https://download.pytorch.org/whl/cpu\n" +
        "".join(f"{name}=={version}\n" for name, version in packages.items()))
    manifest = [dict(path=g["path"], repo=g["repo"], split=g["split"], label=g["y"], sha256=g["sha256"],
                     md5=g["md5"], n_nodes=g["type"].numel(), truncated=g["truncated"]) for g in ds["graphs"]]
    with (run_dir / "manifest.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(manifest[0]))
        writer.writeheader()
        writer.writerows(manifest)

    def report(message):
        print(message, flush=True)
        with (run_dir / "training.log").open("a") as f:
            f.write(message + "\n")

    n_types = len(ds["vocab"])
    model = PHPGuard(n_types, **parameters["model"])
    optimizer = torch.optim.AdamW(model.parameters(), lr=parameters["learning_rate"],
                                 weight_decay=parameters["weight_decay"])
    train_loader = DataLoader(train_data, batch_size=16, shuffle=True,
                              generator=torch.Generator().manual_seed(0))
    val_loader = DataLoader(val_data, batch_size=16, shuffle=False)
    history, best_f1, best_epoch = [], -1.0, None
    started = time.monotonic()
    report(f"CPU train={len(train_graphs)} validation={len(val_graphs)} test={len(test_graphs)} epochs={epochs}")
    for epoch in range(1, epochs + 1):
        model.train()
        total = 0.0
        epoch_started = time.monotonic()
        for step, batch in enumerate(train_loader, 1):
            optimizer.zero_grad()
            loss = F.binary_cross_entropy_with_logits(model(batch), batch.y,
                                                       pos_weight=torch.tensor(pos_weight))
            if not torch.isfinite(loss):
                raise ValueError(f"Loss no finita en época {epoch}, lote {step}")
            loss.backward()
            optimizer.step()
            total += loss.item() * batch.num_graphs
            if step % 50 == 0:
                report(f"ep{epoch:02d} batch={step}/{len(train_loader)}")
        validation, _ = evaluate(model, val_loader)
        history.append(dict(epoch=epoch, loss=total / len(train_data), validation=validation,
                            seconds=time.monotonic() - epoch_started))
        if validation["f1"] > best_f1:
            best_f1, best_epoch = validation["f1"], epoch
            torch.save(dict(state=model.state_dict(), vocab=ds["vocab"], n_types=n_types,
                            epoch=epoch, validation_f1=best_f1), output.with_suffix(".tmp"))
            output.with_suffix(".tmp").replace(output)
        write_json(run_dir / "history.json", history)
        report(f"ep{epoch:02d} loss={total / len(train_data):.4f} val f1={validation['f1']:.4f} "
               f"auc={validation['auc']:.4f} seconds={history[-1]['seconds']:.1f} best={best_epoch}")

    checkpoint = torch.load(output, weights_only=True, map_location="cpu")
    model.load_state_dict(checkpoint["state"])
    model.eval()
    restored = PHPGuard(checkpoint["n_types"], **parameters["model"])
    restored.load_state_dict(checkpoint["state"])
    restored.eval()
    probe = next(iter(val_loader))
    with torch.no_grad():
        torch.testing.assert_close(model(probe), restored(probe), rtol=0, atol=0)
    test_loader = DataLoader([to_data(g) for g in test_graphs], batch_size=16, shuffle=False)
    final, probabilities = evaluate(restored, test_loader)
    with (run_dir / "test_predictions.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["path", "repo", "sha256", "label", "probability", "predicted"])
        writer.writeheader()
        for graph, probability in zip(test_graphs, probabilities, strict=True):
            writer.writerow(dict(path=graph["path"], repo=graph["repo"], sha256=graph["sha256"],
                                 label=graph["y"], probability=probability, predicted=int(probability > 0.5)))
    results = dict(final=final, best_epoch=best_epoch, best_validation_f1=best_f1,
                   train_n=len(train_graphs), validation_n=len(val_graphs), test_n=len(test_graphs),
                   split_repos=SPLIT_REPOS, graph_summary=ds["summary"],
                   checkpoint_sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
                   reload_verified=True, test_evaluations=1, seconds=time.monotonic() - started)
    write_json(metrics_path, results)
    report("FINAL " + json.dumps(results, allow_nan=False))
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset")
    parser.add_argument("model")
    parser.add_argument("--epochs", type=int, default=25)
    args = parser.parse_args()
    main(args.dataset, args.model, epochs=args.epochs)
