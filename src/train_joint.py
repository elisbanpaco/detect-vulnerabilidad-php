"""Entrena detección/localización conjunta en CPU. El test solo se evalúa al finalizar."""
import argparse
import io
from importlib.metadata import distributions
import json
import logging
from pathlib import Path
import platform
import random
import time

import torch
import torch.nn.functional as F
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score

from audit_corpus import ROOT, sha256
from evaluate_localization import localization_metrics
from joint_graph import GRAPH_VERSION
from joint_model import JointPHPGuard
from prepare_joint import source_hashes


def read_graph(folder, row):
    path = (folder / row["graph_path"]).resolve()
    if not path.is_relative_to(folder.resolve()):
        raise ValueError("Ruta de grafo fuera del dataset")
    data = path.read_bytes()
    if sha256(data) != row["graph_file_sha256"]:
        raise ValueError(f"Grafo modificado: {row['case_id']}")
    graph = torch.load(io.BytesIO(data), weights_only=True, map_location="cpu")
    if graph["graph_version"] != GRAPH_VERSION or graph["truncated"]:
        raise ValueError(f"Versión o cobertura incorrecta: {row['case_id']}")
    if graph["line_target"].numel() != torch.unique(graph["lines"]).numel():
        raise ValueError(f"Objetivos por línea desalineados: {row['case_id']}")
    return graph


def evaluate_joint(model, folder, cases):
    model.eval()
    predictions = []
    with torch.no_grad():
        for row in cases:
            graph = read_graph(folder, row)
            file_logit, line_logits, line_ids = model(graph)
            probability = torch.sigmoid(file_logit).item()
            line_probabilities = torch.sigmoid(line_logits).tolist()
            ranking = sorted(zip(line_ids.tolist(), line_probabilities), key=lambda item: (-item[1], item[0]))[:5]
            predictions.append(dict(case_id=row["case_id"], group_id=row["group_id"], label=row["label"],
                                    kind=row["kind"], pattern=row["pattern"], position=row["position"],
                                    probability=probability, predicted=int(probability > .5),
                                    malicious_lines=row["malicious_lines"], line_supervised=row["line_supervised"],
                                    top_lines=[dict(line=line, probability=value) for line, value in ranking]))
    ys = [r["label"] for r in predictions]
    ps = [r["probability"] for r in predictions]
    pred = [r["predicted"] for r in predictions]
    metrics = dict(n=len(predictions), accuracy=accuracy_score(ys, pred),
                   precision=precision_score(ys, pred, zero_division=0), recall=recall_score(ys, pred, zero_division=0),
                   f1=f1_score(ys, pred, zero_division=0), auc=roc_auc_score(ys, ps),
                   confusion_matrix=confusion_matrix(ys, pred, labels=[0, 1]).tolist())
    localized = [r for r in predictions if r["line_supervised"] and r["label"]]
    if not localized:
        raise ValueError("La evaluación necesita positivos con anotación por línea")
    local = [localization_metrics(r["malicious_lines"], [line["line"] for line in r["top_lines"]]) for r in localized]
    metrics["localization_n"] = len(localized)
    for key in local[0]:
        metrics["e2e." + key] = sum(m[key] * r["predicted"] for m, r in zip(local, localized, strict=True)) / len(localized)
    metrics["selection_score"] = .5 * (metrics["f1"] + metrics["e2e.hit@3"])
    for kind in sorted({r["kind"] for r in predictions}):
        subset = [r for r in predictions if r["kind"] == kind]
        metrics["kind." + kind] = dict(n=len(subset), correct=sum(r["label"] == r["predicted"] for r in subset))
    return metrics, predictions


def main(folder, out, epochs=25):
    if epochs < 1:
        raise ValueError("epochs debe ser positivo")
    if out.exists():
        raise FileExistsError(f"La salida ya existe: {out}; usa --out con una carpeta nueva")
    manifest_path = folder / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if manifest["version"] != 2 or manifest["graph_version"] != GRAPH_VERSION:
        raise ValueError("Dataset incompatible; ejecuta prepare_joint.py")
    if manifest["source_sha256"] != source_hashes():
        raise ValueError("El código cambió desde la preparación; crea un dataset nuevo")
    groups = {}
    splits = {split: [r for r in manifest["cases"] if r["split"] == split] for split in ("train", "validation", "test")}
    for row in manifest["cases"]:
        if groups.setdefault(row["group_id"], row["split"]) != row["split"]:
            raise ValueError("Una base o sus clones aparecen en particiones distintas")
    for split, rows in splits.items():
        if {r["label"] for r in rows} != {0, 1}:
            raise ValueError(f"Cada partición necesita ambas clases: {split}")
    supervised = [r for r in splits["train"] if r["line_supervised"]]
    positives = sum(r["positive_lines"] for r in supervised)
    total_lines = sum(r["represented_lines"] for r in supervised)
    if not 0 < positives < total_lines:
        raise ValueError("Faltan líneas positivas/negativas de entrenamiento")
    random.seed(0)
    torch.manual_seed(0)
    torch.set_num_threads(4)
    torch.use_deterministic_algorithms(True)
    config = dict(hid=64, heads=4, layers=3, drop=.2)
    model = JointPHPGuard(len(manifest["vocab"]), **config)
    optimizer = torch.optim.AdamW(model.parameters(), lr=.002, weight_decay=.0001)
    file_positive = sum(r["label"] for r in splits["train"])
    file_weight = torch.tensor((len(splits["train"]) - file_positive) / file_positive)
    line_weight = torch.tensor((total_lines - positives) / positives)
    out.mkdir(parents=True)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", force=True,
                        handlers=[logging.FileHandler(out / "training.log", encoding="utf8"), logging.StreamHandler()])
    params = dict(seed=0, threads=4, device="cpu", epochs=epochs, batch_size=1, learning_rate=.002,
                  weight_decay=.0001, graph_version=GRAPH_VERSION, model=config, threshold=.5,
                  loss="file_BCE + supervised_line_BCE; collected files have no line loss",
                  file_pos_weight=file_weight.item(), line_pos_weight=line_weight.item(),
                  selection="0.5 validation F1 + 0.5 validation end-to-end Hit@3; earliest tie",
                  manifest_path=str(manifest_path.resolve()), manifest_sha256=sha256(manifest_path.read_bytes()),
                  source_sha256=source_hashes())
    (out / "parameters.json").write_text(json.dumps(params, indent=2) + "\n")
    (out / "environment.json").write_text(json.dumps(dict(python=platform.python_version(), platform=platform.platform(),
        packages=dict(sorted((d.metadata["Name"], d.version) for d in distributions()))), indent=2) + "\n")
    history, best, best_epoch = [], -1.0, None
    rng = random.Random(0)
    started = time.monotonic()
    logging.info("START train=%d validation=%d test=%d epochs=%d; full AST, batch=1", *(len(splits[s]) for s in splits), epochs)
    for epoch in range(1, epochs + 1):
        ordered = list(splits["train"])
        rng.shuffle(ordered)
        model.train()
        total = 0.0
        epoch_started = time.monotonic()
        for step, row in enumerate(ordered, 1):
            graph = read_graph(folder, row)
            optimizer.zero_grad(set_to_none=True)
            file_logit, line_logits, _ = model(graph)
            loss = F.binary_cross_entropy_with_logits(file_logit, torch.tensor([float(row["label"])]), pos_weight=file_weight)
            if row["line_supervised"]:
                loss = loss + F.binary_cross_entropy_with_logits(line_logits, graph["line_target"], pos_weight=line_weight)
            if not torch.isfinite(loss):
                raise ValueError(f"Loss no finita: epoch={epoch} case={row['case_id']}")
            loss.backward()
            optimizer.step()
            total += loss.item()
            if step % 50 == 0:
                logging.info("ep%02d step=%d/%d loss=%.4f", epoch, step, len(ordered), total / step)
        validation, _ = evaluate_joint(model, folder, splits["validation"])
        score = validation["selection_score"]
        if score > best:
            best, best_epoch = score, epoch
            torch.save(dict(version=2, graph_version=GRAPH_VERSION, state=model.state_dict(), vocab=manifest["vocab"],
                            n_types=len(manifest["vocab"]), model_config=config, epoch=epoch,
                            validation_score=score, manifest_sha256=params["manifest_sha256"]), out / "best.tmp")
            (out / "best.tmp").replace(out / "best.pt")
        history.append(dict(epoch=epoch, loss=total / len(ordered), validation=validation, seconds=time.monotonic() - epoch_started))
        (out / "history.json").write_text(json.dumps(history, indent=2, allow_nan=False) + "\n")
        logging.info("ep%02d DONE loss=%.4f val_f1=%.4f val_hit3=%.4f score=%.4f best=%d seconds=%.1f",
                     epoch, history[-1]["loss"], validation["f1"], validation["e2e.hit@3"], score, best_epoch, history[-1]["seconds"])
    checkpoint = torch.load(out / "best.pt", weights_only=True, map_location="cpu")
    model.load_state_dict(checkpoint["state"])
    final, predictions = evaluate_joint(model, folder, splits["test"])
    (out / "test_predictions.json").write_text(json.dumps(predictions, indent=2, allow_nan=False) + "\n")
    results = dict(final=final, best_epoch=best_epoch, best_validation_score=best,
                   epochs=epochs, test_evaluations=1, seconds=time.monotonic() - started,
                   manifest_sha256=params["manifest_sha256"], checkpoint_sha256=sha256((out / "best.pt").read_bytes()),
                   caveats=manifest["caveats"])
    (out / "metrics.json").write_text(json.dumps(results, indent=2, allow_nan=False) + "\n")
    logging.info("FINAL %s", json.dumps(results, allow_nan=False))
    logging.info("FINISHED: %s", out.resolve())
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=ROOT / "dataset/processed/joint")
    parser.add_argument("--out", type=Path, default=ROOT / "artifacts/joint")
    parser.add_argument("--epochs", type=int, default=25)
    args = parser.parse_args()
    try:
        main(args.dataset, args.out, args.epochs)
    except (Exception, KeyboardInterrupt):
        logging.exception("FAILED: conserva este registro y compártelo para revisar el error")
        raise SystemExit(1)
