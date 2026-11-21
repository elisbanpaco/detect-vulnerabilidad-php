"""Compara GNN, regla y bolsa AST en un benchmark congelado; solo análisis estático."""
import argparse
from collections import defaultdict
import json
import os
from pathlib import Path
import sys

import joblib
import numpy as np
import torch
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

import phpgraph
from audit_corpus import ROOT, graph_hash, sha256
from build_localization import METHODS, PATTERNS, POSITIONS


def bag_features(graph, n_types):
    n = graph["type"].numel()
    return np.concatenate((np.bincount(graph["type"].numpy(), minlength=n_types),
                           np.bincount(graph["sens"].numpy(), minlength=phpgraph.N_SENS),
                           graph["flags"].numpy().sum(axis=0))) / n


def ranked_lines(scores):
    return sorted((i + 1 for i, value in enumerate(scores) if value > 0), key=lambda line: (-scores[line - 1], line))[:5]


def localization_metrics(gold, ranking):
    gold = set(gold)
    if not gold:
        raise ValueError("Se requieren líneas positivas para medir localización")
    selected = set(ranking[:5])
    return {**{f"hit@{k}": float(bool(gold.intersection(ranking[:k]))) for k in (1, 3, 5)},
            "recall@5": len(gold & selected) / len(gold),
            "iou@5": len(gold & selected) / len(gold | selected)}


def summary_statistics(rows, bootstrap=1000):
    """Bootstrap por grupo: todas las variantes de una base reciben el mismo peso."""
    excluded = sum(r["annotation_status"] == "ambiguous" for r in rows)
    rows = [r for r in rows if r["annotation_status"] != "ambiguous"]
    if not rows:
        return dict(n=0, ambiguous_excluded=excluded)
    groups = sorted({r["group_id"] for r in rows})
    group_index = {group: i for i, group in enumerate(groups)}
    idx = np.array([group_index[r["group_id"]] for r in rows])
    labels = np.array([r["label"] for r in rows])
    predicted = np.array([r["predicted"] for r in rows])
    scores = np.array([r["score"] for r in rows])
    keys = ["tn", "fp", "fn", "tp", "complete_n", "conditional_n", "partial_n", "partial_conditional_n"]
    loc_keys = ["hit@1", "hit@3", "hit@5", "recall@5", "iou@5"]
    keys += [prefix + key for prefix in ("e2e.", "conditional.", "partial.", "partial_conditional.")
             for key in loc_keys if "partial" not in prefix or key.startswith("hit")]
    values = np.zeros((len(groups), len(keys)))
    for i, row in enumerate(rows):
        data = dict.fromkeys(keys, 0.0)
        data[["tn", "fp", "fn", "tp"][2 * row["label"] + row["predicted"]]] = 1
        if row["label"] and row["malicious_lines"]:
            metrics = localization_metrics(row["malicious_lines"], row["ranking"])
            partial = row["annotation_status"] == "partial_assisted"
            data["partial_n" if partial else "complete_n"] = 1
            data["partial_conditional_n" if partial else "conditional_n"] = row["predicted"]
            for key, value in metrics.items():
                if partial and not key.startswith("hit"):
                    continue
                data[("partial." if partial else "e2e.") + key] = value * row["predicted"]
                data[("partial_conditional." if partial else "conditional.") + key] = value * row["predicted"]
        values[idx[i]] += [data[key] for key in keys]
    rng = np.random.default_rng(0)
    weights = np.vstack((np.ones(len(groups)), rng.multinomial(len(groups), np.full(len(groups), 1 / len(groups)), size=bootstrap)))
    totals = weights @ values
    columns = {key: totals[:, i] for i, key in enumerate(keys)}

    def divide(numerator, denominator, undefined=np.nan):
        return np.divide(numerator, denominator, out=np.full_like(numerator, undefined), where=denominator > 0)

    tn, fp, fn, tp = (columns[key] for key in ("tn", "fp", "fn", "tp"))
    two_classes = (tp + fn > 0) & (tn + fp > 0)
    arrays = {
        "accuracy": np.where(two_classes, divide(tp + tn, tp + tn + fp + fn), np.nan),
        "precision": np.where(two_classes, divide(tp, tp + fp, 0), np.nan),
        "recall": divide(tp, tp + fn), "fpr": divide(fp, fp + tn),
        "f1": np.where(two_classes, divide(2 * tp, 2 * tp + fp + fn), np.nan),
    }
    if all(r["continuous_score"] for r in rows) and two_classes[0]:
        pos, neg = np.flatnonzero(labels == 1), np.flatnonzero(labels == 0)
        pair_credit = (scores[pos, None] > scores[None, neg]).astype(float) + 0.5 * (scores[pos, None] == scores[None, neg])
        credit = np.zeros((len(groups), len(groups)))
        np.add.at(credit, (np.broadcast_to(idx[pos, None], pair_credit.shape).ravel(),
                           np.broadcast_to(idx[None, neg], pair_credit.shape).ravel()), pair_credit.ravel())
        arrays["auc"] = divide(np.einsum("bi,ij,bj->b", weights, credit, weights), (tp + fn) * (tn + fp))
    for prefix, denominator in (("e2e.", "complete_n"), ("conditional.", "conditional_n"),
                                ("partial.", "partial_n"), ("partial_conditional.", "partial_conditional_n")):
        for key in loc_keys:
            if prefix + key in columns:
                arrays[prefix + key] = divide(columns[prefix + key], columns[denominator])
    result = dict(n=len(rows), groups=len(groups), ambiguous_excluded=excluded,
                  confusion_matrix=[[int(tn[0]), int(fp[0])], [int(fn[0]), int(tp[0])]],
                  complete_localization_n=int(columns["complete_n"][0]),
                  conditional_localization_n=int(columns["conditional_n"][0]),
                  partial_localization_n=int(columns["partial_n"][0]),
                  metrics={}, ci95={}, bootstrap_replicates=bootstrap)
    for key, array in arrays.items():
        result["metrics"][key] = float(array[0]) if np.isfinite(array[0]) else None
        samples = array[1:][np.isfinite(array[1:])]
        result["ci95"][key] = np.quantile(samples, [0.025, 0.975]).tolist() if len(groups) > 1 and len(samples) else None
    return result


def aggregate_predictions(predictions, bootstrap=1000):
    reports = {}
    for method in METHODS:
        own = [r for r in predictions if r["method"] == method]
        for kind in ("controlled", "real"):
            subset = [r for r in own if r["dataset_kind"] == kind]
            reports[f"{kind}/{method}/all"] = summary_statistics(subset, bootstrap)
            for truncated in (False, True):
                reports[f"{kind}/{method}/truncated={truncated}"] = summary_statistics(
                    [r for r in subset if r["truncated"] == truncated], bootstrap)
            if kind == "controlled":
                for field, categories in (("pattern", PATTERNS), ("position", POSITIONS),
                                          ("kind", ("original", "constant_control", "malicious"))):
                    for category in categories:
                        reports[f"{kind}/{method}/{field}={category}"] = summary_statistics(
                            [r for r in subset if r[field] == category], bootstrap)
    return reports


def main(benchmark, dataset, out):
    if out.exists():
        raise FileExistsError(out)
    manifest_path = benchmark / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    protocol = manifest["protocol"]
    for name, expected in protocol["source_sha256"].items():
        if sha256((ROOT / "src" / name).read_bytes()) != expected:
            raise ValueError(f"Código modificado después de congelar el protocolo: {name}")
    checkpoint = Path(protocol["checkpoint_path"])
    if sha256(checkpoint.read_bytes()) != protocol["checkpoint_sha256"] or sha256(dataset.read_bytes()) != protocol["dataset_sha256"]:
        raise ValueError("Checkpoint o dataset diferentes del protocolo congelado")
    if protocol["methods"] != METHODS or protocol["max_nodes"] != phpgraph.MAX_NODES:
        raise ValueError("El protocolo no coincide con los métodos actuales")
    torch.set_num_threads(4)
    torch.use_deterministic_algorithms(True)
    os.environ["PHPGUARD_CHECKPOINT"] = str(checkpoint)
    if "detect" in sys.modules:
        raise RuntimeError("Ejecutar el evaluador en un proceso nuevo para seleccionar el checkpoint")
    import detect
    if detect.CHECKPOINT_SHA256 != protocol["checkpoint_sha256"]:
        raise ValueError("El detector cargó un checkpoint diferente")
    ds = torch.load(dataset, weights_only=True, map_location="cpu")
    if ds["vocab"] != phpgraph.vocab_state():
        raise ValueError("Vocabularios diferentes")
    n_types = len(ds["vocab"])
    train = [g for g in ds["graphs"] if g["split"] == "train"]
    settings = METHODS["logreg"]
    linear = make_pipeline(StandardScaler(), LogisticRegression(
        C=settings["C"], class_weight=settings["class_weight"], max_iter=settings["max_iter"], random_state=settings["random_state"]))
    linear.fit(np.stack([bag_features(g, n_types) for g in train]), [g["y"] for g in train])
    classifier = linear[-1]
    if classifier.n_iter_.max() >= settings["max_iter"]:
        raise RuntimeError("La regresión logística no convergió; no se presentan resultados incompletos")
    coefficients = classifier.coef_[0] / linear[0].scale_
    out.mkdir(parents=True)
    joblib.dump(linear, out / "logreg.joblib")
    predictions, graph_groups = [], defaultdict(list)
    for i, case in enumerate(manifest["cases"], 1):
        path = (benchmark / case["path"]).resolve()
        if not path.is_relative_to(benchmark.resolve()):
            raise ValueError("Ruta fuera del benchmark")
        code = path.read_bytes()
        if sha256(code) != case["sha256"]:
            raise ValueError(f"Caso modificado: {case['case_id']}")
        graph = phpgraph.build_graph(code)
        graph_groups[graph_hash(graph)].append(case)
        n_lines = code.count(b"\n") + 1
        node_lines = graph["lines"].numpy() - 1
        types, sensitive, flags = graph["type"].numpy(), graph["sens"].numpy(), graph["flags"].numpy()
        gnn = detect.analyze(code)
        linear_scores = np.zeros(n_lines)
        contributions = coefficients[types] + coefficients[n_types + sensitive] + flags @ coefficients[n_types + phpgraph.N_SENS:]
        np.add.at(linear_scores, node_lines, contributions / len(types))
        linear_scores = np.maximum(linear_scores, 0)
        rule_scores = np.zeros(n_lines)
        np.add.at(rule_scores, node_lines, 2 * (sensitive > 0) + flags[:, 0])
        outputs = {"gnn": (gnn["probability"], gnn["line_scores"]),
                   "rule": (float((sensitive > 0).any() and (flags[:, 0] > 0).any()), rule_scores),
                   "logreg": (float(linear.predict_proba(bag_features(graph, n_types)[None])[0, 1]), linear_scores)}
        for method, (score, line_scores) in outputs.items():
            ranking = ranked_lines(line_scores)
            mask = graph["lines"] == graph["ends"] if method == "gnn" else torch.ones(len(types), dtype=torch.bool)
            represented = set(graph["lines"][mask].tolist())
            predictions.append(dict(**case, method=method, score=float(score), continuous_score=method != "rule",
                                    predicted=int(score > protocol["threshold"]), ranking=ranking,
                                    top_scores=[float(line_scores[line - 1]) for line in ranking],
                                    gold_lines_represented=sorted(set(case["malicious_lines"]) & represented),
                                    truncated=graph["truncated"], n_nodes=len(types)))
        if i % 25 == 0:
            print(f"evaluate {i}/{len(manifest['cases'])}", flush=True)
    with (out / "predictions.jsonl").open("w") as f:
        for row in predictions:
            f.write(json.dumps(row, allow_nan=False) + "\n")
    errors = []
    for row in predictions:
        if row["annotation_status"] == "ambiguous":
            continue
        classification_error = row["label"] != row["predicted"]
        localization_miss = bool(row["label"] and row["malicious_lines"] and
            (not row["predicted"] or not set(row["ranking"][:3]).intersection(row["malicious_lines"])))
        if classification_error or localization_miss:
            lines = (benchmark / row["path"]).read_bytes().decode("utf-8", errors="replace").split("\n")
            inspect_lines = sorted(set(row["ranking"]) | set(row["malicious_lines"]))
            errors.append(dict(case_id=row["case_id"], method=row["method"], classification_error=classification_error,
                               localization_miss_at_3=localization_miss,
                               lines={str(line): lines[line - 1][:300] for line in inspect_lines}))
    reports = aggregate_predictions(predictions, protocol["bootstrap"]["replicates"])
    collisions = [dict(graph_sha256=digest, case_ids=[c["case_id"] for c in cases],
                       labels=sorted({c["label"] for c in cases})) for digest, cases in graph_groups.items()
                  if len({c["label"] for c in cases}) > 1]
    results = dict(manifest_sha256=sha256(manifest_path.read_bytes()), checkpoint_sha256=detect.CHECKPOINT_SHA256,
                   purpose=protocol["purpose"], annotation_warning="Real annotations are assisted, not independent human ground truth; real set has no confirmed negative class.",
                   reports=reports, conflicting_input_graphs=collisions)
    (out / "metrics.json").write_text(json.dumps(results, indent=2, allow_nan=False) + "\n")
    (out / "errors.json").write_text(json.dumps(errors, indent=2, allow_nan=False) + "\n")
    (out / "frozen_manifest.json").write_bytes(manifest_path.read_bytes())
    for key in (f"{kind}/{method}/all" for kind in ("controlled", "real") for method in METHODS):
        print(key, json.dumps(reports[key], allow_nan=False), flush=True)
    print("Conflicting exact graph inputs:", len(collisions), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", type=Path, default=ROOT / "dataset/processed/localization")
    parser.add_argument("--dataset", type=Path, default=ROOT / "dataset/processed/graphs.pt")
    parser.add_argument("--out", type=Path, default=ROOT / "artifacts/localization/results")
    args = parser.parse_args()
    main(args.benchmark, args.dataset, args.out)
