"""Congela un benchmark diagnóstico real/controlado sin ejecutar PHP."""
import argparse
from collections import Counter
import json
from pathlib import Path
import random

import torch
import phpgraph
from audit_corpus import ROOT, graph_hash, sha256, token_hash

PATTERNS = ("command", "eval", "write_php")
POSITIONS = ("begin", "middle", "end")
METHODS = {
    "gnn": {"localization": "0.5 attention + 0.5 gradient-times-input; single-line nodes; max by line"},
    "rule": {"detection": "sensitive name AND superglobal anywhere in represented AST",
             "ranking": "2 per sensitive node + 1 per superglobal node, assigned to node start line"},
    "logreg": {"features": "AST type counts + sensitive counts + flag sums, divided by node count",
               "scaling": "StandardScaler fitted on original train only", "C": 1.0,
               "class_weight": "balanced", "max_iter": 2000, "random_state": 0,
               "ranking": "positive summed linear contribution of nodes starting on each line"},
}


def payload(pattern, malicious, key):
    variable = "$v_" + key
    value = f"$_POST['{key}']" if malicious else {
        "command": "'date'", "eval": "'return 1;'", "write_php": "'<?php return 1;'"}[pattern]
    sink = {"command": f"\\system({variable});", "eval": f"eval({variable});",
            "write_php": f"\\file_put_contents(__DIR__ . '/cache.php', {variable});"}[pattern]
    code = f"if (isset($_POST['{key}'])) {{\n    {variable} = {value};\n    {sink}\n}}"
    return code.encode(), [1, 2]  # Índices desde cero: asignación de la fuente y operación consumidora.


def insertion_points(code):
    root = phpgraph._parser.parse(code).root_node
    if root.has_error:
        raise ValueError("original_parse_error")
    points = set()
    stack = [root]
    while stack:
        node = stack.pop()
        braced_namespace = node.type == "program" and any(
            c.type == "namespace_definition" and c.child_by_field_name("body") is not None
            for c in node.named_children)
        if node.type in {"program", "compound_statement"} and not braced_namespace:
            for child in node.named_children:
                if child.type not in {"php_tag", "comment", "namespace_definition", "declare_statement", "text", "text_interpolation"}:
                    points.add(child.start_byte)
            if node.type == "compound_statement" and node.children[-1].type == "}":
                points.add(node.children[-1].start_byte)
            if node.type == "program" and node.children:
                last = node.children[-1]
                if last.type not in {"text", "text_interpolation", "php_end_tag"}:
                    points.add(last.end_byte)
        stack.extend(reversed(node.named_children))
    # Se prueban los límites sin consultar predicciones. La inserción debe quedar dentro de PHP.
    ordered = sorted(points)
    valid = []
    probe = b"if (isset($_POST['probe'])) { $v = $_POST['probe']; system($v); }"
    for target in (0, len(ordered) // 2, len(ordered) - 1):
        for index in sorted(range(len(ordered)), key=lambda i: (abs(i - target), i)):
            offset = ordered[index]
            if offset in valid:
                continue
            try:
                insert(code, offset, probe, [0])
                valid.append(offset)
                break
            except ValueError:
                continue
    if len(valid) < 3:
        raise ValueError("fewer_than_three_valid_statement_boundaries")
    return sorted(valid)


def insert(code, offset, block, positive_offsets):
    if not 0 <= offset <= len(code):
        raise ValueError("invalid_insertion_offset")
    patch = b"\n" + block + b"\n"
    result = code[:offset] + patch + code[offset:]
    if result[:offset] + result[offset + len(patch):] != code:
        raise ValueError("non_reversible_insertion")
    root = phpgraph._parser.parse(result).root_node
    if root.has_error:
        raise ValueError("modified_parse_error")
    stack, has_call = [root], False
    while stack:
        node = stack.pop()
        if offset <= node.start_byte and node.end_byte <= offset + len(patch):
            has_call |= node.type == "function_call_expression"
        if node.end_byte >= offset and node.start_byte <= offset + len(patch):
            stack.extend(node.named_children)
    if not has_call:
        raise ValueError("insertion_is_not_php_code")
    first_line = code[:offset].count(b"\n") + 2
    return result, [first_line + index for index in positive_offsets], len(patch)


def overlaps_training(code, graph, blocked):
    fingerprints = {"sha256": sha256(code), "graph_sha256": graph_hash(graph),
                    "tokens_sha256": token_hash(code)}
    return [kind for kind, value in fingerprints.items() if value in blocked[kind]]


def main(audit_dir, checkpoint, annotations, out):
    if out.exists():
        raise FileExistsError(out)
    ckpt = torch.load(checkpoint, weights_only=True, map_location="cpu")
    phpgraph.load_vocab(ckpt["vocab"])
    audit = json.loads((audit_dir / "inventory.json").read_text())
    blocked = {kind: {row[kind] for row in audit if row["group_has_train"]}
               for kind in ("sha256", "graph_sha256", "tokens_sha256")}
    by_path = {row["path"]: row for row in audit}
    candidates = sorted((r for r in audit if r["repo"] == "phpMyAdmin" and not r["excluded_from_benchmark"]),
                        key=lambda r: ((ROOT / r["path"]).stat().st_size, r["path"]))
    cases, contents, exclusions, selected = [], {}, [], []
    groups_used = set()
    rng = random.Random(0)

    def add_case(row, code, **metadata):
        digest = sha256(code)
        case_id = sha256((row["sha256"] + json.dumps(metadata, sort_keys=True)).encode())[:20]
        path = f"files/{case_id}.php"
        if case_id in contents:
            raise ValueError(f"case_id repetido: {case_id}")
        contents[case_id] = code
        cases.append(dict(case_id=case_id, path=path, sha256=digest, source_path=row["path"],
                          source_sha256=row["sha256"], source_repo=row["repo"],
                          group_id=row["group_id"], n_lines=code.count(b"\n") + 1,
                          annotated_line_fraction=len(set(metadata["malicious_lines"])) / (code.count(b"\n") + 1),
                          **metadata))

    for stratum in range(3):
        bucket = candidates[len(candidates) * stratum // 3:len(candidates) * (stratum + 1) // 3]
        rng.shuffle(bucket)
        accepted = 0
        for row in bucket:
            if accepted == 10:
                break
            if row["group_id"] in groups_used:
                exclusions.append(dict(path=row["path"], reason="base_group_already_selected"))
                continue
            code = (ROOT / row["path"]).read_bytes()
            if sha256(code) != row["sha256"]:
                raise ValueError(f"Fuente modificada: {row['path']}")
            try:
                offsets = insertion_points(code)
                variants = []
                for pattern in PATTERNS:
                    key = sha256((row["sha256"] + pattern).encode())[:10]
                    for position, offset in zip(POSITIONS, offsets, strict=True):
                        for malicious in (False, True):
                            block, positive_offsets = payload(pattern, malicious, key)
                            generated, positive_lines, patch_size = insert(code, offset, block, positive_offsets)
                            if len(generated) > 200_000:
                                raise ValueError("generated_size_limit")
                            graph = phpgraph.build_graph(generated)
                            overlap = overlaps_training(generated, graph, blocked)
                            if overlap:
                                raise ValueError("generated_overlap_with_train:" + ",".join(overlap))
                            variants.append((generated, dict(kind="malicious" if malicious else "constant_control",
                                pattern=pattern, position=position, label=int(malicious),
                                malicious_lines=positive_lines if malicious else [],
                                insertion_byte=offset, insertion_length=patch_size,
                                insertion_fraction=offset / len(code))))
            except ValueError as error:
                exclusions.append(dict(path=row["path"], reason=str(error)))
                continue
            common = dict(dataset_kind="controlled", size_stratum=stratum,
                          annotation_status="complete_controlled", independent_human_review=False,
                          runtime_reachability_tested=False)
            add_case(row, code, **common, kind="original", pattern="none", position="original",
                     label=0, malicious_lines=[], insertion_byte=None, insertion_length=0,
                     insertion_fraction=None)
            for generated, metadata in variants:
                add_case(row, generated, **common, **metadata)
            selected.append(dict(path=row["path"], sha256=row["sha256"], stratum=stratum,
                                 group_id=row["group_id"], offsets=offsets))
            groups_used.add(row["group_id"])
            accepted += 1
        if accepted != 10:
            raise ValueError(f"Solo {accepted}/10 bases válidas en tercil {stratum}; no se congela un benchmark incompleto")

    real_annotations = json.loads(annotations.read_text())
    real_count = 0
    for annotation in real_annotations["cases"][:20]:
        row = by_path[annotation["path"]]
        code = (ROOT / row["path"]).read_bytes()
        if row["label"] != 1:
            raise ValueError(f"La anotación real no procede de la colección maliciosa: {row['path']}")
        if sha256(code) != row["sha256"] or annotation["sha256"] != row["sha256"]:
            raise ValueError(f"Hash de anotación incorrecto: {row['path']}")
        if row["excluded_from_benchmark"] or overlaps_training(code, phpgraph.build_graph(code), blocked):
            exclusions.append(dict(path=row["path"], reason="real_overlap_with_training_group"))
            continue
        status = annotation["annotation_status"]
        lines = annotation["malicious_lines"]
        if status not in {"complete_assisted", "partial_assisted", "ambiguous"}:
            raise ValueError(f"Estado de anotación inválido: {status}")
        if not annotation["evidence"] or any(not 1 <= line <= code.count(b"\n") + 1 for line in lines):
            raise ValueError(f"Anotación inválida: {row['path']}")
        if status != "ambiguous" and not lines:
            raise ValueError(f"Faltan líneas maliciosas: {row['path']}")
        source_lines = code.decode("utf8", errors="replace").split("\n")
        for evidence in annotation["evidence"]:
            if not evidence["rationale"] or any(source_lines[int(line) - 1] != text
                    for line, text in evidence["source_lines"].items()):
                raise ValueError(f"Evidencia desalineada: {row['path']}")
        add_case(row, code, dataset_kind="real", kind="collected_webshell", pattern=annotation["behavior"],
                 position="original", label=1, malicious_lines=sorted(set(lines)), annotation_status=status,
                 independent_human_review=False, runtime_reachability_tested=False,
                 reviewer=annotation["reviewer"], evidence=annotation["evidence"])
        real_count += 1
    protocol = dict(version=1, purpose="diagnostic; not a fresh blind test or deployment validation",
                    seed=0, max_nodes=phpgraph.MAX_NODES, threshold=0.5, methods=METHODS,
                    localization_metrics=["hit@1", "hit@3", "hit@5", "recall@5", "iou@5"],
                    partial_policy="positive hits are lower bounds; no complete precision/recall/IoU",
                    bootstrap=dict(replicates=1000, seed=0, unit="base audit group; all paired variants together"),
                    checkpoint_path=str(checkpoint.resolve()), checkpoint_sha256=sha256(checkpoint.read_bytes()),
                    audit_inventory_sha256=sha256((audit_dir / "inventory.json").read_bytes()),
                    annotations_sha256=sha256(annotations.read_bytes()),
                    dataset_sha256=sha256((ROOT / "dataset/processed/graphs.pt").read_bytes()),
                    source_sha256={name: sha256((ROOT / "src" / name).read_bytes()) for name in (
                        "audit_corpus.py", "build_localization.py", "evaluate_localization.py", "detect.py", "model.py", "phpgraph.py")},
                    annotation_policy="controlled positives: source assignment + sink line; real labels assisted, not independently reviewed",
                    runtime_policy="static parsing only; insertion presence does not establish runtime reachability")
    manifest = dict(protocol=protocol, selected_bases=selected, cases=cases, exclusions=exclusions,
                    summary=dict(controlled=sum(c["dataset_kind"] == "controlled" for c in cases),
                                 real=real_count, labels=dict(Counter(c["label"] for c in cases)),
                                 real_status=dict(Counter(c["annotation_status"] for c in cases if c["dataset_kind"] == "real"))))
    out.mkdir(parents=True)
    (out / "files").mkdir()
    for case in cases:
        (out / case["path"]).write_bytes(contents[case["case_id"]])
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest["summary"], indent=2), flush=True)
    print("Manifest SHA-256:", sha256((out / "manifest.json").read_bytes()), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, default=ROOT / "artifacts/localization/audit")
    parser.add_argument("--checkpoint", type=Path, default=ROOT / "artifacts/baseline/phpguard.pt")
    parser.add_argument("--annotations", type=Path, default=ROOT / "dataset/localization_annotations.json")
    parser.add_argument("--out", type=Path, default=ROOT / "dataset/processed/localization")
    args = parser.parse_args()
    main(args.audit, args.checkpoint, args.annotations, args.out)
