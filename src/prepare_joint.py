"""Prepara entrenamiento mixto completo, sin reutilizar las bases del diagnóstico."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import random
import tempfile

import torch
import phpgraph
from audit_corpus import ROOT, graph_hash, sha256, token_hash
from build_localization import PATTERNS, POSITIONS, insert, insertion_points, payload
from joint_graph import GRAPH_VERSION, build_joint_graph
from prepare_data import SPLIT_REPOS

SOURCE_FILES = ("prepare_joint.py", "joint_graph.py", "joint_model.py", "train_joint.py", "phpgraph.py",
                "build_localization.py", "evaluate_localization.py", "audit_corpus.py")


def source_hashes():
    return {name: sha256(Path(__file__).with_name(name).read_bytes()) for name in SOURCE_FILES}


def main(audit, diagnostic, out, training_bases=30, validation_bases=15, test_bases=30):
    if out.exists():
        raise FileExistsError(out)
    if any(n < 3 or n % 3 for n in (training_bases, validation_bases, test_bases)):
        raise ValueError("Las cantidades de bases deben ser positivas y múltiplos de tres")
    torch.set_num_threads(4)
    rows = json.loads(audit.read_text())
    old_diagnostic = json.loads(diagnostic.read_text())
    diagnostic_groups = {c["group_id"] for c in old_diagnostic["cases"]}
    owners = defaultdict(set)
    for row in rows:
        owners[row["group_id"]].add(row["split"])
    exclusions, eligible = [], []
    for row in rows:
        reason = ("previous_diagnostic_group" if row["group_id"] in diagnostic_groups else
                  "cross_split_group" if len(owners[row["group_id"]]) != 1 else
                  "normalization_label_conflict" if row["group_has_label_conflict"] else None)
        if reason:
            exclusions.append(dict(path=row["path"], reason=reason))
        else:
            eligible.append(row)
    cases, contents, used_groups, bases = [], {}, set(), []

    def add(row, code, kind, gold, supervised, **extra):
        if len(code) > 200_000:
            raise ValueError("generated_size_limit")
        case_id = sha256((row["sha256"] + kind + json.dumps(extra, sort_keys=True)).encode())[:20]
        cases.append(dict(case_id=case_id, split=row["split"], repo=row["repo"], group_id=row["group_id"],
                          source_path=row["path"], source_sha256=row["sha256"], sha256=sha256(code),
                          label=int(kind == "malicious" or kind == "collected_malicious"), kind=kind,
                          malicious_lines=gold, line_supervised=supervised,
                          annotation_status="complete_controlled" if supervised else "source_label_only", **extra))
        contents[case_id] = code

    rng = random.Random(0)
    for repo, count in (("wordpress", training_bases), ("laravel", training_bases),
                        ("composer", validation_bases), ("phpMyAdmin", test_bases)):
        candidates = sorted((r for r in eligible if r["repo"] == repo),
                            key=lambda r: ((ROOT / r["path"]).stat().st_size, r["path"]))
        for stratum in range(3):
            bucket = candidates[len(candidates) * stratum // 3:len(candidates) * (stratum + 1) // 3]
            rng.shuffle(bucket)
            accepted = 0
            for row in bucket:
                if accepted == count // 3:
                    break
                if row["group_id"] in used_groups:
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
                            for positive in (False, True):
                                block, relative = payload(pattern, positive, key)
                                generated, gold, size = insert(code, offset, block, relative)
                                if len(generated) > 200_000:
                                    raise ValueError("generated_size_limit")
                                variants.append((generated, "malicious" if positive else "constant_control",
                                                 gold if positive else [], pattern, position, offset, size))
                except ValueError as error:
                    exclusions.append(dict(path=row["path"], reason=str(error)))
                    continue
                add(row, code, "original", [], True, pattern="none", position="original", size_stratum=stratum)
                for generated, kind, gold, pattern, position, offset, size in variants:
                    add(row, generated, kind, gold, True, pattern=pattern, position=position,
                        size_stratum=stratum, insertion_byte=offset, insertion_length=size)
                used_groups.add(row["group_id"])
                bases.append(dict(path=row["path"], split=row["split"], group_id=row["group_id"], stratum=stratum))
                accepted += 1
            if accepted != count // 3:
                raise ValueError(f"Bases válidas insuficientes: {repo}, tercil {stratum}: {accepted}/{count // 3}")
    raw_groups = set()
    for row in sorted(eligible, key=lambda r: r["path"]):
        if row["label"] != 1 or row["group_id"] in raw_groups:
            continue
        code = (ROOT / row["path"]).read_bytes()
        if sha256(code) != row["sha256"]:
            raise ValueError(f"Fuente modificada: {row['path']}")
        if phpgraph._parser.parse(code).root_node.has_error:
            exclusions.append(dict(path=row["path"], reason="collected_parse_error"))
            continue
        add(row, code, "collected_malicious", [], False, pattern="unreviewed_collection", position="original")
        raw_groups.add(row["group_id"])
    cases.sort(key=lambda c: (list(SPLIT_REPOS).index(c["split"]), c["case_id"]))
    for split in SPLIT_REPOS:
        if {c["label"] for c in cases if c["split"] == split} != {0, 1}:
            raise ValueError(f"Falta una clase en {split}")
    fingerprints = {"sha256": {}, "tokens": {}, "graph": {}}
    phpgraph.load_vocab({"<unk>": 0})
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".joint-", dir=out.parent) as temp:
        staging = Path(temp) / "joint"
        (staging / "graphs").mkdir(parents=True)
        (staging / "files").mkdir()
        for i, case in enumerate(cases, 1):
            code = contents[case["case_id"]]
            graph = build_joint_graph(code, grow_vocab=case["split"] == "train")
            line_ids = torch.unique(graph["lines"], sorted=True)
            gold = set(case["malicious_lines"])
            if graph["truncated"] or not gold.issubset(line_ids.tolist()):
                raise ValueError(f"Líneas anotadas sin cobertura: {case['case_id']}")
            graph["line_target"] = torch.tensor([float(line in gold) for line in line_ids.tolist()])
            for kind, digest in (("sha256", case["sha256"]), ("tokens", token_hash(code)), ("graph", graph_hash(graph))):
                previous = fingerprints[kind].setdefault(digest, case["split"])
                if previous != case["split"]:
                    raise ValueError(f"Colisión {kind} entre {previous} y {case['split']}; no se publica el dataset")
            graph_path = f"graphs/{case['case_id']}.pt"
            torch.save(graph, staging / graph_path)
            case.update(graph_path=graph_path, graph_file_sha256=sha256((staging / graph_path).read_bytes()),
                        file_path=f"files/{case['case_id']}.php", n_nodes=graph["type"].numel(),
                        represented_lines=line_ids.numel(), positive_lines=len(gold),
                        flow_edges=graph["flow_edges"])
            (staging / case["file_path"]).write_bytes(code)
            if i % 100 == 0:
                print(f"prepare joint {i}/{len(cases)}", flush=True)
        summary = {split: dict(files=sum(c["split"] == split for c in cases),
                       kinds=dict(Counter(c["kind"] for c in cases if c["split"] == split)),
                       bases=sum(b["split"] == split for b in bases),
                       largest_graph=max(c["n_nodes"] for c in cases if c["split"] == split),
                       line_positives=sum(c["positive_lines"] for c in cases if c["split"] == split),
                       supervised_lines=sum(c["represented_lines"] for c in cases if c["split"] == split and c["line_supervised"]))
                   for split in SPLIT_REPOS}
        manifest = dict(version=2, graph_version=GRAPH_VERSION, vocab=phpgraph.vocab_state(), cases=cases,
                        bases=bases, exclusions=exclusions, summary=summary, source_sha256=source_hashes(),
                        audit_sha256=sha256(audit.read_bytes()), diagnostic_sha256=sha256(diagnostic.read_bytes()),
                        seed=0, max_nodes=None, max_bytes=200000,
                        caveats=["Controlled templates are shared across splits; this tests new bases, not unseen payload families.",
                                 "Collected labels are inherited and have no line supervision or independent human validation.",
                                 "Lexical def/use links do not implement branch-sensitive or interprocedural taint analysis.",
                                 "This is a new controlled cohort, not an external blind deployment test."])
        (staging / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        staging.rename(out)
    print(json.dumps(summary, indent=2), flush=True)
    print(f"READY: {out / 'manifest.json'}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, default=ROOT / "artifacts/localization/audit/inventory.json")
    parser.add_argument("--diagnostic", type=Path, default=ROOT / "dataset/processed/localization/manifest.json")
    parser.add_argument("--out", type=Path, default=ROOT / "dataset/processed/joint")
    parser.add_argument("--training-bases", type=int, default=30)
    parser.add_argument("--validation-bases", type=int, default=15)
    parser.add_argument("--test-bases", type=int, default=30)
    args = parser.parse_args()
    main(args.audit, args.diagnostic, args.out, args.training_bases, args.validation_bases, args.test_bases)
