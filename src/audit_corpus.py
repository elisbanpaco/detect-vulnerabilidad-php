"""Auditoría conservadora de bytes, entradas GNN y tokens; nunca ejecuta PHP."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

import torch
import phpgraph

ROOT = Path(__file__).resolve().parent.parent


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def graph_hash(graph):
    digest = hashlib.sha256()
    for key in ("type", "sens", "flags", "edge_index"):
        tensor = graph[key].contiguous()
        digest.update(f"{key}:{tensor.dtype}:{tuple(tensor.shape)}:".encode())
        digest.update(tensor.numpy().tobytes())
    return digest.hexdigest()


def token_hash(code):
    # shortcut: normalización sintáctica conservadora; no identifica familias ni equivalencia semántica.
    stack = [phpgraph._parser.parse(code).root_node]
    tokens = []
    atomic = {"name", "qualified_name", "namespace_name", "variable_name", "integer", "float",
              "string_content", "string_value"}
    while stack:
        node = stack.pop()
        if node.type == "comment":
            continue
        if node.type in atomic or not node.children:
            tokens.append(node.type)
        else:
            stack.extend(reversed(node.children))
    return sha256("\0".join(tokens).encode())


def group_rows(rows):
    parents = list(range(len(rows)))

    def find(i):
        while parents[i] != i:
            parents[i] = parents[parents[i]]
            i = parents[i]
        return i

    matches = []
    for kind in ("sha256", "graph_sha256", "tokens_sha256"):
        buckets = defaultdict(list)
        for i, row in enumerate(rows):
            buckets[row[kind]].append(i)
        for digest, indices in buckets.items():
            if len(indices) < 2:
                continue
            for i in indices[1:]:
                parents[find(i)] = find(indices[0])
            splits = sorted({rows[i]["split"] for i in indices})
            labels = sorted({rows[i]["label"] for i in indices})
            matches.append(dict(kind=kind, fingerprint=digest, count=len(indices), splits=splits,
                                labels=labels, paths=[rows[i]["path"] for i in indices],
                                assessment="identical_bytes" if kind == "sha256" else
                                "identical_model_input" if kind == "graph_sha256" else
                                "normalization_candidate_not_confirmed_clone_or_family"))
    components = defaultdict(list)
    for i in range(len(rows)):
        components[find(i)].append(i)
    for indices in components.values():
        group_id = min(rows[i]["sha256"] for i in indices)
        has_train = any(rows[i]["split"] == "train" for i in indices)
        conflicts = len({rows[i]["label"] for i in indices}) > 1
        for i in indices:
            rows[i].update(group_id=group_id, group_has_train=has_train,
                           group_has_label_conflict=conflicts,
                           excluded_from_benchmark=has_train)
    return matches


def main(dataset, out):
    if out.exists():
        raise FileExistsError(out)
    ds = torch.load(dataset, weights_only=True, map_location="cpu")
    rows = []
    for i, graph in enumerate(ds["graphs"], 1):
        path = ROOT / graph["path"]
        code = path.read_bytes()
        if sha256(code) != graph["sha256"]:
            raise ValueError(f"El archivo cambió desde la preparación: {path}")
        rows.append(dict(path=graph["path"], repo=graph["repo"], label=graph["y"], split=graph["split"],
                         sha256=graph["sha256"], graph_sha256=graph_hash(graph), tokens_sha256=token_hash(code)))
        if i % 500 == 0:
            print(f"audit {i}/{len(ds['graphs'])}", flush=True)
    matches = group_rows(rows)
    summary = dict(files=len(rows), unique_graph_inputs=len({r["graph_sha256"] for r in rows}),
                   matching_groups=dict(Counter(m["kind"] for m in matches)),
                   cross_split_groups=dict(Counter(m["kind"] for m in matches if len(m["splits"]) > 1)),
                   eligible_by_repo=dict(Counter(r["repo"] for r in rows if not r["excluded_from_benchmark"])),
                   graph_overlap_with_training={split: sum(
                       r["split"] == split and any(m["kind"] == "graph_sha256" and "train" in m["splits"]
                       and r["graph_sha256"] == m["fingerprint"] for m in matches) for r in rows)
                       for split in ("validation", "test")},
                   caveat="Token groups are conservative candidates, not verified clones or malware families.")
    out.mkdir(parents=True)
    (out / "inventory.json").write_text(json.dumps(rows, indent=2) + "\n")
    (out / "groups.json").write_text(json.dumps(matches, indent=2) + "\n")
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=ROOT / "dataset/processed/graphs.pt")
    parser.add_argument("--out", type=Path, default=ROOT / "artifacts/localization/audit")
    args = parser.parse_args()
    main(args.dataset, args.out)
