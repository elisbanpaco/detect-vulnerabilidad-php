"""Inferencia del modelo conjunto v2; salida por archivo y por línea, sin ejecutar PHP."""
import argparse
import json
from pathlib import Path

import torch
import phpgraph
from audit_corpus import ROOT
from joint_graph import GRAPH_VERSION, build_joint_graph
from joint_model import JointPHPGuard


def analyze_joint(code, checkpoint_path):
    checkpoint = torch.load(checkpoint_path, weights_only=True, map_location="cpu")
    if checkpoint.get("version") != 2 or checkpoint["graph_version"] != GRAPH_VERSION:
        raise ValueError("Se requiere un checkpoint conjunto v2")
    phpgraph.load_vocab(checkpoint["vocab"])
    model = JointPHPGuard(checkpoint["n_types"], **checkpoint["model_config"])
    model.load_state_dict(checkpoint["state"])
    model.eval()
    graph = build_joint_graph(code)
    with torch.no_grad():
        file_logit, line_logits, line_ids = model(graph)
    ranking = sorted(zip(line_ids.tolist(), torch.sigmoid(line_logits).tolist()), key=lambda item: (-item[1], item[0]))[:5]
    probability = torch.sigmoid(file_logit).item()
    return dict(probability=probability, verdict="MALICIOSO" if probability > .5 else "LIMPIO",
                n_nodes=graph["type"].numel(), truncated=False, parse_error=graph["parse_error"],
                top_lines=[dict(line=line, score=score) for line, score in ranking])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--checkpoint", type=Path, default=ROOT / "artifacts/joint/best.pt")
    args = parser.parse_args()
    torch.set_num_threads(4)
    print(json.dumps(analyze_joint(args.file.read_bytes(), args.checkpoint), indent=2))
