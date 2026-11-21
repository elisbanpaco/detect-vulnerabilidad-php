"""Inferencia: archivo PHP -> veredicto + líneas sospechosas (localización). Uso: python3 detect.py archivo.php"""
import os
import hashlib
import sys
import torch
from torch_geometric.data import Data, Batch

import phpgraph
from model import PHPGuard, node_saliency

HERE = os.path.dirname(os.path.abspath(__file__))
CHECKPOINT_PATH = os.path.abspath(os.environ.get("PHPGUARD_CHECKPOINT", os.path.join(HERE, "phpguard.pt")))
with open(CHECKPOINT_PATH, "rb") as f:
    CHECKPOINT_SHA256 = hashlib.file_digest(f, "sha256").hexdigest()
_ckpt = torch.load(CHECKPOINT_PATH, weights_only=True, map_location="cpu")
phpgraph.load_vocab(_ckpt["vocab"])
_model = PHPGuard(_ckpt["n_types"])
_model.load_state_dict(_ckpt["state"])
_model.eval()
_inv = {v: k for k, v in _ckpt["vocab"].items()}
THRESHOLD = 0.5


def analyze(code: bytes, top_k: int = 8):
    g = phpgraph.build_graph(code, grow_vocab=False)
    data = Data(type=g["type"], sens=g["sens"], flags=g["flags"], edge_index=g["edge_index"],
                num_nodes=g["type"].numel())
    data = Batch.from_data_list([data])
    scores, prob = node_saliency(_model, data)
    n_lines = code.count(b"\n") + 1
    line_score = [0.0] * (n_lines + 2)
    for s, ln, en in zip(scores.tolist(), g["lines"].tolist(), g["ends"].tolist()):
        if en == ln:  # solo nodos de una línea: evita que bloques grandes (clases/funciones) coloreen todo
            line_score[ln] = max(line_score[ln], s)
    mx = max(line_score) or 1.0
    line_score = [x / mx for x in line_score]
    ranked = sorted(range(1, n_lines + 1), key=lambda i: -line_score[i])[:top_k]
    text_lines = code.decode("utf8", "ignore").split("\n")
    # subgrafo para visualización (máx. 220 nodos: los más influyentes)
    sc = scores.tolist()
    keep = sorted(range(len(sc)), key=lambda i: -sc[i])[:220]
    kset = set(keep)
    ei = g["edge_index"].tolist()
    edges = sorted({(a, b) for a, b in zip(ei[0], ei[1]) if a < b and a in kset and b in kset})
    graph = dict(
        nodes=[dict(id=i, type=_inv.get(int(g["type"][i]), "?"), score=round(sc[i], 3),
                    line=int(g["lines"][i])) for i in keep],
        edges=[dict(s=a, t=b) for a, b in edges],
    )
    return dict(
        graph=graph,
        probability=prob,
        verdict="MALICIOSO" if prob > THRESHOLD else "LIMPIO",
        n_nodes=int(g["type"].numel()),
        n_edges=int(g["edge_index"].shape[1]),
        line_scores=line_score[1:n_lines + 1],
        top_lines=[dict(line=i, score=round(line_score[i], 3), code=text_lines[i - 1][:160].strip())
                   for i in ranked if line_score[i] > 0 and i - 1 < len(text_lines)],
        sensitive_hits=sorted({phpgraph.SENSITIVE[s - 1] for s in g["sens"].tolist() if s > 0}),
    )


if __name__ == "__main__":
    r = analyze(open(sys.argv[1], "rb").read())
    print(f"{r['verdict']}  p={r['probability']:.3f}  nodos={r['n_nodes']}")
    for t in r["top_lines"]:
        print(f"  L{t['line']:>4}  {t['score']:.2f}  {t['code']}")
