"""GNN con supervisión por línea; el máximo logit de línea determina la detección."""
import torch
from torch import nn
import torch.nn.functional as F
from torch_geometric.nn import GATv2Conv
from torch_geometric.utils import scatter

from phpgraph import N_SENS


class JointPHPGuard(nn.Module):
    def __init__(self, n_types, hid=64, heads=4, layers=3, drop=0.2):
        super().__init__()
        self.type_emb = nn.Embedding(n_types, hid)
        self.sens_emb = nn.Embedding(N_SENS, hid)
        self.flag_lin = nn.Linear(5, hid)
        self.convs = nn.ModuleList([GATv2Conv(hid, hid // heads, heads=heads, dropout=drop) for _ in range(layers)])
        self.norms = nn.ModuleList([nn.LayerNorm(hid) for _ in range(layers)])
        self.line_head = nn.Linear(hid, 1)
        self.drop = drop

    def forward(self, graph):
        x = self.type_emb(graph["type"]) + self.sens_emb(graph["sens"]) + self.flag_lin(graph["flags"])
        for conv, norm in zip(self.convs, self.norms):
            x = norm(x + F.dropout(F.elu(conv(x, graph["edge_index"])), self.drop, self.training))
        line_ids, inverse = torch.unique(graph["lines"], sorted=True, return_inverse=True)
        line_logits = self.line_head(scatter(x, inverse, dim=0, reduce="mean")).squeeze(-1)
        return line_logits.max().reshape(1), line_logits, line_ids
