"""GNN para detección de código malicioso en PHP, con localización por atención y saliencia."""
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATv2Conv, global_mean_pool, global_max_pool
from torch_geometric.utils import softmax as pyg_softmax
from torch_geometric.nn import global_add_pool

from phpgraph import N_SENS


class PHPGuard(nn.Module):
    def __init__(self, n_types: int, hid: int = 64, heads: int = 4, layers: int = 3, drop: float = 0.2):
        super().__init__()
        self.type_emb = nn.Embedding(n_types, hid)
        self.sens_emb = nn.Embedding(N_SENS, hid)
        self.flag_lin = nn.Linear(5, hid)
        self.convs = nn.ModuleList()
        self.norms = nn.ModuleList()
        for _ in range(layers):
            self.convs.append(GATv2Conv(hid, hid // heads, heads=heads, dropout=drop))
            self.norms.append(nn.LayerNorm(hid))
        self.gate = nn.Linear(hid, 1)           # atención de nodo -> localización
        self.drop = drop
        self.head = nn.Sequential(nn.Linear(hid * 2, hid), nn.ReLU(), nn.Dropout(drop), nn.Linear(hid, 1))

    def embed(self, data):
        return self.type_emb(data.type) + self.sens_emb(data.sens) + self.flag_lin(data.flags)

    def forward(self, data, x0=None, return_nodes=False):
        x = self.embed(data) if x0 is None else x0
        for conv, norm in zip(self.convs, self.norms):
            h = conv(x, data.edge_index)
            h = F.dropout(F.elu(h), self.drop, self.training)
            x = norm(x + h)
        a = pyg_softmax(self.gate(x).squeeze(-1), data.batch)       # peso por nodo dentro de su grafo
        pooled_att = global_add_pool(x * a.unsqueeze(-1), data.batch)
        pooled_max = global_max_pool(x, data.batch)
        logit = self.head(torch.cat([pooled_att, pooled_max], dim=-1)).squeeze(-1)
        return (logit, a) if return_nodes else logit


def node_saliency(model, data):
    """Importancia por nodo = |grad(logit) · embedding| (para un solo grafo). Mezcla con atención."""
    model.eval()
    x0 = model.embed(data).detach().requires_grad_(True)
    logit, att = model(data, x0=x0, return_nodes=True)
    grad, = torch.autograd.grad(logit.sum(), x0)
    sal = (grad * x0).abs().sum(-1)
    sal = sal / (sal.max() + 1e-9)
    att = att.detach()
    att = att / (att.max() + 1e-9)
    return 0.5 * sal.detach() + 0.5 * att, torch.sigmoid(logit).item()
