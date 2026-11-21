"""AST completo y conexiones léxicas definición/uso, sin ejecutar PHP."""
from collections import defaultdict

import torch
import phpgraph

GRAPH_VERSION = "full_ast_lexical_def_use_v1"
SCOPES = {"function_definition", "method_declaration", "anonymous_function", "anonymous_function_creation_expression", "arrow_function"}
CONSUMERS = {"assignment_expression", "function_call_expression", "member_call_expression",
             "scoped_call_expression", "return_statement", "expression_statement"}


def build_joint_graph(code, grow_vocab=False):
    if not isinstance(code, bytes) or len(code) > 200_000:
        raise ValueError("Se requieren bytes PHP de hasta 200000 bytes; el código no se recorta")
    root = phpgraph._parser.parse(code).root_node
    nodes, parents, scopes, types, sensitive, flags, lines, ends = [], [], [], [], [], [], [], []
    ast = set()
    stack = [(root, -1, 0)]
    while stack:
        node, parent, scope = stack.pop()
        if node.type in SCOPES:
            scope = node.id
        index = len(nodes)
        nodes.append(node)
        parents.append(parent)
        scopes.append(scope)
        sens, superglobal, dynamic, long_string = phpgraph._token_flags(node, code)
        types.append(phpgraph.type_id(node.type, grow_vocab))
        sensitive.append(sens)
        flags.append([superglobal, dynamic, long_string, float(node.type == "ERROR"), min(node.child_count, 20) / 20])
        lines.append(node.start_point[0] + 1)
        ends.append(node.end_point[0] + 1)
        if parent >= 0:
            ast.update(((parent, index), (index, parent)))
        stack.extend((child, index, scope) for child in reversed(node.children))
    definitions = defaultdict(dict)
    flow = set()
    # shortcut: última asignación en orden léxico por ámbito; no es análisis de flujo sensible a ramas, alias o llamadas.
    for index in sorted(range(len(nodes)), key=lambda i: (nodes[i].end_byte, -nodes[i].start_byte)):
        node = nodes[index]
        scope = definitions[scopes[index]]
        if node.type == "variable_name":
            parent = parents[index]
            left = nodes[parent].child_by_field_name("left") if parent >= 0 and nodes[parent].type == "assignment_expression" else None
            if left is not None and left.id == node.id:
                continue
            name = code[node.start_byte:node.end_byte]
            consumer = parent
            while consumer >= 0 and nodes[consumer].type not in CONSUMERS:
                consumer = parents[consumer]
            if name in scope and consumer >= 0 and scope[name] != consumer:
                flow.update(((scope[name], consumer), (consumer, scope[name])))
        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            if left is not None and left.type == "variable_name":
                scope[code[left.start_byte:left.end_byte]] = index
    edges = sorted(ast | flow)
    edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous() if edges else torch.empty((2, 0), dtype=torch.long)
    return dict(type=torch.tensor(types, dtype=torch.long), sens=torch.tensor(sensitive, dtype=torch.long),
                flags=torch.tensor(flags, dtype=torch.float), edge_index=edge_index,
                lines=torch.tensor(lines, dtype=torch.long), ends=torch.tensor(ends, dtype=torch.long),
                truncated=False, parse_error=root.has_error, graph_version=GRAPH_VERSION,
                ast_edges=len(ast), flow_edges=len(flow - ast))
