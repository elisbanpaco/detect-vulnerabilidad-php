"""Identidades de fuentes y formas de llamada; no evalúa PHP ni resuelve constantes."""
from collections import Counter

import torch
import phpgraph
from joint_graph import build_joint_graph

SOURCE_NAMES = ["<none>", "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER", "$GLOBALS", "$_SESSION", "$_ENV"]
SOURCE_IDS = {name: index for index, name in enumerate(SOURCE_NAMES)}
CALL_NAMES = ["<none>", "named", "variable", "literal", "expression"]
GRAPH_VERSION = "full_ast_lexical_def_use_source_call_v3"


def inspect_code(code):
    root = phpgraph._parser.parse(code).root_node
    nodes, stack = [], [root]
    while stack:
        node = stack.pop()
        nodes.append(node)
        stack.extend(reversed(node.children))
    source_kind, call_kind = [], []
    sources, bitwise, constants = Counter(), Counter(), Counter()
    calls, indirect_variables = [], []
    for index, node in enumerate(nodes):
        text = code[node.start_byte:node.end_byte]
        source = SOURCE_IDS.get(text.decode('utf8', errors='replace'), 0) if node.type == "variable_name" else 0
        source_kind.append(source)
        if source:
            sources[SOURCE_NAMES[source]] += 1
        kind = 0
        if node.type == "function_call_expression":
            target = node.child_by_field_name("function")
            if target is not None:
                kind = (1 if target.type in {"name", "qualified_name", "relative_name"} else
                        2 if target.type in {"variable_name", "dynamic_variable_name", "subscript_expression"} else
                        3 if target.type in {"string", "encapsed_string"} else 4)
                calls.append(dict(index=index, line=node.start_point[0] + 1, kind=CALL_NAMES[kind],
                                  target_type=target.type,
                                  target=code[target.start_byte:target.end_byte].decode('utf8', errors='replace')[:160]))
        call_kind.append(kind)
        if node.type == "dynamic_variable_name":
            indirect_variables.append(dict(line=node.start_point[0] + 1, expression=text.decode('utf8', errors='replace')[:160]))
        if not node.children and node.type in {"^", "&", "|", "~"}:
            bitwise[node.type] += 1
        if node.type == "name" and node.parent is not None and node.parent.type in {
                "binary_expression", "unary_op_expression", "parenthesized_expression", "assignment_expression"}:
            constants[text.decode('utf8', errors='replace')] += 1
    return dict(source_kind=torch.tensor(source_kind, dtype=torch.long), call_kind=torch.tensor(call_kind, dtype=torch.long),
                sources=dict(sources), calls=calls, bitwise_operators=dict(bitwise),
                bare_constant_candidates=dict(constants), indirect_variables=indirect_variables,
                parse_error=root.has_error,
                caveat="Bare constants may be predefined or defined elsewhere; their runtime status is not established.")


def build_semantic_graph(code, grow_vocab=False):
    graph = build_joint_graph(code, grow_vocab)
    features = inspect_code(code)
    if len(features["source_kind"]) != graph["type"].numel():
        raise ValueError("Desalineación de nodos entre AST y características semánticas")
    graph.update(source_kind=features["source_kind"], call_kind=features["call_kind"], graph_version=GRAPH_VERSION)
    return graph
