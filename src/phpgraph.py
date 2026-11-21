"""PHP source -> AST graph (tree-sitter) with node features and line mapping.

Solo análisis estático: el código PHP nunca se ejecuta.
"""
import hashlib
import re
import torch
import tree_sitter_php as tsphp
from tree_sitter import Language, Parser

PHP = Language(tsphp.language_php())
_parser = Parser(PHP)

MAX_NODES = 2500

# Funciones/constructos típicamente asociados a ejecución, ofuscación o acceso a archivos.
SENSITIVE = [
    "eval", "assert", "system", "exec", "shell_exec", "passthru", "popen", "proc_open",
    "pcntl_exec", "base64_decode", "gzinflate", "gzuncompress", "str_rot13", "create_function",
    "preg_replace", "call_user_func", "call_user_func_array", "array_map", "usort", "include",
    "include_once", "require", "require_once", "file_put_contents", "fwrite", "move_uploaded_file",
    "chr", "hex2bin", "pack", "urldecode", "strrev", "fsockopen", "curl_exec", "unlink",
    "ini_set", "set_time_limit", "phpinfo", "mail", "readfile", "file_get_contents",
]
SENS_IDX = {n: i + 1 for i, n in enumerate(SENSITIVE)}  # 0 = ninguno
N_SENS = len(SENSITIVE) + 1
SUPERGLOBALS = {"$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER", "$GLOBALS"}

_type_vocab = {"<unk>": 0}


def type_id(t: str, grow: bool) -> int:
    if t not in _type_vocab:
        if not grow:
            return 0
        _type_vocab[t] = len(_type_vocab)
    return _type_vocab[t]


def vocab_state():
    return dict(_type_vocab)


def load_vocab(v):
    _type_vocab.clear()
    _type_vocab.update(v)


def _token_flags(node, src: bytes):
    """(sensitive_idx, is_superglobal, is_varvar_or_dynamic_call, is_long_string)."""
    t = node.type
    text = src[node.start_byte:node.end_byte]
    sens = 0
    superg = 0
    dyn = 0
    longstr = 0
    if t in ("name", "qualified_name"):
        sens = SENS_IDX.get(text.decode("utf8", "ignore").lower().lstrip("\\"), 0)
    elif t in ("include_expression", "include_once_expression", "require_expression",
               "require_once_expression"):
        sens = SENS_IDX.get(t.split("_expression")[0], 0)
    elif t == "variable_name":
        if text.decode("utf8", "ignore") in SUPERGLOBALS:
            superg = 1
    elif t in ("dynamic_variable_name",):
        dyn = 1
    elif t in ("string", "encapsed_string", "heredoc", "nowdoc", "string_content", "string_value"):
        if len(text) > 120 and re.fullmatch(rb"[A-Za-z0-9+/=\s\"']{120,}", text[:400] or b"x"):
            longstr = 1
    return sens, superg, dyn, longstr


def build_graph(code: bytes, grow_vocab: bool = False):
    """Devuelve dict con tensores: type_ids, sens, flags, edge_index, lines (línea inicial por nodo)."""
    tree = _parser.parse(code)
    root = tree.root_node
    types, sens, flags, lines, ends = [], [], [], [], []
    src_idx, dst_idx = [], []

    stack = [(root, -1)]
    while stack and len(types) < MAX_NODES:
        node, parent = stack.pop()
        i = len(types)
        s, sg, dy, ls = _token_flags(node, code)
        types.append(type_id(node.type, grow_vocab))
        sens.append(s)
        flags.append([sg, dy, ls, 1.0 if node.type == "ERROR" else 0.0,
                      min(node.child_count, 20) / 20.0])
        lines.append(node.start_point[0] + 1)
        ends.append(node.end_point[0] + 1)
        if parent >= 0:
            src_idx += [parent, i]
            dst_idx += [i, parent]
        kids = list(node.children)
        for k in reversed(kids):
            stack.append((k, i))
    n = len(types)
    if n == 0:
        types, sens, flags, lines, ends = [0], [0], [[0, 0, 0, 0, 0]], [1], [1]
        n = 1
    ei = torch.tensor([src_idx, dst_idx], dtype=torch.long) if src_idx else torch.zeros((2, 0), dtype=torch.long)
    keep = (ei < n).all(dim=0) if ei.numel() else torch.zeros(0, dtype=torch.bool)
    ei = ei[:, keep] if ei.numel() else ei
    return dict(
        type=torch.tensor(types, dtype=torch.long),
        sens=torch.tensor(sens, dtype=torch.long),
        flags=torch.tensor(flags, dtype=torch.float),
        edge_index=ei,
        lines=torch.tensor(lines, dtype=torch.long),
        ends=torch.tensor(ends, dtype=torch.long),
        truncated=bool(stack),
    )


def file_md5(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()
