"""tree-sitter 语法树通用工具：节点文本、子节点查找、符号名抽取等。

只依赖 tree-sitter 的具体语法树，不使用任何现成数据流/污点规则。
"""
from __future__ import annotations

from tree_sitter import Node


def text(node: Node | None, source: bytes) -> str:
    """节点对应的源码文本（UTF-8 解码）。"""
    if node is None:
        return ""
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def children(node: Node, ntype: str | None = None) -> list[Node]:
    """直接子节点；可按节点类型过滤。"""
    out = []
    for c in node.children:
        if ntype is None or c.type == ntype:
            out.append(c)
    return out


def first_child(node: Node, ntype: str) -> Node | None:
    for c in node.children:
        if c.type == ntype:
            return c
    return None


def walk(node: Node):
    """前序遍历整棵子树。"""
    yield node
    for c in node.children:
        yield from walk(c)


def find_first(node: Node, ntype: str) -> Node | None:
    """子树中第一个指定类型的节点。"""
    for n in walk(node):
        if n.type == ntype:
            return n
    return None


def find_all(node: Node, ntype: str) -> list[Node]:
    return [n for n in walk(node) if n.type == ntype]


def node_name(node: Node, source: bytes) -> str:
    """抽取标识符/类型名/方法名的规范短名。"""
    if node is None:
        return ""
    if node.type in {"identifier", "type_identifier"}:
        return text(node, source)
    # method_declaration: name 子节点
    n = first_child(node, "identifier") or first_child(node, "type_identifier")
    if n is not None:
        return text(n, source)
    return text(node, source)


def qualified_chain(node: Node, source: bytes) -> str:
    """field_access / method_invocation 的点号链，如 req.getParameter。

    注意 object/name/field/scope 是 tree-sitter 字段名，必须用 child_by_field_name。
    """
    if node is None:
        return ""
    if node.type == "identifier":
        return text(node, source)
    if node.type in {"field_access", "method_invocation", "scoped_identifier"}:
        if node.type == "scoped_identifier":
            obj = node.child_by_field_name("scope")
        else:
            obj = node.child_by_field_name("object")
        name = node.child_by_field_name("name") if node.type != "field_access" else node.child_by_field_name("field")
        if obj is not None and name is not None:
            return qualified_chain(obj, source) + "." + text(name, source)
        if name is not None:
            return text(name, source)
    # 兜底：去掉空白
    return " ".join(text(node, source).split())


def get_invocation_parts(inv: Node, source: bytes) -> tuple[str, str, list[Node]]:
    """method_invocation -> (接收者链文本, 方法名, 实参节点列表)。"""
    obj = inv.child_by_field_name("object")
    name_node = inv.child_by_field_name("name")
    args_node = inv.child_by_field_name("arguments")
    args = [c for c in (args_node.children if args_node is not None else []) if c.is_named]
    recv = qualified_chain(obj, source) if obj is not None else ""
    return recv, text(name_node, source), args


def get_field_parts(fa: Node, source: bytes) -> tuple[str, str]:
    """field_access -> (接收者链, 字段名)。"""
    obj = fa.child_by_field_name("object")
    name_node = fa.child_by_field_name("field")
    return qualified_chain(obj, source) if obj is not None else "", text(name_node, source)


def line_of(node: Node) -> int:
    return node.start_point[0] + 1


def object_of(node: Node | None) -> Node | None:
    """method_invocation/field_access/array_access 的 object 字段（tree-sitter 字段名）。"""
    return node.child_by_field_name("object") if node is not None else None


def is_leaf_string_literal(node: Node) -> bool:
    return node.type == "string_literal"
