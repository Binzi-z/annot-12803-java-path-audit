"""tree-sitter-java 版本适配层（固定依赖 tree-sitter-java==0.23.5）。"""
from __future__ import annotations


def java_language():
    import tree_sitter_java
    return tree_sitter_java.language()
