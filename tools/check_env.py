import sys

try:
    import tree_sitter
    import tree_sitter_java
    from tree_sitter import Language, Parser
    lang = Language(tree_sitter_java.language())
    parser = Parser(lang)
    tree = parser.parse(b"class A { int x; }")
    print("tree-sitter", tree_sitter.__version__, "java ok, root:", tree.root_node.type)
except Exception as e:
    print("ENV ERROR:", type(e).__name__, e)
    sys.exit(1)
