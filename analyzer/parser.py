"""单文件解析：基于 tree-sitter 具体语法树抽取包、导入、类、字段、方法声明。"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from tree_sitter import Language, Node, Parser

from . import astutil as A
from . import tree_sitter_java_shim


_PARSER = None


def get_parser() -> Parser:
    global _PARSER
    if _PARSER is None:
        _PARSER = Parser(Language(tree_sitter_java_shim.java_language()))
    return _PARSER


@dataclass
class MethodDecl:
    fqn: str                    # pkg.Cls#name(arg 短类型,...)
    cls_fqn: str
    cls_short: str
    name: str
    params: list[tuple[str, str]]      # (参数名, 类型短名)
    param_annotations: dict[str, tuple[str, ...]]   # 参数名 -> 注解短名元组
    annotations: tuple[str, ...]       # 方法级注解短名
    is_private: bool
    return_type: str
    is_static: bool
    is_constructor: bool
    body: Node | None
    file_rel: str
    repo: str
    lang_version: str = "java"


@dataclass
class ClassDecl:
    fqn: str
    short: str
    pkg: str
    extends: str = ""
    implements: tuple[str, ...] = ()
    annotations: tuple[str, ...] = ()
    fields: dict[str, str] = field(default_factory=dict)     # 字段名 -> 类型短名
    methods: list[str] = field(default_factory=list)         # 方法 FQN 列表


@dataclass
class FileUnit:
    repo: str
    rel_path: str
    source: bytes
    package: str
    imports: tuple[str, ...]
    classes: dict[str, ClassDecl]
    methods: dict[str, MethodDecl]
    content_hash: str


def _type_short(type_node: Node | None, source: bytes) -> str:
    if type_node is None:
        return ""
    raw = A.text(type_node, source)
    # 去掉泛型与数组符号，取最后一段短名
    base = raw.split("<", 1)[0].replace("[]", "").strip()
    return base.rsplit(".", 1)[-1]


def _anno_short(anno: Node, source: bytes) -> str:
    """注解短名：支持 @Value 与 @org.springframework...Value 两种写法。"""
    name_node = anno.child_by_field_name("name")
    raw = A.text(name_node, source) if name_node is not None else A.text(anno, source)
    return raw.lstrip("@").rsplit(".", 1)[-1]


def parse_file(repo: str, rel_path: str, source: bytes) -> FileUnit:
    tree = get_parser().parse(source)
    root = tree.root_node
    pkg_node = A.first_child(root, "package_declaration")
    pkg = ""
    if pkg_node is not None:
        si = A.first_child(pkg_node, "scoped_identifier")
        pkg = A.text(si, source) if si is not None else A.text(pkg_node, source).replace("package", "").replace(";", "").strip()

    imports: list[str] = []
    for imp in A.children(root, "import_declaration"):
        imports.append(A.text(imp, source).replace("import", "").replace("static", "").replace(";", "").strip())

    classes: dict[str, ClassDecl] = {}
    methods: dict[str, MethodDecl] = {}

    for cd in [n for n in root.children if n.type in ("class_declaration", "interface_declaration", "enum_declaration")]:
        short = A.node_name(cd, source)
        fqn = f"{pkg}.{short}" if pkg else short
        ext = ""
        impl: tuple[str, ...] = ()
        for c in cd.children:
            if c.type == "superclass":
                t = A.find_first(c, "type_identifier") or A.find_first(c, "generic_type")
                ext = _type_short(t, source)
            elif c.type == "interface_list":
                impl = tuple(_type_short(t, source) for t in A.find_all(c, "type_identifier"))
        cls_annos = tuple(_anno_short(a, source) for a in A.children(cd, "annotation"))
        cls = ClassDecl(fqn=fqn, short=short, pkg=pkg, extends=ext, implements=impl,
                        annotations=cls_annos)

        body_node = cd.child_by_field_name("body") or cd
        for fd in A.find_all(body_node, "field_declaration"):
            tname = _type_short(fd.child_by_field_name("type"), source)
            for dec in A.find_all(fd, "variable_declarator"):
                nm = A.node_name(dec.child_by_field_name("name"), source)
                if nm:
                    cls.fields[nm] = tname

        for md in A.find_all(body_node, "method_declaration") + A.find_all(body_node, "constructor_declaration"):
            is_ctor = md.type == "constructor_declaration"
            name = cls.short if is_ctor else A.node_name(md.child_by_field_name("name"), source)
            params: list[tuple[str, str]] = []
            param_annotations: dict[str, tuple[str, ...]] = {}
            plist = md.child_by_field_name("parameters")
            if plist is not None:
                for fp in A.children(plist, "formal_parameter"):
                    pname = A.node_name(fp.child_by_field_name("name"), source)
                    ptype = _type_short(fp.child_by_field_name("type"), source)
                    params.append((pname, ptype))
                    annos = tuple(_anno_short(a, source) for a in A.find_all(fp, "annotation"))
                    if annos:
                        param_annotations[pname] = annos
            method_annos = tuple(_anno_short(a, source) for a in A.find_all(md, "annotation"))
            is_static = any("static" in A.text(m, source) for m in A.children(md, "modifiers"))
            is_private = any("private" in A.text(m, source) for m in A.children(md, "modifiers"))
            rtype = "" if is_ctor else _type_short(md.child_by_field_name("type"), source)
            sig = ",".join(p for _, p in params)
            fqn_m = f"{fqn}#{'<init>' if is_ctor else name}({sig})"
            mdecl = MethodDecl(
                fqn=fqn_m, cls_fqn=fqn, cls_short=short, name=("<init>" if is_ctor else name),
                params=params, param_annotations=param_annotations, annotations=method_annos,
                is_private=is_private, return_type=rtype,
                is_static=is_static, is_constructor=is_ctor,
                body=md.child_by_field_name("body"), file_rel=rel_path, repo=repo,
            )
            methods[fqn_m] = mdecl
            cls.methods.append(fqn_m)
        classes[fqn] = cls

    content_hash = hashlib.sha256(source).hexdigest()
    return FileUnit(repo=repo, rel_path=rel_path, source=source, package=pkg,
                    imports=tuple(imports), classes=classes, methods=methods, content_hash=content_hash)
