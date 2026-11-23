"""过程内符号化分析：把一个方法体抽象成“外部词表”上的污点依赖闭包摘要。

外部词表（跨方法可连接的稳定符号，不依赖文件版本）：
  arg:i            第 i 个形参
  field:f          实例字段 f（field-based，跨接收者合并）
  static:C.f       静态字段
  coll:<...>       集合槽（局部集合 / 字段集合）
  src:KIND         直接污点源（REQUEST/UPLOAD/CONFIG/ZIP_ENTRY）
  unk:reason       来源不可判定（未知重载等）
  call:k           本方法内第 k 个调用点的返回值伪节点（引擎用被调方 ret 闭包替换）
每个标签带两个布尔标记：sanitized（已被规范化+前缀校验净化）、unknown（含不可判定边）。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field as dc_field

from tree_sitter import Node

from . import astutil as A
from . import catalog as C
from .index import GlobalIndex
from .parser import MethodDecl

COLLECTION_TYPES = {"List", "ArrayList", "LinkedList", "Map", "HashMap", "TreeMap",
                    "Set", "HashSet", "LinkedHashSet", "Collection", "Iterator", "Iterable"}
GETTER_RE = re.compile(r"^get[A-Z].*")
SETTER_RE = re.compile(r"^set[A-Z].*")


# --------------------------------------------------------------------- 依赖标签
@dataclass(frozen=True)
class DepTag:
    key: str
    sanitized: bool = False
    unknown: bool = False

    def canon(self) -> str:
        suf = ""
        if self.unknown:
            suf += "|u"
        if self.sanitized:
            suf += "|s"
        return self.key + suf

    def with_flags(self, sanitized: bool | None = None, unknown: bool | None = None) -> "DepTag":
        return DepTag(self.key,
                      self.sanitized if sanitized is None else sanitized,
                      self.unknown if unknown is None else unknown)


def parse_tag(s: str) -> DepTag:
    parts = s.split("|")
    return DepTag(parts[0], sanitized="s" in parts[1:], unknown="u" in parts[1:])


class DepSet:
    """标签集合；同名 key 合并时保留“最弱”标记（未净化优先、未知优先）。"""

    def __init__(self, tags: set[DepTag] | None = None):
        self.tags: dict[str, DepTag] = {}
        for t in tags or set():
            self.add(t)

    def add(self, t: DepTag) -> None:
        old = self.tags.get(t.key)
        if old is None:
            self.tags[t.key] = t
        else:
            self.tags[t.key] = DepTag(t.key,
                                      sanitized=old.sanitized and t.sanitized,
                                      unknown=old.unknown or t.unknown)

    def union(self, other: "DepSet") -> "DepSet":
        out = DepSet()
        for t in list(self.tags.values()) + list(other.tags.values()):
            out.add(t)
        return out

    def copy(self) -> "DepSet":
        return DepSet(set(self.tags.values()))

    def mark(self, sanitized: bool | None = None, unknown: bool | None = None) -> "DepSet":
        out = DepSet()
        for t in self.tags.values():
            out.add(t.with_flags(sanitized=sanitized, unknown=unknown))
        return out

    def keys(self) -> set[str]:
        return set(self.tags.keys())

    def to_list(self) -> list[str]:
        return sorted(t.canon() for t in self.tags.values())

    @classmethod
    def from_list(cls, items: list[str]) -> "DepSet":
        return cls({parse_tag(s) for s in items})

    def __bool__(self) -> bool:
        return bool(self.tags)


# --------------------------------------------------------------------- 方法摘要
@dataclass
class SinkRecord:
    kind: str
    line: int
    deps: list[str]            # 标签 canon 列表
    unknown: bool              # 该落点实参中是否含不可判定标签

@dataclass
class CallRecord:
    site: int
    line: int
    name: str
    recv_type_hint: str
    is_static: bool
    arg_count: int
    targets: list[str]
    resolution: str
    arg_deps: list[list[str]]  # 每个实参的 DepSet
    pseudo: str                # call:k

@dataclass
class MethodSummary:
    fqn: str
    content_hash: str
    params: list[tuple[str, str]]
    ret_deps: list[str]
    field_writes: dict[str, list[str]]
    coll_writes: dict[str, list[str]]
    sinks: list[SinkRecord]
    calls: list[CallRecord]
    unknown_calls: list[dict]
    direct_sources: list[dict]
    local_coll_types: dict[str, str]
    normalizer_uses: list[dict]
    prefix_guards: list[dict]
    reject_guards: list[dict] = dc_field(default_factory=list)

    def to_json(self) -> dict:
        return {
            "fqn": self.fqn, "content_hash": self.content_hash, "params": self.params,
            "ret_deps": sorted(self.ret_deps),
            "field_writes": {k: sorted(v) for k, v in sorted(self.field_writes.items())},
            "coll_writes": {k: sorted(v) for k, v in sorted(self.coll_writes.items())},
            "sinks": [vars(s) for s in sorted(self.sinks, key=lambda x: x.line)],
            "calls": [vars(c) for c in sorted(self.calls, key=lambda x: x.site)],
            "unknown_calls": sorted(self.unknown_calls, key=lambda x: (x["line"], x["name"])),
            "direct_sources": sorted(self.direct_sources, key=lambda x: (x["line"], x["kind"])),
            "local_coll_types": dict(sorted(self.local_coll_types.items())),
            "normalizer_uses": sorted(self.normalizer_uses, key=lambda x: x["line"]),
            "prefix_guards": sorted(self.prefix_guards, key=lambda x: x["line"]),
            "reject_guards": sorted(self.reject_guards, key=lambda x: x["line"]),
        }


# --------------------------------------------------------------------- 分析器
class IntraAnalyzer:
    def __init__(self, index: GlobalIndex):
        self.idx = index

    def _is_request_entry(self) -> bool:
        """入口约定：类名匹配 Controller/Filter/Servlet/.../Sample，方法非静态、
        非构造器、非 accessor，且无内部调用语义（名字不以 get/set 开头的私有辅助除外）。
        带映射注解的方法无条件视为入口。"""
        if any(a in C.ENTRY_METHOD_ANNOTATIONS for a in getattr(self.m, "annotations", ())):
            return True
        if not re.match(C.ENTRY_CLASS_REGEX, self.m.cls_short):
            return False
        if self.m.is_static or self.m.is_constructor or getattr(self.m, "is_private", False):
            return False
        if GETTER_RE.match(self.m.name) or SETTER_RE.match(self.m.name):
            return False
        return not self.m.name.startswith("_")

    def analyze(self, m: MethodDecl) -> MethodSummary:
        self.m = m
        self.source = self.idx.files[0].source  # 兜底，下面按文件取
        for f in self.idx.files:
            if f.rel_path == m.file_rel:
                self.source = f.source
                break
        self.env: dict[str, DepSet] = {}
        self.field_writes: dict[str, DepSet] = {}
        self.coll_writes: dict[str, DepSet] = {}
        self.ret = DepSet()
        self.sinks: list[SinkRecord] = []
        self.calls: list[CallRecord] = []
        self.unknown_calls: list[dict] = []
        self.direct_sources: list[dict] = []
        self.local_types: dict[str, str] = {}
        self.normalizer_uses: list[dict] = []
        self.prefix_guards: list[dict] = []
        self.reject_guards: list[dict] = []
        self.sanitized_roots: set[str] = set()
        self.site_counter = 0
        entry = self._is_request_entry()
        # 形参注入 arg 标签；入口方法的 String 形参额外视为 REQUEST 源；
        # @Value 等标注参数视为 CONFIG 源
        for i, (pname, ptype) in enumerate(m.params):
            tags = {DepTag(f"arg:{i}")}
            annos = m.param_annotations.get(pname, ())
            if any(a in C.SOURCE_ANNOTATIONS for a in annos):
                tags.add(DepTag("src:CONFIG"))
                self.direct_sources.append({"line": A.line_of(m.body) if m.body else 0,
                                            "kind": "CONFIG"})
            elif entry and ptype == "String":
                tags.add(DepTag("src:REQUEST"))
                self.direct_sources.append({"line": A.line_of(m.body) if m.body else 1,
                                            "kind": "REQUEST"})
            self.env[pname] = DepSet(tags)
            self.local_types[pname] = ptype
            if ptype in COLLECTION_TYPES:
                self.coll_writes.setdefault(f"coll:arg:{i}", DepSet())
        if m.body is not None:
            self._block(m.body, sanitized_vars=set())
        return MethodSummary(
            fqn=m.fqn, content_hash=self._method_hash(m), params=list(m.params),
            ret_deps=self.ret.to_list(),
            field_writes={k: v.to_list() for k, v in self.field_writes.items()},
            coll_writes={k: v.to_list() for k, v in self.coll_writes.items()},
            sinks=self.sinks, calls=self.calls, unknown_calls=self.unknown_calls,
            direct_sources=self.direct_sources, local_coll_types=self.local_types,
            normalizer_uses=self.normalizer_uses, prefix_guards=self.prefix_guards,
            reject_guards=self.reject_guards,
        )

    def _method_hash(self, m: MethodDecl) -> str:
        import hashlib
        body = A.text(m.body, self.source) if m.body is not None else ""
        return hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]

    # ------------------------------------------------------------- 语句块/分支
    def _block(self, block: Node, sanitized_vars: set[str]) -> None:
        for stmt in block.children:
            if stmt.type == "block":
                self._block(stmt, set(sanitized_vars))
            elif stmt.type == "if_statement":
                self._if(stmt, sanitized_vars)
            elif stmt.type in ("for_statement", "enhanced_for_statement", "while_statement", "do_statement"):
                self._loop(stmt, sanitized_vars)
            elif stmt.type in ("try_statement", "catch_clause", "finally_clause"):
                # try-with-resources 的资源声明不在 block 内，需显式评估，
                # 否则 try (new FileInputStream(t)) 这类落点会漏
                for res in A.find_all(stmt, "resource"):
                    init = res.child_by_field_name("value") or A.find_first(res, "object_creation_expression") \
                        or A.find_first(res, "method_invocation")
                    if init is not None:
                        self._eval(init)
                body = stmt.child_by_field_name("body") or A.first_child(stmt, "block")
                if body is not None:
                    self._block(body, set(sanitized_vars))
            elif stmt.type in ("{", "}", ";"):
                continue
            else:
                self._stmt(stmt, sanitized_vars)

    def _if(self, node: Node, sanitized_vars: set[str]) -> None:
        cond = node.child_by_field_name("condition")
        # 模式：if (校验失败) throw/return —— 守卫之后视为已净化
        reject = self._is_reject_guard(node, cond)
        saved_env = {k: v.copy() for k, v in self.env.items()}
        guard_vars = set(sanitized_vars)
        if cond is not None:
            guard_vars |= self._guard_vars(cond)
        if reject:
            # 校验失败即中断 → 当前块后续语句中的相关变量按已净化处理
            sanitized_vars |= guard_vars
            for v in guard_vars:
                self.sanitized_roots.add(v)
                if v in self.env:
                    self.env[v] = self.env[v].mark(sanitized=True)
        cons = node.child_by_field_name("consequence")
        if cons is not None:
            if cons.type == "block":
                self._block(cons, guard_vars)
            else:
                self._stmt(cons, guard_vars)
        then_env = {k: v.copy() for k, v in self.env.items()}
        alt = node.child_by_field_name("alternative")
        if alt is not None:
            self.env = {k: v.copy() for k, v in saved_env.items()}
            if alt.type == "block":
                self._block(alt, set(sanitized_vars))
            else:
                self._stmt(alt, sanitized_vars)
            # 分支合并：净化标记取交集（保守：一边没净化则合并不净化）
            merged = DepSet()
            keys_ = set(then_env) | set(self.env)
            new_env: dict[str, DepSet] = {}
            for k in keys_:
                a, b = then_env.get(k), self.env.get(k)
                if a and b:
                    new_env[k] = a.union(b)
                else:
                    new_env[k] = (a or b).copy()
            self.env = new_env
        elif not reject:
            # 无 else：回退后做并集（保守，净化标记自然按 DepSet 规则弱化）
            for k, v in self.env.items():
                if k in then_env:
                    then_env[k] = then_env[k].union(v)
            self.env = then_env

    def _is_reject_guard(self, if_node: Node, cond: Node | None) -> bool:
        if cond is None:
            return False
        if not self._expr_mentions_check(cond):
            return False
        # then 分支仅由 throw / return 构成
        cons = if_node.child_by_field_name("consequence")
        if cons is None:
            return False
        ok = False
        if cons.type == "block":
            stmts = [s for s in cons.children if s.is_named]
            ok = bool(stmts) and all(s.type in ("throw_statement", "return_statement") for s in stmts)
        else:
            ok = cons.type in ("throw_statement", "return_statement")
        if ok:
            for v in sorted(self._guard_vars(cond)):
                self.reject_guards.append({"line": A.line_of(if_node), "var": v})
        return ok

    def _expr_mentions_check(self, cond: Node) -> bool:
        for inv in A.find_all(cond, "method_invocation"):
            _, name, args = A.get_invocation_parts(inv, self.source)
            if C.is_prefix_check(name) or name in C.TRAVERSAL_CHECK_METHODS:
                if name in C.TRAVERSAL_CHECK_METHODS:
                    if any(".." in A.text(a, self.source) for a in args):
                        return True
                else:
                    return True
        return False

    def _guard_vars(self, cond: Node) -> set[str]:
        """守卫条件里参与前缀/穿越校验的变量名，同时登记前缀校验证据。"""
        out: set[str] = set()
        for inv in A.find_all(cond, "method_invocation"):
            _, name, args = A.get_invocation_parts(inv, self.source)
            if C.is_prefix_check(name) or (name in C.TRAVERSAL_CHECK_METHODS):
                if name in C.TRAVERSAL_CHECK_METHODS:
                    if not any(".." in A.text(a, self.source) for a in args):
                        continue
                self.prefix_guards.append({"line": A.line_of(inv), "check": name})
                obj = inv.child_by_field_name("object")
                if obj is not None:
                    root = self._root_var(obj)
                    if root:
                        out.add(root)
        return out

    def _root_var(self, node: Node) -> str:
        n = node
        while n.type in ("field_access", "method_invocation", "array_access"):
            nxt = n.child_by_field_name("object") or n.child_by_field_name("array")
            if nxt is None:
                break
            n = nxt
        if n.type == "identifier":
            return A.text(n, self.source)
        return ""

    def _loop(self, node: Node, sanitized_vars: set[str]) -> None:
        # 循环体执行两次以模拟一次迭代后的不动点（成本可控，足够覆盖集合-循环传播）
        body = node.child_by_field_name("body")
        if body is None:
            return
        # 增强 for：把集合槽的污点闭包绑定到元素变量
        if node.type == "enhanced_for_statement":
            elem = node.child_by_field_name("variable")
            coll_expr = node.child_by_field_name("value")
            if elem is not None and coll_expr is not None:
                ename_node = A.find_first(elem, "identifier")
                ename = A.text(ename_node, self.source) if ename_node is not None else ""
                if ename:
                    # 集合槽依赖与集合表达式自身依赖取并集：
                    # 覆盖 List/Map（集合槽）与 String[] 等未建模数组（env 依赖）两种情况
                    merged = self._eval(coll_expr)
                    ctag = self._coll_tag_of_expr(coll_expr)
                    if ctag and ctag in self.coll_writes:
                        merged = merged.union(self.coll_writes[ctag])
                    self.env[ename] = merged
        if body.type != "block":
            self._stmt(body, sanitized_vars)
            return
        before = {k: v.copy() for k, v in self.env.items()}
        self._block(body, set(sanitized_vars))
        # 合并回迭代前状态后再走一遍
        for k, v in list(before.items()):
            if k in self.env:
                self.env[k] = self.env[k].union(v)
        self._block(body, set(sanitized_vars))

    # ------------------------------------------------------------------ 语句
    def _stmt(self, node: Node, sanitized_vars: set[str]) -> None:
        if node.type == "local_variable_declaration":
            type_node = node.child_by_field_name("type")
            tname = A.text(type_node, self.source).split("<", 1)[0].replace("[]", "") if type_node else ""
            for dec in A.find_all(node, "variable_declarator"):
                vname = A.node_name(A.first_child(dec, "identifier"), self.source)
                self.local_types[vname] = tname
                rhs = dec.child_by_field_name("value")
                if rhs is not None:
                    self.env[vname] = self._eval(rhs)
                    if tname in COLLECTION_TYPES:
                        self._coll_add(f"coll:local:{vname}", self.env[vname], init=True)
                else:
                    self.env[vname] = DepSet()
        elif node.type == "assignment_expression" or node.type == "expression_statement":
            if node.type == "assignment_expression":
                lhs = node.child_by_field_name("left")
                rhs = node.child_by_field_name("right")
                if lhs is not None and rhs is not None:
                    self._assign(lhs, self._eval(rhs))
            else:
                # 表达式语句：直接评估其命名子表达式（方法调用/对象创建/赋值表达式）
                for sub in node.children:
                    if sub.is_named:
                        self._eval(sub)
        elif node.type == "return_statement":
            expr = next((c for c in node.children if c.is_named), None)
            if expr is not None:
                self.ret = self.ret.union(self._eval(expr))
        elif node.type == "enhanced_for_statement":
            self._loop(node, sanitized_vars)
        elif node.type in ("throw_statement",):
            return
        else:
            # 其他语句里的调用仍需评估（sink/源副作用）
            for inv in A.find_all(node, "method_invocation"):
                self._eval_invocation(inv)
            for obj in A.find_all(node, "object_creation_expression"):
                self._eval_creation(obj)

    def _assign(self, lhs: Node, deps: DepSet) -> None:
        if lhs.type == "identifier":
            name = A.text(lhs, self.source)
            if self.local_types.get(name) in COLLECTION_TYPES:
                self._coll_add(f"coll:local:{name}", deps, init=True)
            self.env[name] = deps
        elif lhs.type == "field_access":
            _, fname = A.get_field_parts(lhs, self.source)
            tag = self._field_tag(lhs, fname)
            self.field_writes[tag] = self.field_writes.get(tag, DepSet()).union(deps)
        elif lhs.type == "array_access":
            arr = lhs.child_by_field_name("array")
            ctag = self._coll_tag_of_expr(arr)
            if ctag:
                self._coll_add(ctag, deps)

    def _field_tag(self, fa: Node, fname: str) -> str:
        obj = fa.child_by_field_name("object")
        if obj is not None and obj.type == "identifier":
            t = self.local_types.get(A.text(obj, self.source), "")
            if t and t[0].isupper() and t not in COLLECTION_TYPES:
                return f"static:{t}.{fname}"
        return f"field:{fname}"

    def _coll_tag_of_expr(self, node: Node | None) -> str | None:
        if node is None:
            return None
        if node.type == "identifier":
            name = A.text(node, self.source)
            if self.local_types.get(name) in COLLECTION_TYPES:
                return f"coll:local:{name}"
            return f"coll:var:{name}"
        if node.type == "field_access":
            _, fname = A.get_field_parts(node, self.source)
            return f"coll:field:{fname}"
        if node.type == "array_access":
            return self._coll_tag_of_expr(node.child_by_field_name("array"))
        return None

    def _coll_add(self, tag: str, deps: DepSet, init: bool = False) -> None:
        cur = self.coll_writes.get(tag)
        if cur is None or init:
            self.coll_writes[tag] = deps.copy() if init else (cur.union(deps) if cur else deps.copy())
        else:
            self.coll_writes[tag] = cur.union(deps)

    # ------------------------------------------------------------------ 表达式
    def _eval(self, node: Node) -> DepSet:
        t = node.type
        if t in ("string_literal", "character_literal", "integer_literal", "decimal_literal",
                 "true", "false", "null_literal"):
            return DepSet()
        if t == "identifier":
            name = A.text(node, self.source)
            if self.local_types.get(name) in COLLECTION_TYPES:
                return self.coll_writes.get(f"coll:local:{name}", DepSet()).copy()
            return self.env.get(name, DepSet()).copy()
        if t == "parenthesized_expression":
            inner = next((c for c in node.children if c.is_named), None)
            return self._eval(inner) if inner is not None else DepSet()
        if t in ("binary_expression", "ternary_expression"):
            out = DepSet()
            for c in node.children:
                if c.is_named and c.type not in ("binary_operator", "?:", ":"):
                    out = out.union(self._eval(c))
            return out
        if t == "field_access":
            _, fname = A.get_field_parts(node, self.source)
            tag = self._field_tag(node, fname)
            # 字段读取：field 标签本身即来源；若本方法内有写则并入
            out = DepSet({DepTag(tag)})
            if tag in self.field_writes:
                out = out.union(self.field_writes[tag])
            if tag.startswith("field:") and f"coll:field:{fname}" in self.coll_writes:
                out = out.union(self.coll_writes[f"coll:field:{fname}"])
            return out
        if t == "array_access":
            ctag = self._coll_tag_of_expr(node.child_by_field_name("array"))
            if ctag:
                return self.coll_writes.get(ctag, DepSet({DepTag(ctag)})).copy()
            return DepSet()
        if t == "method_invocation":
            return self._eval_invocation(node)
        if t == "object_creation_expression":
            return self._eval_creation(node)
        if t == "assignment_expression":
            rhs = node.child_by_field_name("right")
            lhs = node.child_by_field_name("left")
            deps = self._eval(rhs) if rhs is not None else DepSet()
            if lhs is not None:
                self._assign(lhs, deps)
            return deps
        if t == "cast_expression":
            inner = next((c for c in node.children if c.is_named and "type" not in c.type), None)
            if inner is None:
                inner = next((c for c in node.children if c.is_named), None)
            return self._eval(inner) if inner is not None else DepSet()
        if t in ("lambda_expression", "anonymous_class_creation"):
            return DepSet()
        # 兜底：合并所有命名子表达式
        out = DepSet()
        for c in node.children:
            if c.is_named and "expression" in c.type:
                out = out.union(self._eval(c))
        return out

    def _recv_type_hint(self, inv: Node) -> tuple[str, str, bool]:
        obj = inv.child_by_field_name("object")
        if obj is None:
            return "", "", True
        chain = A.qualified_chain(obj, self.source)
        root = self._root_var(obj)
        hint = self.local_types.get(root, "")
        return chain, hint, False

    def _eval_invocation(self, inv: Node) -> DepSet:
        recv_chain, name, args = A.get_invocation_parts(inv, self.source)
        _, hint, is_static = self._recv_type_hint(inv)
        if not recv_chain:
            is_static = True
        arg_deps = [self._eval(a) for a in args]

        # 1) 污点源
        spec = C.match_source(name, recv_chain or hint)
        if spec is not None:
            line = A.line_of(inv)
            self.direct_sources.append({"line": line, "kind": spec.kind})
            tag = DepTag(f"src:{spec.kind}")
            # 接收者根变量已被 reject 守卫/前置净化覆盖时，派生源继承净化标记
            obj = inv.child_by_field_name("object")
            root = self._root_var(obj) if obj is not None else ""
            if root and root in self.sanitized_roots:
                tag = tag.with_flags(sanitized=True)
            return DepSet({tag})

        # 2) 规范化方法：已知签名 → 净化；无法确定 → 未知重载
        if C.is_normalizer_name(name):
            base = arg_deps[0] if arg_deps else (self._eval(inv.child_by_field_name("object"))
                                                 if inv.child_by_field_name("object") is not None else DepSet())
            if C.is_known_normalizer(name, recv_chain or hint):
                self.normalizer_uses.append({"line": A.line_of(inv), "name": name, "resolved": True})
                return base.mark(sanitized=True)
            self.unknown_calls.append({"line": A.line_of(inv), "name": name,
                                       "reason": "NORMALIZER_OVERLOAD_UNRESOLVED"})
            self.normalizer_uses.append({"line": A.line_of(inv), "name": name, "resolved": False})
            self._record_call(inv, name, hint, is_static, arg_deps)
            return base.mark(unknown=True)

        # 3) 路径构造：依赖透传
        if name in C.PATH_BUILDERS and any(t in (recv_chain or hint) for t in C.PATH_BUILDER_RECEIVERS):
            out = DepSet()
            if inv.child_by_field_name("object") is not None:
                out = out.union(self._eval(inv.child_by_field_name("object")))
            for d in arg_deps:
                out = out.union(d)
            return out

        # 4) 集合 API：add/put/get/iterator
        if name in ("add", "put", "putAll", "addAll"):
            ctag = self._coll_tag_of_expr(inv.child_by_field_name("object"))
            if ctag:
                payload = DepSet()
                for d in arg_deps:
                    payload = payload.union(d)
                self._coll_add(ctag, payload)
            return DepSet()
        if name in ("get", "iterator", "listIterator", "stream", "toArray", "elements"):
            ctag = self._coll_tag_of_expr(inv.child_by_field_name("object"))
            if ctag and self.local_types.get(self._root_var(inv.child_by_field_name("object")), "") in COLLECTION_TYPES:
                return self.coll_writes.get(ctag, DepSet({DepTag(ctag)})).copy()

        # 5) getter/setter 桥接（无源码的框架类）
        if GETTER_RE.match(name) and not self._has_target(name, len(args)):
            fname = name[3].lower() + name[4:]
            return DepSet({DepTag(f"field:{fname}")})
        if SETTER_RE.match(name) and not self._has_target(name, len(args)):
            fname = name[3].lower() + name[4:]
            tag = f"field:{fname}"
            payload = DepSet()
            for d in arg_deps:
                payload = payload.union(d)
            self.field_writes[tag] = self.field_writes.get(tag, DepSet()).union(payload)
            return DepSet()

        # 6) 落点
        sink_specs = C.match_sink(name, recv_chain or hint, self.m.name)
        if sink_specs:
            deps = DepSet()
            for sp in sink_specs:
                idx_arg = sp.arg_index
                d = arg_deps[idx_arg] if idx_arg < len(arg_deps) else DepSet()
                deps = deps.union(d)
                self.sinks.append(SinkRecord(
                    kind=sp.kind, line=A.line_of(inv), deps=d.to_list(),
                    unknown=any(parse_tag(x).unknown for x in d.to_list())))

        # 7) 普通调用：生成 call:k 伪标签并登记调用点（供过程间引擎连接）
        return self._record_call(inv, name, hint, is_static, arg_deps)

    def _has_target(self, name: str, argc: int) -> bool:
        return any(len(self.idx.methods[f].params) == argc for f in self.idx.methods_by_short_name.get(name, []))

    def _record_call(self, inv: Node, name: str, hint: str, is_static: bool,
                     arg_deps: list[DepSet]) -> DepSet:
        self.site_counter += 1
        pseudo = f"call:{self.site_counter}"
        argc = len(A.get_invocation_parts(inv, self.source)[2])
        # 注意：此处只记录“名字+接收者类型提示+参数个数”，不做跨文件解析。
        # 目标 FQN 由 index.link_calls 在装载阶段针对当前索引统一链接，
        # 因此缓存摘要不依赖其他文件的版本状态，杜绝跨版本漂移。
        self.calls.append(CallRecord(
            site=self.site_counter, line=A.line_of(inv), name=name, recv_type_hint=hint,
            is_static=is_static, arg_count=argc, targets=[], resolution="PENDING",
            arg_deps=[d.to_list() for d in arg_deps], pseudo=pseudo))
        return DepSet({DepTag(pseudo)})

    def _eval_creation(self, node: Node) -> DepSet:
        tnode = node.child_by_field_name("type")
        tname = A.text(tnode, self.source).split("<", 1)[0] if tnode is not None else ""
        args_node = node.child_by_field_name("arguments")
        arg_deps = [self._eval(a) for a in (args_node.children if args_node is not None else [])
                    if a.is_named]
        # 构造器落点（FileInputStream / File / FileSystemResource 等）
        for sp in C.match_sink("<init>", tname, self.m.name):
            d = arg_deps[sp.arg_index] if sp.arg_index < len(arg_deps) else DepSet()
            self.sinks.append(SinkRecord(
                kind=sp.kind, line=A.line_of(node), deps=d.to_list(),
                unknown=any(parse_tag(x).unknown for x in d.to_list())))
        out = DepSet()
        for d in arg_deps:
            out = out.union(d)
        if tname in COLLECTION_TYPES:
            return DepSet()  # 新空集合无污点
        return out
