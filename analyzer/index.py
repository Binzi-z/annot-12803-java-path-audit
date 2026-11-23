"""跨仓库全局索引：符号表、调用解析（含继承/接口的多态目标）、调用图边数上界。

三个仓库（控制层 / 公共工具库 / 过滤器插件）被视为一个逻辑工程，import 与同名类
在同一命名空间中连接，从而跨仓库的方法调用可以解析到目标方法 FQN。
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .parser import FileUnit, MethodDecl


@dataclass
class CallSite:
    method_fqn: str              # 含调用点的方法
    repo: str
    file: str
    line: int
    recv_expr: str
    method_name: str
    arg_count: int
    target_fqns: tuple[str, ...]      # 解析到的目标（可能多个，多态）
    resolution: str                   # UNIQUE / POLY / EXTERNAL / UNRESOLVED / UNKNOWN_OVERLOAD


class GlobalIndex:
    def __init__(self, files: list[FileUnit], edge_per_site_bound: int = 16):
        self.files = sorted(files, key=lambda f: (f.repo, f.rel_path))
        self.methods: dict[str, MethodDecl] = {}
        self.classes: dict[str, object] = {}
        self.by_short_class: dict[str, list[str]] = {}
        self.short_to_fqn_import: dict[tuple[str, str], str] = {}
        self.methods_by_short_name: dict[str, list[str]] = {}
        self.call_sites: list[CallSite] = []
        self.edge_per_site_bound = edge_per_site_bound
        self._build()

    # ------------------------------------------------------------------ 建索引
    def _build(self) -> None:
        for f in self.files:
            for fqn, cls in f.classes.items():
                self.classes[fqn] = cls
                self.by_short_class.setdefault(cls.short, []).append(fqn)
                for imp in f.imports:
                    if not imp.endswith(".*"):
                        self.short_to_fqn_import[(f.rel_path, imp.rsplit(".", 1)[-1])] = imp
            for fqn, m in f.methods.items():
                self.methods[fqn] = m
                self.methods_by_short_name.setdefault(m.name, []).append(fqn)

    # -------------------------------------------------------------- 类型名解析
    def resolve_type(self, short: str, context_file: str) -> str:
        """短类型名 -> 类 FQN（先查 import，再查同名类）。"""
        if not short:
            return ""
        hit = self.short_to_fqn_import.get((context_file, short))
        if hit and hit in self.classes:
            return hit
        cands = self.by_short_class.get(short, [])
        if len(cands) == 1:
            return cands[0]
        # 多个同名类：无法唯一确定，返回第一个确定性候选（排序保证稳定），调用解析按名字族处理
        return sorted(cands)[0] if cands else ""

    def _hierarchy_names(self, cls_fqn: str) -> set[str]:
        """类自身 + 父类 + 实现接口（含传递）的短名集合，用于多态目标收集。"""
        out: set[str] = set()
        stack = [cls_fqn]
        seen: set[str] = set()
        while stack:
            cur = stack.pop()
            if not cur or cur in seen:
                continue
            seen.add(cur)
            cls = self.classes.get(cur)
            if cls is None:
                # 外部短名（JDK/三方库，无源码）
                out.add(cur.rsplit(".", 1)[-1])
                continue
            out.add(cls.short)
            if cls.extends:
                par = self.resolve_type(cls.extends, "")
                if par:
                    stack.append(par)
            for it in cls.impl:
                ifc = self.resolve_type(it, "")
                if ifc:
                    stack.append(ifc)
        return out

    # ---------------------------------------------------------- 调用图与上界
    def build_call_graph(self) -> dict:
        """汇总边数、上界、超界裁剪统计。上界 = 调用点数 × 每点目标上界。"""
        sites = sorted(self.call_sites, key=lambda s: (s.file, s.line, s.method_name))
        edge_count = 0
        truncated_sites = 0
        truncated_edges = 0
        for s in sites:
            n = len(s.target_fqns)
            if n > self.edge_per_site_bound:
                truncated_sites += 1
                truncated_edges += n - self.edge_per_site_bound
                edge_count += self.edge_per_site_bound
            else:
                edge_count += n
        bound = len(sites) * self.edge_per_site_bound
        return {
            "call_sites": len(sites),
            "edge_count": edge_count,
            "edge_upper_bound": bound,
            "bound_policy": (
                "每个调用点多态目标超过 %d 个时，按目标方法 FQN 字典序截取前 %d 个，"
                "被裁掉的目标在摘要中记为 UNKNOWN_OVERLOAD 并计入未知路径占比" % (
                    self.edge_per_site_bound, self.edge_per_site_bound)),
            "truncated_sites": truncated_sites,
            "truncated_edges": truncated_edges,
            "over_bound": edge_count > bound,
        }

    # ---------------------------------------------------------- 装载期链接
    def link_calls(self, summaries: dict) -> None:
        """对方法摘要中的每个调用点做当前索引下的目标解析（缓存复用后同样重跑）。

        摘要只存名字/接收者提示/参数个数，解析结果永远不进缓存键值——这是
        “缓存命中与否不改变结论、且不产生跨版本漂移”的关键环节。
        """
        from . import catalog as C
        for fqn in sorted(summaries):
            m = self.methods.get(fqn)
            if m is None:
                continue
            s = summaries[fqn]
            existing = {(x.method_fqn, x.line, x.method_name) for x in self.call_sites}
            for call in sorted(s.calls, key=lambda c: c.site):
                candidates = self._candidates(fqn, call.recv_type_hint, call.name,
                                              call.arg_count, call.is_static)
                candidates = sorted(set(candidates))
                truncated = False
                if len(candidates) > self.edge_per_site_bound:
                    truncated = True
                    candidates = candidates[:self.edge_per_site_bound]
                if len(candidates) == 1:
                    resolution = "UNIQUE"
                elif len(candidates) > 1:
                    resolution = "POLY"
                else:
                    resolution = "EXTERNAL"
                call.targets = candidates
                call.resolution = ("TRUNCATED" if truncated else resolution)
                key = (fqn, call.line, call.name)
                if key not in existing:
                    self.call_sites.append(CallSite(
                        method_fqn=fqn, repo=m.repo, file=m.file_rel, line=call.line,
                        recv_expr=call.recv_type_hint, method_name=call.name,
                        arg_count=call.arg_count, target_fqns=tuple(candidates),
                        resolution=call.resolution))
                    existing.add(key)
                # 规范化调用的未知重载标注
                if C.is_normalizer_name(call.name) and resolution in ("EXTERNAL", "POLY"):
                    reason = ("NORMALIZER_OVERLOAD_POLY" if resolution == "POLY"
                              else "NORMALIZER_OVERLOAD_EXTERNAL")
                    if not any(u["line"] == call.line and u["name"] == call.name
                               for u in s.unknown_calls):
                        s.unknown_calls.append({"line": call.line, "name": call.name, "reason": reason})

    def _candidates(self, method_fqn: str, recv_type_hint: str, name: str,
                    arg_count: int, is_static: bool) -> list[str]:
        ctx_file = self.methods[method_fqn].file_rel
        candidates: list[str] = []
        if recv_type_hint:
            cls_fqn = self.resolve_type(recv_type_hint, ctx_file)
            if cls_fqn:
                family = self._hierarchy_names(cls_fqn)
                for fqn in self.methods_by_short_name.get(name, []):
                    mm = self.methods[fqn]
                    if mm.cls_short in family and len(mm.params) == arg_count:
                        candidates.append(fqn)
        if not candidates:
            owner = self.methods.get(method_fqn)
            if owner is not None:
                for fqn in self.methods_by_short_name.get(name, []):
                    mm = self.methods[fqn]
                    if (is_static or mm.cls_fqn == owner.cls_fqn) and len(mm.params) == arg_count:
                        candidates.append(fqn)
        if not candidates:
            candidates = [f for f in self.methods_by_short_name.get(name, [])
                          if len(self.methods[f].params) == arg_count]
        return candidates
