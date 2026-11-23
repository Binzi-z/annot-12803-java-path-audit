"""过程间引擎：在方法摘要之上构建全局标签图，做字段不动点 + 需求驱动污点到达分析。

确定性保证：所有遍历均按排序后的键进行，不使用集合迭代序、时间戳或随机数；
缓存命中与否只改变“摘要从文件读还是重新算”，输入相同则图与结论完全一致。
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import catalog as C
from .intra import DepSet, DepTag, MethodSummary, parse_tag
from .index import GlobalIndex

CALL_STRING_BOUND = 8
MAX_CALLEE_SITES_PER_CALL = 16
_SANITIZER_NAME_RE = re.compile(C.SANITIZER_HELPER_REGEX)


@dataclass
class Finding:
    rule_id: str
    kind: str
    level: str                 # FINDING / UNKNOWN
    repo: str
    file: str
    line: int
    method_fqn: str
    source_kinds: list[str]
    unknown_ratio: float
    path: list[dict]


class InterEngine:
    def __init__(self, index: GlobalIndex, summaries: dict[str, MethodSummary]):
        self.idx = index
        self.summaries = summaries
        self.unknown_edges: set[str] = set()
        self.total_edges = 0
        self.unknown_sink_arrivals = 0
        self.total_sink_arrivals = 0
        self._build_global_edges()

    # ---------------------------------------------------- 被调闭包回译（核心）
    def _callee_return_tags(self, caller: MethodSummary, call, depth: int) -> set[str]:
        """展开一个调用点：把被调方 ret 闭包翻译回调用者词表。

        - src/field/coll/unk 标签原样上带；
        - arg:i 回译为该调用点第 i 个实参的依赖标签（跨方法连接的关键）；
        - 被调方法经结构核验为自定义净化工具时，整体打 sanitized 标记。
        """
        out: set[str] = set()
        sanitizer = False
        for target in sorted(call.targets)[:MAX_CALLEE_SITES_PER_CALL]:
            ts = self.summaries.get(target)
            if ts is None:
                self.unknown_edges.add(f"{caller.fqn}->{target}")
                out.add(DepTag(f"unk:missing:{target}", unknown=True).canon())
                continue
            if self._is_verified_sanitizer(ts):
                sanitizer = True
            for canon in self._expand(ts, ts.ret_deps, depth + 1):
                tag = parse_tag(canon)
                if tag.key.startswith("arg:"):
                    try:
                        i = int(tag.key.split(":", 1)[1])
                    except ValueError:
                        continue
                    if i < len(call.arg_deps):
                        for d in call.arg_deps[i]:
                            dt = parse_tag(d)
                            out.add(dt.with_flags(
                                sanitized=sanitizer or dt.sanitized,
                                unknown=dt.unknown).canon())
                else:
                    out.add(tag.with_flags(sanitized=sanitizer or tag.sanitized).canon()
                            if not tag.unknown else tag.canon())
        if not call.targets:
            # 只有“规范化方法且重载不可确定”才计未知（PG-1999 口径）；
            # 普通外部 JDK/三方调用返回普通伪标签，不污染未知占比、不翻转漏洞等级
            if C.is_normalizer_name(call.name):
                self.unknown_edges.add(f"{caller.fqn}->{call.name}@line{call.line}")
                out.add(DepTag(f"unk:external:{call.name}", unknown=True).canon())
            else:
                out.add(DepTag(f"ext:{call.name}").canon())
        return out

    # ------------------------------------------------------------ 全局字段边
    def _build_global_edges(self) -> None:
        """字段/集合写闭包：field 标签 <- 写入依赖的闭包（按方法摘要展开 call 伪标签）。

        跨调用字段写替换：被调方法字段写中的 arg:i，在调用点替换为该调用第 i 个
        实参的依赖标签——否则经 setter 链进入字段槽的源会断在被调方法的形参上。
        外层不动点保证多跳 setter 链最终收敛。
        """
        self.global_edges: dict[str, set[str]] = {}
        dirty = True
        rounds = 0
        while dirty and rounds < 64:
            dirty = False
            rounds += 1
            for fqn in sorted(self.summaries):
                s = self.summaries[fqn]
                for gtag, deps in sorted({**s.field_writes, **s.coll_writes}.items()):
                    cur = self.global_edges.setdefault(gtag, set())
                    expanded = self._expand(s, deps, depth=0)
                    if cur.symmetric_difference(expanded):
                        cur.update(expanded)
                        dirty = True
                # 调用点：把被调方的字段/集合写按实参回译后并入全局槽
                for call in sorted(s.calls, key=lambda c: c.site):
                    for target in sorted(call.targets)[:MAX_CALLEE_SITES_PER_CALL]:
                        ts = self.summaries.get(target)
                        if ts is None:
                            continue
                        for gtag, deps in sorted({**ts.field_writes, **ts.coll_writes}.items()):
                            substituted = self._subs_args(deps, call, depth=0)
                            cur = self.global_edges.setdefault(gtag, set())
                            if cur.symmetric_difference(substituted):
                                cur.update(substituted)
                                dirty = True

    def _subs_args(self, tag_canon_list: list[str], call, depth: int) -> set[str]:
        """把被调方摘要里的 arg:i 替换为调用点实参依赖；其余标签原样保留。"""
        out: set[str] = set()
        for canon in sorted(tag_canon_list):
            tag = parse_tag(canon)
            if tag.key.startswith("arg:"):
                try:
                    i = int(tag.key.split(":", 1)[1])
                except ValueError:
                    continue
                if i < len(call.arg_deps):
                    out.update(call.arg_deps[i])
            else:
                out.add(canon)
        return out

    def _expand(self, s: MethodSummary, tag_canon_list: list[str], depth: int) -> set[str]:
        """把 call:k 伪标签替换成被调方法返回闭包；返回全局规范标签集合。"""
        out: set[str] = set()
        calls_by_pseudo = {c.pseudo: c for c in s.calls}
        for canon in sorted(tag_canon_list):
            tag = parse_tag(canon)
            if tag.key.startswith("call:"):
                call = calls_by_pseudo.get(tag.key)
                if call is None or depth >= CALL_STRING_BOUND:
                    self.unknown_edges.add(f"{s.fqn}->{tag.key}")
                    out.add(tag.canon())
                    continue
                out |= self._callee_return_tags(s, call, depth)
            else:
                out.add(canon)
        return out

    # ------------------------------------------------------------ 入口驱动
    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        entry_fqns = sorted(f for f, sm in self.summaries.items() if sm.direct_sources)
        for fqn in entry_fqns:
            sm = self.summaries[fqn]
            for src in sorted(sm.direct_sources, key=lambda x: x["line"]):
                # 传播过程会在链路上每个方法（含被调方）内做落点判定
                self._propagate(fqn, DepTag(f"src:{src['kind']}").canon(),
                                origin_line=src["line"], call_stack=(),
                                src_kind=src["kind"], findings=findings)
        self._drive_global_sources(findings)
        return self._dedup(findings)

    def _drive_global_sources(self, findings: list[Finding]) -> None:
        """源经 setter/字段流入字段槽，再在另一方法的 sink 命中（跨类跨包主场景）。"""
        source_globals: set[str] = set()
        for fqn in sorted(self.summaries):
            sm = self.summaries[fqn]
            if not sm.direct_sources:
                continue
            for gtag, edges in sorted(self.global_edges.items()):
                if any(parse_tag(e).key.startswith("src:") for e in edges):
                    source_globals.add(gtag)
        for gtag in sorted(source_globals):
            for fqn in sorted(self.summaries):
                sm = self.summaries[fqn]
                for snk in sorted(sm.sinks, key=lambda x: x.line):
                    dep_keys = self._effective_sink_keys(sm, snk)
                    if gtag in dep_keys or any(k in self.global_edges.get(gtag, set()) for k in dep_keys):
                        src_kinds = sorted({parse_tag(e).key.split(":", 1)[1]
                                            for e in self.global_edges[gtag]
                                            if parse_tag(e).key.startswith("src:")})
                        self._emit(fqn, snk, src_kinds,
                                   unknown=any(parse_tag(d).unknown for d in snk.deps),
                                   via=gtag, findings=findings)

    # ------------------------------------------------------------ 有界传播
    def _propagate(self, fqn: str, entry_canon: str, origin_line: int,
                   call_stack: tuple[str, ...], src_kind: str,
                   findings: list[Finding]) -> set[str]:
        """从方法内一个入口标签出发，做调用串有界的闭包到达，返回可到达标签（带标记）。

        链路上每个方法的落点都在这里判定（覆盖“污点实参进入被调方法、落点在被调方”）。
        """
        s = self.summaries.get(fqn)
        if s is None:
            return {entry_canon}
        if fqn in call_stack or len(call_stack) >= CALL_STRING_BOUND:
            self.unknown_edges.add(f"bounded:{fqn}")
            return {entry_canon}
        reach: set[str] = {entry_canon}
        changed = True
        guard = 0
        local_edges = self._local_edges(s)
        while changed and guard < 128:
            changed = False
            guard += 1
            for a in sorted(list(reach)):
                for b in sorted(local_edges.get(a, set())):
                    if b not in reach:
                        reach.add(b)
                        changed = True
        # 当前方法（含被调方）自身的落点判定
        for snk in sorted(s.sinks, key=lambda x: x.line):
            self._check_sink(fqn, snk, reach, src_kind, findings)
        # call 伪标签跨方法连接：用被调闭包回译替换
        for canon in sorted(list(reach)):
            tag = parse_tag(canon)
            if tag.key.startswith("call:"):
                call = next((c for c in s.calls if c.pseudo == tag.key), None)
                if call is None:
                    continue
                if len(call_stack) >= CALL_STRING_BOUND:
                    self.unknown_edges.add(f"bounded:{fqn}")
                    continue
                reach |= self._callee_return_tags(s, call, len(call_stack))
                # 实参污点进入被调方后再向上带出的 src/field 闭包已由回译覆盖
                for target in sorted(call.targets)[:MAX_CALLEE_SITES_PER_CALL]:
                    if target not in self.summaries:
                        continue
                    arg_in: set[str] = set()
                    for i, deps in enumerate(call.arg_deps):
                        if any(parse_tag(d).key == tag.key for d in deps):
                            arg_in.add(DepTag(f"arg:{i}",
                                              sanitized=tag.sanitized, unknown=tag.unknown).canon())
                    if not arg_in:
                        arg_in = {DepTag("arg:0", sanitized=tag.sanitized,
                                         unknown=tag.unknown).canon()}
                    for start in arg_in:
                        sub = self._propagate(target, start, origin_line,
                                              call_stack + (fqn,), src_kind, findings)
                        for r in sub:
                            rt = parse_tag(r)
                            if rt.key.startswith(("src:", "field:", "coll:", "unk:")):
                                reach.add(r)
        # 字段槽读：合并全局字段边
        extra: set[str] = set()
        for canon in reach:
            tag = parse_tag(canon)
            if tag.key.startswith(("field:", "static:", "coll:")):
                for e in self.global_edges.get(tag.key, set()):
                    extra.add(e)
        reach |= extra
        return reach

    def _effective_sink_keys(self, s: MethodSummary, snk) -> set[str]:
        """落点实参经 call 伪标签展开 + 全局字段边展开后的有效标签键集合。"""
        keys: set[str] = set()
        for d in snk.deps:
            for canon in self._expand(s, [d], 0):
                tag = parse_tag(canon)
                keys.add(tag.key)
                if tag.key.startswith(("field:", "static:", "coll:")):
                    keys.update(parse_tag(e).key for e in self.global_edges.get(tag.key, set()))
        return keys

    def _is_verified_sanitizer(self, s: MethodSummary) -> bool:
        """自定义净化工具确认（满足任一证据组合，保守原则）：
        A. 方法体同时含“已知规范化方法”和“前缀/穿越校验守卫”；
        B. 含穿越片段 reject 守卫（if(contains("..")) throw/return），与过程内语义一致。
        仅名字像净化但无证据（如只 getAbsolutePath）一律不确认。"""
        if not _SANITIZER_NAME_RE.match(s.fqn.split("#", 1)[-1].split("(", 1)[0]):
            return False
        has_norm = any(u.get("resolved") for u in s.normalizer_uses)
        has_guard = bool(s.prefix_guards)
        has_reject = bool(getattr(s, "reject_guards", []))
        return (has_norm and has_guard) or has_reject

    def _local_edges(self, s: MethodSummary) -> dict[str, set[str]]:
        """由摘要重建方法内标签闭包边（确定性地按排序构建）。"""
        edges: dict[str, set[str]] = {}

        def add(a: str, b: str) -> None:
            edges.setdefault(a, set()).add(b)

        for c in s.calls:
            for deps in c.arg_deps:
                for d in deps:
                    add(d, c.pseudo)
        for gtag, deps in {**s.field_writes, **s.coll_writes}.items():
            for d in deps:
                add(d, gtag)
        for d in s.ret_deps:
            add(d, "ret")
        return edges

    # ------------------------------------------------------------ sink 判定
    def _check_sink(self, fqn: str, snk, arrival: set[str], src_kind: str,
                    findings: list[Finding]) -> None:
        s = self.summaries[fqn]
        # 先把落点实参里的 call:k 伪标签展开成被调方返回闭包，
        # 再把 field/coll 标签沿全局字段边展开，得到“有效落点依赖”
        effective: dict[str, DepTag] = {}
        for d in snk.deps:
            for canon in self._expand(s, [d], 0):
                t = parse_tag(canon)
                self._merge_weak(effective, t)
                if t.key.startswith(("field:", "static:", "coll:")):
                    for e in self.global_edges.get(t.key, set()):
                        self._merge_weak(effective, parse_tag(e))
        arrive_keys = {parse_tag(a).key for a in arrival}
        arrive_unknown = {parse_tag(a).key for a in arrival if parse_tag(a).unknown}
        # 命中：有效落点标签的键能在到达集合中找到。净化位以“落点侧摘要标签”为准
        # （过程内分析精确记录），入口播种标签不参与净化 AND，避免误报。
        hit = [t for key, t in sorted(effective.items()) if key in arrive_keys]
        if not hit:
            return
        self.total_sink_arrivals += 1
        unknown = any(t.unknown for t in hit) or snk.unknown or any(
            t.key in arrive_unknown for t in hit)
        sanitized = all(t.sanitized for t in hit)
        if unknown:
            self.unknown_sink_arrivals += 1
        if sanitized and not unknown:
            return
        self._emit(fqn, snk, [src_kind], unknown=unknown, via=None, findings=findings)

    @staticmethod
    def _merge_weak(m: dict[str, DepTag], t: DepTag) -> None:
        old = m.get(t.key)
        if old is None:
            m[t.key] = t
        else:
            # 同键取最弱：未净化优先、未知优先
            m[t.key] = DepTag(t.key, sanitized=old.sanitized and t.sanitized,
                              unknown=old.unknown or t.unknown)

    def _emit(self, fqn: str, snk, src_kinds: list[str], unknown: bool,
              via: str | None, findings: list[Finding]) -> None:
        m = self.idx.methods.get(fqn)
        if m is None:
            return
        findings.append(Finding(
            rule_id="PG-1999" if unknown else "PG-1001",
            kind=snk.kind,
            level="UNKNOWN" if unknown else "FINDING",
            repo=m.repo, file=m.file_rel, line=snk.line, method_fqn=fqn,
            source_kinds=sorted(set(src_kinds)),
            unknown_ratio=0.0,
            path=[{"file": m.file_rel, "line": snk.line, "via": via or "sink", "kind": snk.kind}],
        ))

    def _dedup(self, findings: list[Finding]) -> list[Finding]:
        seen: set[tuple] = set()
        out: list[Finding] = []
        for f in sorted(findings, key=lambda x: (x.file, x.line, x.kind, x.method_fqn, x.level)):
            key = (f.rule_id, f.file, f.line, f.kind, f.method_fqn)
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out

    # ------------------------------------------------------------ 指标
    def unknown_metrics(self) -> dict:
        total = self.total_edges or 1
        return {
            "unknown_edge_count": len(self.unknown_edges),
            "total_edge_count": self.total_edges,
            "unknown_edge_ratio": round(len(self.unknown_edges) / total, 6),
            "unknown_sink_arrivals": self.unknown_sink_arrivals,
            "total_sink_arrivals": self.total_sink_arrivals,
            "unknown_sink_ratio": round(
                self.unknown_sink_arrivals / self.total_sink_arrivals, 6)
                if self.total_sink_arrivals else 0.0,
        }

    def note_edges(self, n: int) -> None:
        self.total_edges = max(self.total_edges, n)
