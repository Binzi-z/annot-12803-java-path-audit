"""扫描编排与 CLI：三仓库装载、摘要复用、链接、引擎、SARIF、CI 基线比对。"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time

from . import __version__
from .cache import SummaryCache
from .engine import InterEngine
from .index import GlobalIndex
from .intra import IntraAnalyzer
from .parser import parse_file
from .sarif import build_sarif, fingerprint, load_fingerprints, render_sarif


def discover_java_files(roots: list[str]) -> list[tuple[str, str, str]]:
    """返回 (repo 名, 仓库根, 相对路径)；repo 名取根目录名。"""
    out: list[tuple[str, str, str]] = []
    for root in sorted(roots):
        repo = os.path.basename(os.path.normpath(root))
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames.sort()
            for fn in sorted(filenames):
                if fn.endswith(".java"):
                    full = os.path.join(dirpath, fn)
                    out.append((repo, root, os.path.relpath(full, root).replace("\\", "/")))
    return out


def load_index_and_summaries(roots: list[str], cache: SummaryCache,
                             changed_rel: set[str] | None = None):
    t0 = time.perf_counter()
    discovered = discover_java_files(roots)
    files = []
    parse_ns = 0
    for repo, root, rel in discovered:
        full = os.path.join(root, rel.replace("/", os.sep))
        with open(full, "rb") as fh:
            source = fh.read()
        files.append(parse_file(repo, rel, source))
    parse_ns = time.perf_counter() - t0

    t1 = time.perf_counter()
    index = GlobalIndex(files)
    analyzer = IntraAnalyzer(index)
    summaries = {}
    for f in index.files:
        for fqn in sorted(f.methods):
            m = f.methods[fqn]
            body_hash = _body_hash(m, f.source)
            if changed_rel is not None and f.rel_path not in changed_rel:
                cached = cache.get(fqn, body_hash)
                if cached is not None:
                    summaries[fqn] = cached
                    continue
            cached = cache.get(fqn, body_hash)
            if cached is not None:
                summaries[fqn] = cached
                continue
            s = analyzer.analyze(m)
            cache.put(s)
            summaries[fqn] = s
    summary_ns = time.perf_counter() - t1

    t2 = time.perf_counter()
    index.link_calls(summaries)
    link_ns = time.perf_counter() - t2
    timing = {"parse_s": round(parse_ns, 3), "summary_s": round(summary_ns, 3),
              "link_s": round(link_ns, 3)}
    return index, summaries, timing, cache.stats(), len(discovered)


def _body_hash(m, source: bytes) -> str:
    from . import astutil as A
    import hashlib as _h
    body = A.text(m.body, source) if m.body is not None else ""
    return _h.sha256(body.encode("utf-8")).hexdigest()[:16]


def run_scan(roots: list[str], cache_dir: str, use_cache: bool,
             changed_files: list[str] | None = None) -> dict:
    cache = SummaryCache(cache_dir, enabled=use_cache)
    changed_rel = None
    if changed_files is not None:
        changed_rel = {p.replace("\\", "/") for p in changed_files}
    index, summaries, timing, cache_stats, n_files = load_index_and_summaries(
        roots, cache, changed_rel)

    t3 = time.perf_counter()
    engine = InterEngine(index, summaries)
    cg = index.build_call_graph()
    engine.note_edges(cg["edge_count"])
    findings = engine.run()
    engine_ns = time.perf_counter() - t3

    unknown = engine.unknown_metrics()
    metrics = {
        "toolVersion": __version__,
        "files": n_files,
        "timing": {**timing, "engine_s": round(engine_ns, 3),
                   "total_s": round(sum(timing.values()) + engine_ns, 3)},
        "callGraph": cg,
        "unknownPaths": unknown,
        "counts": {
            "errors": sum(1 for f in findings if f.rule_id == "PG-1001"),
            "warnings_unknown": sum(1 for f in findings if f.rule_id == "PG-1999"),
        },
    }
    # 运行时观测（耗时、缓存命中）绝不进 SARIF：否则同提交两次扫描的字节会不同。
    # SARIF 只保留结构性、确定性的指标。
    sarif_metrics = {k: v for k, v in metrics.items() if k not in ("cache", "timing")}
    sarif_doc = build_sarif(findings, sarif_metrics, __version__)
    metrics["cache"] = cache_stats
    return {"sarif": sarif_doc, "metrics": metrics, "findings": findings}


def write_changed_list(scm_root: str, out_path: str) -> None:
    """从 git 取增量改动文件（CI 中可替换为平台提供的变更清单）。"""
    import subprocess
    out = subprocess.run(["git", "-C", scm_root, "diff", "--name-only", "HEAD~1", "HEAD"],
                         capture_output=True, text=True, check=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(sorted(out.stdout.split())))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="PathGuard Java 路径穿越静态分析器")
    ap.add_argument("roots", nargs="+", help="一个或多个仓库根目录（控制层/工具库/过滤器插件）")
    ap.add_argument("--out", required=True, help="SARIF 输出路径")
    ap.add_argument("--cache-dir", default=".pathguard-cache")
    ap.add_argument("--no-cache", action="store_true", help="关闭摘要缓存（用于对照实验）")
    ap.add_argument("--baseline", help="基线 SARIF；给出后仅阻断相对基线新增的 fingerprint")
    ap.add_argument("--changed-list", help="增量模式：变更文件清单（每行一个仓库内相对路径）")
    ap.add_argument("--metrics-out", help="指标 JSON 输出路径")
    args = ap.parse_args(argv)

    changed = None
    if args.changed_list:
        with open(args.changed_list, "r", encoding="utf-8") as fh:
            changed = [ln.strip() for ln in fh if ln.strip()]

    result = run_scan(args.roots, args.cache_dir, use_cache=not args.no_cache,
                      changed_files=changed)
    blob = render_sarif(result["sarif"])
    with open(args.out, "wb") as fh:
        fh.write(blob)
    if args.metrics_out:
        with open(args.metrics_out, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(result["metrics"], fh, ensure_ascii=False, sort_keys=True, indent=2)

    m = result["metrics"]
    print(json.dumps(m, ensure_ascii=False, sort_keys=True, indent=2))

    # CI 阻断策略：error 级 finding；有基线时仅新增才阻断，UNKNOWN 仅警告不阻断
    new_errors = []
    baseline_fps = load_fingerprints(args.baseline) if args.baseline else set()
    for f in result["findings"]:
        if f.rule_id != "PG-1001":
            continue
        if not baseline_fps or fingerprint(f) not in baseline_fps:
            new_errors.append(f)
    print(f"[PathGuard] findings={m['counts']} new_blocking={len(new_errors)} "
          f"unknown_sink_ratio={m['unknownPaths']['unknown_sink_ratio']}")
    return 1 if new_errors else 0


if __name__ == "__main__":
    sys.exit(main())
