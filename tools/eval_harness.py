"""PathGuard 验证台：召回/误报、性能、确定性、未知占比、调用图上界，一次跑完。"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from analyzer.cli import run_scan
from analyzer.sarif import render_sarif
from tools.gen_samples import generate as gen_samples


def _scan(roots, cache_dir, use_cache=True, changed=None):
    t0 = time.perf_counter()
    res = run_scan(roots, cache_dir=cache_dir, use_cache=use_cache, changed_files=changed)
    blob = render_sarif(res["sarif"])
    return res, blob, time.perf_counter() - t0


def evaluate_samples(base: str) -> dict:
    sample_dir = os.path.join(base, "samples")
    if os.path.exists(sample_dir):
        shutil.rmtree(sample_dir)
    gen_stats = gen_samples(sample_dir)
    labels = json.load(open(os.path.join(sample_dir, "labels.json"), encoding="utf-8"))

    res, blob, wall = _scan([sample_dir], os.path.join(base, "cache-samples"))
    findings = res["findings"]

    def case_of(method_fqn: str) -> str:
        name = method_fqn.split("#", 1)[-1].split("(", 1)[0]
        # case06Read 这类配套方法归并到主用例 case06
        return name[:6] if name.startswith("case") else name

    hit_error: dict[str, int] = {}
    hit_unknown: dict[str, int] = {}
    for f in findings:
        cid = case_of(f.method_fqn)
        if f.rule_id == "PG-1001":
            hit_error[cid] = hit_error.get(cid, 0) + 1
        elif f.rule_id == "PG-1999":
            hit_unknown[cid] = hit_unknown.get(cid, 0) + 1

    tp = fn = fp = 0
    fp_cases, fn_cases, unknown_ok = [], [], []
    for lab in labels:
        cid = lab["id"]
        if lab.get("unknown"):
            if hit_unknown.get(cid) and not hit_error.get(cid):
                unknown_ok.append(cid)
            elif hit_error.get(cid):
                fp += 1
                fp_cases.append(cid)
            continue
        if lab["vulnerable"]:
            if hit_error.get(cid):
                tp += 1
            else:
                fn += 1
                fn_cases.append(cid)
        else:
            if hit_error.get(cid):
                fp += 1
                fp_cases.append(cid)
    vuln_n = sum(1 for x in labels if x["vulnerable"])
    safe_n = sum(1 for x in labels if not x["vulnerable"] and not x.get("unknown"))
    return {
        "sample_stats": gen_stats,
        "recall": round(tp / vuln_n, 4), "tp": tp, "fn": fn, "fn_cases": sorted(fn_cases),
        "false_positive_rate": round(fp / safe_n, 4), "fp": fp, "safe_n": safe_n,
        "fp_cases": sorted(fp_cases),
        "unknown_cases_recognized": len(unknown_ok),
        "unknown_total": sum(1 for x in labels if x.get("unknown")),
        "wall_s": round(wall, 3),
        "metrics": res["metrics"],
    }


def check_determinism(base: str, roots: list[str]) -> dict:
    """同提交连扫两次逐字节一致 + 缓存开/关结论一致。"""
    cache_a = os.path.join(base, "cache-det-a")
    cache_b = os.path.join(base, "cache-det-b")
    res1, blob1, _ = _scan(roots, cache_a, use_cache=True)
    res2, blob2, _ = _scan(roots, cache_a, use_cache=True)
    res3, blob3, _ = _scan(roots, cache_b, use_cache=False)
    return {
        "two_runs_byte_identical": blob1 == blob2,
        "cache_on_vs_off_byte_identical": blob1 == blob3,
        "finding_counts": {"cached": len(res1["findings"]), "nocache": len(res3["findings"])},
        "cache_stats_second_run": res2["metrics"]["cache"],
    }


def gen_big_corpus(base: str, target_loc: int = 200_000) -> tuple[str, int]:
    """确定性合成大工程：模板化类（无随机数），控制在 ~20 万行。"""
    big = os.path.join(base, "bigcorpus")
    if os.path.exists(big):
        shutil.rmtree(big)
    pkg_dir = os.path.join(big, "com", "scale")
    os.makedirs(pkg_dir, exist_ok=True)
    methods_per_class = 25
    lines_per_class = methods_per_class * 16 + 20
    n_classes = target_loc // lines_per_class + 1
    for ci in range(n_classes):
        lines = ["package com.scale;", "",
                 "import java.io.File;", "import java.io.FileInputStream;",
                 "import java.nio.file.Files;", "import java.nio.file.Paths;",
                 "import java.util.ArrayList;", "import java.util.List;",
                 "", f"public class Big{ci:04d} {{",
                 '    private String base = "/var/data";',
                 "    private String slot;"]
        for mi in range(methods_per_class):
            vuln = (ci * 7 + mi) % 11 == 0   # 确定性散布 ~9% 漏洞方法
            lines += [
                f"    public void m{mi:02d}(String requested) throws Exception {{"]
            if vuln:
                lines += [
                    "        List<String> xs = new ArrayList<>();",
                    "        xs.add(requested);",
                    "        for (String x : xs) {",
                    "            File f = new File(base, x);",
                    "            new FileInputStream(f);",
                    "        }",
                    "    }"]
            else:
                lines += [
                    "        String fixed = \"static/part\";",
                    "        File f = new File(base, fixed);",
                    "        if (Files.isDirectory(f.toPath())) {",
                    "            Files.newDirectoryStream(f.toPath());",
                    "        }",
                    "    }"]
        lines.append("}")
        with open(os.path.join(pkg_dir, f"Big{ci:04d}.java"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(lines) + "\n")
    loc = sum(sum(1 for _ in open(os.path.join(dp, f), encoding="utf-8"))
              for dp, _, fns in os.walk(big) for f in fns)
    return big, loc


def perf_full_and_incremental(base: str) -> dict:
    big, loc = gen_big_corpus(base)
    cache_dir = os.path.join(base, "cache-big")
    res_full, blob_full, wall_full = _scan([big], cache_dir, use_cache=True)
    # 第二次全量：全缓存命中
    _, _, wall_warm = _scan([big], cache_dir, use_cache=True)

    # 增量：改动一个文件
    pkg_dir = os.path.join(big, "com", "scale")
    changed_name = "Big0007.java"
    p = os.path.join(pkg_dir, changed_name)
    with open(p, "a", encoding="utf-8", newline="\n") as fh:
        fh.write("/* incremental touch */\n")
    t0 = time.perf_counter()
    res_inc, blob_inc, _ = _scan([big], cache_dir, use_cache=True,
                                 changed=[f"com/scale/{changed_name}"])
    wall_inc = time.perf_counter() - t0
    return {
        "loc": loc, "files": res_full["metrics"]["files"],
        "full_cold_s": round(wall_full, 3),
        "full_warm_s": round(wall_warm, 3),
        "incremental_s": round(wall_inc, 3),
        "meets_full_budget_180s": wall_full < 180,
        "meets_incremental_budget_15s": wall_inc < 15,
        "call_graph": res_full["metrics"]["callGraph"],
        "unknown_paths": res_full["metrics"]["unknownPaths"],
        "incremental_cache": res_inc["metrics"]["cache"],
    }


def main() -> int:
    base = os.path.join(ROOT, "out", "eval")
    if os.path.exists(base):
        shutil.rmtree(base)
    os.makedirs(base, exist_ok=True)

    report = {}
    report["sample_evaluation"] = evaluate_samples(base)
    fixture_roots = [os.path.join(ROOT, "fixtures", "repos", r)
                     for r in ("repo-controller", "repo-common", "repo-filter-plugin")]
    report["determinism"] = check_determinism(base, fixture_roots)
    report["performance"] = perf_full_and_incremental(base)

    # ---------------------------------------------------------- 硬性门禁
    se = report["sample_evaluation"]
    cg = report["performance"]["call_graph"]
    gates = {
        "recall_ge_0.85": se["recall"] >= 0.85,
        "false_positive_rate_le_0.15": se["false_positive_rate"] <= 0.15,
        "full_scan_lt_180s": report["performance"]["meets_full_budget_180s"],
        "incremental_lt_15s": report["performance"]["meets_incremental_budget_15s"],
        "two_runs_byte_identical": report["determinism"]["two_runs_byte_identical"],
        "cache_on_off_identical": report["determinism"]["cache_on_vs_off_byte_identical"],
        "call_graph_within_bound": (not cg["over_bound"])
        and cg["edge_count"] <= cg["edge_upper_bound"],
    }
    report["gates"] = gates
    report["all_gates_passed"] = all(gates.values())

    out = os.path.join(base, "report.json")
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(report, fh, ensure_ascii=False, sort_keys=True, indent=2)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if report["all_gates_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
