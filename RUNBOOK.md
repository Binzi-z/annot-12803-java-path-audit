# PathGuard —— 自建 Java 路径穿越静态分析器

仅依赖 `tree-sitter` / `tree-sitter-java` 做语法解析，**AST 建模、过程内摘要、过程间
污点引擎、源/落点/净化目录全部自研**，不使用任何现成规则引擎或规则包。设计与口径见
[DESIGN.md](DESIGN.md)。

## 目录

```
analyzer/            分析器（9 个模块，见 DESIGN.md §14）
fixtures/repos/      三个仓库六个类的文件服务夹具（Controller/工具类/Filter）
tools/
  gen_samples.py     生成 50 条带标签样本（vulnerable/safe/unknown）
  eval_harness.py    召回/误报/性能/确定性/未知占比一体验证 + 硬性门禁
  selfcheck.py       编译检查 + 最小端到端
  test_ci_blocking.py 基线“只阻断新增”行为测试
ci/pathguard-ci.yml  CI 接入示例（三仓库、缓存、基线、SARIF 上传）
DESIGN.md            总体设计（含增量复用/无漂移/调用图上界/未知占比论证）
```

## 环境

```
pip install -r requirements.txt   # tree-sitter==0.26.1, tree-sitter-java==0.23.5
```

## 快速自检

```
python tools/selfcheck.py
```

## 三仓库扫描（输出 SARIF）

```
python -m analyzer.cli \
  fixtures/repos/repo-controller fixtures/repos/repo-common fixtures/repos/repo-filter-plugin \
  --out out/scan.sarif --cache-dir out/cache --metrics-out out/metrics.json
```

退出码：出现相对基线新增的 `PG-1001`（确定性路径穿越）即 1，否则 0。
`PG-1999`（规范化重载不可确定的未知路径）为 warning，不阻断但计入未知占比。

## 全量验证（题目指标）

```
python tools/eval_harness.py
```

产出 `out/eval/report.json`，并内置硬性门禁（任一不过则退出码 2）：

| 门禁 | 口径 |
|---|---|
| `recall_ge_0.85` | 50 样本召回 ≥ 85% |
| `false_positive_rate_le_0.15` | 安全样本误报率 ≤ 15%（unknown 样本单列） |
| `full_scan_lt_180s` | 确定性合成 ~20 万行工程冷全量 < 180 s |
| `incremental_lt_15s` | 单文件改动增量扫描 < 15 s |
| `two_runs_byte_identical` | 同提交双跑 SARIF 逐字节一致 |
| `cache_on_off_identical` | 缓存开/关 SARIF 逐字节一致（结论与缓存无关） |
| `call_graph_within_bound` | `edge_count ≤ 调用点数 × 16` 上界 |

报告同时给出调用图 `call_sites/edge_count/edge_upper_bound/truncated_*` 与
未知路径占比 `unknownPaths.unknown_edge_ratio`、`unknown_sink_ratio`。

## CI 基线阻断测试

```
python tools/test_ci_blocking.py
```

验证：安全码不阻断 → 同码对基线不阻断 → 注入新漏洞后阻断（退出码 1）。

## 两条关键工程保证（摘要复用）

- **增量复用**：缓存键 = 版本命名空间 + 方法 FQN + 方法体源码哈希；方法体字节不变即命中。
  增量时全量解析/索引保持跨文件视图完整，仅变更方法重算摘要。
- **无跨版本漂移**：缓存值是“未链接”摘要，调用目标（跨文件事实）在每次装载时由
  `link_calls` 针对当前索引重算，永不入缓存；依赖文件变更不需要使调用方缓存失效。
  详见 DESIGN.md §8。
