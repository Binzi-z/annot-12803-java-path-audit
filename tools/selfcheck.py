"""快速自检：语法编译 + 单文件解析 + 摘要生成 + 引擎最小端到端。"""
import sys

ROOT = r"D:\AI-zhongqiang\feedback\选题\12803\作答工作区_cc-12803-20261124-r1"
sys.path.insert(0, ROOT)

import py_compile  # noqa: E402
from pathlib import Path  # noqa: E402

for p in Path(ROOT, "analyzer").glob("*.py"):
    py_compile.compile(str(p), doraise=True)
print("compile ok")

from analyzer.parser import parse_file  # noqa: E402
from analyzer.index import GlobalIndex  # noqa: E402
from analyzer.intra import IntraAnalyzer  # noqa: E402
from analyzer.engine import InterEngine  # noqa: E402

SRC = b"""
package demo;
import java.io.File;
import java.io.FileInputStream;
public class DemoController {
    private String base = "/var/data";
    public void download(String requested) throws Exception {
        File target = new File(base, requested);
        new FileInputStream(target);
    }
}
"""
fu = parse_file("demo", "DemoController.java", SRC)
assert "demo.DemoController#download(String)" in fu.methods, list(fu.methods)
idx = GlobalIndex([fu])
ia = IntraAnalyzer(idx)
sums = {fqn: ia.analyze(m) for fqn, m in idx.methods.items()}
idx.link_calls(sums)
eng = InterEngine(idx, sums)
findings = eng.run()
print("findings:", [(f.rule_id, f.kind, f.line) for f in findings])
assert any(f.rule_id == "PG-1001" for f in findings), "expected PG-1001"
print("selfcheck ok")
