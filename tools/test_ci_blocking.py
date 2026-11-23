"""CI 基线阻断行为测试（确定性、无需联网）：

1. 首次扫描建立基线；
2. 同代码再扫，无新增 -> 退出码 0（不阻断存量）；
3. 注入一个新漏洞后再扫 -> 退出码 1（阻断新增），且 SARIF 含新 fingerprint。
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SAFE = """
package demo;
import java.io.File;
import java.io.FileInputStream;
public class DemoController {
    private String base = "/var/data";
    public void download(String requested) throws Exception {
        if (requested.contains("..")) { throw new SecurityException("x"); }
        new FileInputStream(new File(base, requested));
    }
}
"""

VULN = """
package demo;
import java.io.File;
import java.io.FileInputStream;
public class DemoController {
    private String base = "/var/data";
    public void download(String requested) throws Exception {
        new FileInputStream(new File(base, requested));
    }
    public void download2(String requested) throws Exception {
        new FileInputStream(new File(base, requested + "/x"));
    }
}
"""


def run_cli(repo, out, baseline=None):
    cmd = [sys.executable, "-m", "analyzer.cli", repo,
           "--out", out, "--cache-dir", os.path.join(os.path.dirname(out), "cache")]
    if baseline:
        cmd += ["--baseline", baseline]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def main():
    work = tempfile.mkdtemp(prefix="pg-ci-test-")
    try:
        repo = os.path.join(work, "repo")
        os.makedirs(os.path.join(repo, "demo"), exist_ok=True)
        src = os.path.join(repo, "demo", "DemoController.java")
        base_sarif = os.path.join(work, "baseline.sarif")
        cur_sarif = os.path.join(work, "current.sarif")

        with open(src, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(SAFE)
        rc, log = run_cli(repo, base_sarif)
        assert rc == 0, f"safe code should not block:\n{log}"

        # 同代码对基线再扫：无新增
        rc, log = run_cli(repo, cur_sarif, baseline=base_sarif)
        assert rc == 0, f"unchanged code must not block:\n{log}"

        # 注入新漏洞
        with open(src, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(VULN)
        rc, log = run_cli(repo, cur_sarif, baseline=base_sarif)
        assert rc == 1, f"new vulnerability must block (got rc={rc}):\n{log}"

        doc = json.load(open(cur_sarif, encoding="utf-8"))
        n_err = sum(1 for r in doc["runs"][0]["results"] if r["ruleId"] == "PG-1001")
        assert n_err >= 2, f"expected >=2 error findings, got {n_err}"
        print("CI baseline blocking test: PASS")
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
