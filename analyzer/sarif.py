"""确定性 SARIF 2.1.0 输出。

逐字节一致手段：结果按稳定键排序、JSON sort_keys、固定分隔符与换行、
不写时间戳/主机名/绝对路径（仓库内相对路径）、fingerprint 用内容哈希。
"""
from __future__ import annotations

import hashlib
import io
import json

from .engine import Finding

RULES = [
    {
        "id": "PG-1001",
        "name": "PathTraversalFlow",
        "shortDescription": {"text": "外部可控路径到达文件/解压/静态服务/模板落点且未完成净化"},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://internal/pathguard/PG-1001",
    },
    {
        "id": "PG-1999",
        "name": "UnknownPathNormalization",
        "shortDescription": {"text": "路径规范化重载不可唯一确定，污点到达无法判定（未知路径）"},
        "defaultConfiguration": {"level": "warning"},
        "helpUri": "https://internal/pathguard/PG-1999",
    },
]

KIND_TEXT = {
    "FILE_READ": "文件读取/路径拼接",
    "UNZIP": "解压落盘",
    "STATIC_SERVE": "静态目录服务",
    "TEMPLATE_INCLUDE": "模板 include",
}


def fingerprint(f: Finding) -> str:
    raw = "|".join([f.rule_id, f.repo, f.file, str(f.line), f.kind, f.method_fqn])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _result(f: Finding) -> dict:
    loc = f"{f.repo}/{f.file}" if f.repo else f.file
    return {
        "ruleId": f.rule_id,
        "level": "error" if f.rule_id == "PG-1001" else "warning",
        "message": {"text": ("[%s] %s：源 %s 未净化到达落点（方法 %s）" % (
            f.rule_id, KIND_TEXT.get(f.kind, f.kind),
            ",".join(f.source_kinds) or "UNKNOWN", f.method_fqn))},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": loc.replace("\\", "/"), "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": f.line},
            }
        }],
        "partialFingerprints": {"pathGuard/v1": fingerprint(f)},
        "properties": {"findingLevel": f.level, "sinkKind": f.kind,
                       "sourceKinds": f.source_kinds, "unknownRatio": f.unknown_ratio},
    }


def build_sarif(findings: list[Finding], metrics: dict, tool_version: str) -> dict:
    results = [_result(f) for f in sorted(
        findings, key=lambda x: (x.rule_id, x.repo, x.file, x.line, x.kind))]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "PathGuard",
                "version": tool_version,
                "informationUri": "https://internal/pathguard",
                "rules": RULES,
            }},
            "results": results,
            "invocations": [{"executionSuccessful": True,
                             "endTimeUtc": "1970-01-01T00:00:00Z"}],
            "properties": {"pathGuardMetrics": metrics},
        }],
    }


def render_sarif(doc: dict) -> bytes:
    # sort_keys + 紧凑分隔符 + 统一 LF：同一输入必然逐字节一致
    buf = io.StringIO()
    json.dump(doc, buf, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    buf.write("\n")
    return buf.getvalue().encode("utf-8")


def load_fingerprints(sarif_path: str) -> set[str]:
    """从基线 SARIF 读取 fingerprint 集合，用于 CI“仅阻断新增”。"""
    with open(sarif_path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    out: set[str] = set()
    for run in doc.get("runs", []):
        for r in run.get("results", []):
            fp = r.get("partialFingerprints", {}).get("pathGuard/v1")
            if fp:
                out.add(fp)
    return out
