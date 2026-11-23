"""内容寻址的方法摘要缓存。

缓存键只包含：分析器/schema/目录版本 + 方法 FQN + 方法体源码哈希。
缓存值是“未链接”的摘要（call.targets 恒为空、resolution=PENDING），跨文件解析
结果永不入缓存——每次装载都针对当前索引重新 link，因此：
  1. 增量复用：方法体字节不变即命中，与该方法在哪个提交、哪台机器上无关；
  2. 无跨版本漂移：依赖文件改了只影响装载期链接，旧缓存值不含任何外部符号事实；
  3. 版本升级：命名空间整体更换，旧缓存自然不可见，不存在新旧 schema 混用。
"""
from __future__ import annotations

import hashlib
import json
import os

from . import CATALOG_VERSION, SUMMARY_SCHEMA_VERSION, __version__
from .intra import CallRecord, MethodSummary, SinkRecord


class SummaryCache:
    def __init__(self, cache_dir: str, enabled: bool = True):
        self.enabled = enabled
        ns = hashlib.sha256(
            f"{__version__}|{CATALOG_VERSION}|{SUMMARY_SCHEMA_VERSION}".encode("utf-8")).hexdigest()[:16]
        self.root = os.path.join(cache_dir, ns)
        self.hits = 0
        self.misses = 0
        if enabled:
            os.makedirs(self.root, exist_ok=True)

    def _key(self, fqn: str, body_hash: str) -> str:
        raw = f"{__version__}|{SUMMARY_SCHEMA_VERSION}|{CATALOG_VERSION}|{fqn}|{body_hash}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _path(self, key: str) -> str:
        return os.path.join(self.root, key[:2], key + ".json")

    def get(self, fqn: str, body_hash: str) -> MethodSummary | None:
        if not self.enabled:
            self.misses += 1
            return None
        p = self._path(self._key(fqn, body_hash))
        if not os.path.exists(p):
            self.misses += 1
            return None
        try:
            with open(p, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            # 防御：即便文件被手工串改，body_hash/fqn 不一致也拒绝使用
            if data.get("fqn") != fqn or data.get("content_hash") != body_hash:
                self.misses += 1
                return None
            self.hits += 1
            return _summary_from_json(data)
        except (json.JSONDecodeError, OSError, KeyError):
            self.misses += 1
            return None

    def put(self, summary: MethodSummary) -> None:
        if not self.enabled:
            return
        key = self._key(summary.fqn, summary.content_hash)
        p = self._path(key)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(summary.to_json(), fh, ensure_ascii=False, sort_keys=True, indent=0)
        os.replace(tmp, p)   # 原子发布，避免并发/中断产生半截缓存

    def stats(self) -> dict:
        return {"cache_enabled": self.enabled, "cache_hits": self.hits, "cache_misses": self.misses}


def _summary_from_json(d: dict) -> MethodSummary:
    return MethodSummary(
        fqn=d["fqn"], content_hash=d["content_hash"],
        params=[tuple(x) for x in d["params"]],
        ret_deps=list(d["ret_deps"]),
        field_writes={k: list(v) for k, v in d["field_writes"].items()},
        coll_writes={k: list(v) for k, v in d["coll_writes"].items()},
        sinks=[SinkRecord(**x) for x in d["sinks"]],
        calls=[CallRecord(targets=[], resolution="PENDING", **{
            k: v for k, v in x.items() if k not in ("targets", "resolution")}) for x in d["calls"]],
        unknown_calls=list(d["unknown_calls"]),
        direct_sources=list(d["direct_sources"]),
        local_coll_types=dict(d["local_coll_types"]),
        normalizer_uses=list(d.get("normalizer_uses", [])),
        prefix_guards=list(d.get("prefix_guards", [])),
        reject_guards=list(d.get("reject_guards", [])),
    )
