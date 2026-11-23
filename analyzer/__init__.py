"""PathGuard —— 仅基于 tree-sitter 语法解析自建的 Java 路径穿越静态分析器。

模块划分：
  astutil  语法树通用工具
  catalog  自建的源/落点/净化方法目录（分析模型，非第三方规则）
  parser   单文件解析与类型/类/方法抽取
  index    跨仓库符号索引、调用解析、调用图与边数上界
  intra    过程内符号化摘要
  engine   字段不动点 + 带调用串的需求驱动过程间传播
  cache    内容寻址摘要缓存
  sarif    确定性 SARIF 输出
  cli      扫描入口与指标
"""

__version__ = "1.0.0"
# 目录/模式（catalog）与摘要 schema 的版本号，进入缓存键，版本升级即整体换命名空间
CATALOG_VERSION = "cat-3"
SUMMARY_SCHEMA_VERSION = "sum-5"
