# PathGuard：Java 路径穿越静态分析器设计文档

## 1. 目标与硬约束

| 维度 | 要求 | 设计落点 |
|---|---|---|
| 漏洞类型 | `../` 跳出根目录的路径穿越 | 污点流：源 → 传播 → 落点，净化可阻断 |
| 技术红线 | 只用语法解析库自建 AST 与过程间摘要，**不许套现成规则** | 仅依赖 `tree-sitter` / `tree-sitter-java`；源、落点、净化目录（`catalog.py`）与数据流引擎全部自研，无任何规则引擎/规则包 |
| 落点 | 文件读取拼接、解压落盘、静态目录服务、模板 include | 四类 SinkSpec，见 §4 |
| 源 | 请求参数、上传文件名、配置 | 三类 SourceSpec（另含 ZipEntry 条目名这一文件内源） |
| 传播 | 跨类跨包、getter/setter、集合 | field-based 全局槽 + 集合槽 + 调用回译，见 §6 |
| 净化 | 规范化路径 + 前缀校验 | 双重证据确认；只做其一不算净化，见 §5 |
| 输出 | SARIF，CI 阻断新增 | 确定性 SARIF 2.1.0 + fingerprint 基线比对 |
| 精度 | 50 样本召回 ≥85%、误报 ≤15% | §10 验证口径 |
| 性能 | 20 万行全量 <3 分钟、增量 <15 秒 | 摘要内容寻址缓存 + 装载期链接，§8 |
| 范围 | 控制层、公共工具库、过滤器插件三仓库，跨仓调用连得上 | 统一逻辑工程命名空间，§7 |
| 确定性 | 同提交双跑 SARIF 逐字节一致；缓存命中与否不改变结论 | §9 |
| 调用图 | 边数上界 + 超界策略 | §7.3 |
| 未知 | 规范化重载不可确定标未知，报告给未知路径占比 | §5.3、§11 |

## 2. 总体架构与数据流

```
                 ┌────────────── 三仓库源码（controller / common / filter-plugin）
                 ▼
   parser.py   tree-sitter 具体语法树 → FileUnit（包/导入/类/字段/方法/方法体哈希）
                 ▼
   index.py    GlobalIndex：类短名↔FQN、import 表、方法短名族、继承/接口族
                 ▼
   intra.py    过程内符号化分析 → MethodSummary（外部词表上的依赖闭包，不含跨文件事实）
                 ▼                        ▲
   cache.py    内容寻址缓存（方法体哈希命中即复用）┘
                 ▼
   index.link_calls()  装载期统一解析调用目标（结果永不入缓存）—— 无漂移的关键
                 ▼
   engine.py   全局字段/集合槽不动点 + 调用串有界的需求驱动过程间传播
                 ▼
   sarif.py    确定性排序/序列化 → SARIF；fingerprint 与基线比对 → CI 阻断判定
```

分层的核心思想：**过程内产物（摘要）与过程间事实（调用解析）物理分离**。摘要只描述“这个方法体内部，外部词表符号之间如何依赖”，不引用任何其他文件的符号状态；调用目标在每次扫描装载时针对当前索引重新链接。这一条同时支撑了增量复用、无跨版本漂移和缓存无关确定性（§8、§9）。

## 3. 自建 AST（不使用任何现成规则）

- `parser.py` 调 `tree-sitter-java` 得到具体语法树（CST），自行遍历 `class_declaration / method_declaration / method_invocation / field_access / assignment_expression / enhanced_for_statement` 等节点，抽取：
  - 包名、`import` 列表、类的 extends/implements；
  - 字段名→类型、方法签名（FQN 形如 `pkg.Cls#name(arg 短类型,...)`）、构造器归一为 `<init>`；
  - 方法体节点与方法体字节哈希（SHA-256 前 16 位）。
- 类型只做**短名 + import 解析 + 同名类族**，不做完整 Java 类型推断：这是精度与性能的刻意折中，配合多态目标族（§7.2）保证不漏。
- 分析模型（哪些方法是源/落点/净化）写在自研的 `catalog.py`，它是**建模规格**而非第三方规则：条目是“方法短名 + 接收者类型名特征 + 所在方法名正则”，匹配与数据流都由本仓库代码执行。升级模型走 `CATALOG_VERSION`，整体更换缓存命名空间。

## 4. 源与落点模型

### 4.1 源（三类 + 一类文件内源）

| kind | 识别方式 |
|---|---|
| REQUEST | `getParameter / getParameterValues / getHeader / getQueryString` |
| UPLOAD | 接收者类型含 `MultipartFile/FileItem` 特征的 `getSubmittedFileName / getName`（类型特征约束避免 `getName` 误伤） |
| CONFIG | `System.getProperty / getEnv / Properties.getProperty / Config.getString`，以及 `@Value`、`@ConfigurationProperty` 标注的参数/字段 |
| ZIP_ENTRY | `ZipEntry/JarEntry/ZipFile` 上的 `getName`（解压条目名，Zip Slip 的文件内源） |

源在过程内表现为不可再上溯的标签 `src:KIND`。

### 4.2 落点（四类）

| kind | 代表 API |
|---|---|
| FILE_READ | `new FileInputStream/FileReader/RandomAccessFile`、`Files.readAllBytes/readString/lines/newInputStream/exists/isDirectory/list/newDirectoryStream` |
| UNZIP | 仅在方法名匹配 `unzip/extract/untar/decompress` 语义的方法内命中 `FileOutputStream` 构造、`Files.write/copy`（避免把普通写盘误算解压落点） |
| STATIC_SERVE | `ResourceHandlerRegistry.addResourceLocations`、`ResourceHttpRequestHandler.setResourceLocations`、`FileSystemResource` 构造，以及 serve/static/resource/download 语义方法内的文件读取 |
| TEMPLATE_INCLUDE | `getRequestDispatcher`、`RequestDispatcher.include`、FreeMarker `Configuration.getTemplate`、`TemplateEngine.process` |

路径构造 API（`Paths.get / Path.of / Path.resolve / resolveSibling / new File`）不是落点，按**依赖透传**处理：实参污点传到返回值。

## 5. 净化模型：规范化 + 前缀校验，双重证据

### 5.1 认可的净化范式

只有满足下列之一，污点标签才获得 `sanitized` 标记：

1. **已知规范化 + 前缀校验**：`Path.normalize / toRealPath`、`File.getCanonicalPath/getCanonicalFile` 等可唯一解析到已知签名的调用（打净化标记），随后出现 `startsWith(根)` 类前缀校验；或
2. **reject 守卫**：`if (x.contains("..")) throw/return …` 形态——校验失败即中断，守卫之后同一变量按已净化处理（过程内对 if 语句做专门的守卫识别，登记 `prefix_guards` 证据）；
3. **自定义净化工具方法**：方法名匹配宽松命名约定（`safe*/sanitize*/guard*/normalize*/canonical*`）**只是闸门**，引擎还要核验该方法摘要中**同时存在**“已知规范化方法使用”与“前缀/穿越校验守卫”两类证据才确认（`_is_verified_sanitizer`）。只规范化不校验（如 `normalizeOnly`）、只校验不规范化且无 reject 语义的，都不确认——保守不净化。

### 5.2 标记如何随传播保持/弱化

标签带两个布尔位 `sanitized`、`unknown`。合并规则（`DepSet.add`）：
- 同名标签合流时，**净化标记取 AND**（任一路径未净化即未净化）；
- 未知标记取 OR（任一路径不可判定即不可判定）。

### 5.3 无法确定的规范化重载 → 未知，不放行

当 `normalize/canonicalize/...` 的接收者类型无法解析到 `KNOWN_NORMALIZER_RECEIVERS` 中的已知签名（典型：`Object normalizer` 上调用、接口多实现、外部库无源码且呈现 POLY/EXTERNAL），**不猜测、不净化**：
- 过程内登记 `unknown_calls`（reason=`NORMALIZER_OVERLOAD_*`），标签打 `unknown`；
- 该标签到达落点时产出独立规则 **PG-1999（warning，不阻断）** 而非静默放行，也不与确定性漏洞 PG-1001 混同；
- 未知边与未知落点到达分别计数，形成报告中的**未知路径占比**（§11）。

## 6. 过程内摘要：外部词表上的依赖闭包

### 6.1 外部词表（跨方法可连接的稳定符号）

| 标签 | 含义 |
|---|---|
| `arg:i` | 第 i 个形参 |
| `field:f` / `static:C.f` | 实例/静态字段（field-based，跨接收者合并，牺牲对象敏感换可扩展性） |
| `coll:local:v` / `coll:field:f` / `coll:arg:i` | 集合槽：List/Map/Set/数组的元素污点合并存放 |
| `src:KIND` | 直接污点源 |
| `call:k` | 本方法第 k 个调用点返回值伪节点（装载期再绑定被调方闭包） |
| `unk:reason` | 不可判定来源 |

### 6.2 过程内处理要点

- 语句级模拟：局部变量声明、赋值（含字段写、数组/集合下标写）、return、if/for/while/try；
- **分支**：if 的 then/else 环境做并集合并，净化标记自然按 AND 弱化；reject 守卫单独识别；
- **循环**：循环体执行两次模拟一次迭代后的不动点，成本可控；增强 for 把集合槽闭包绑定到元素变量；
- **集合**：`add/put/addAll/putAll` 并入集合槽，`get/iterator/stream/toArray` 从集合槽读出，`toArray` 后再增强 for 的链路可闭合（样本 case45）；
- **getter/setter**：无源码目标时，`getX()→field:x`、`setX(v)→field:x 写` 做桥接；有源码目标则走正常调用解析；
- 每个方法产出 `MethodSummary`：返回闭包、字段/集合写闭包、落点记录（含实参依赖与 unknown 位）、调用点（仅名字+接收者提示+参数个数+实参依赖）、源、规范化/守卫证据。

摘要 JSON 全字段排序、无时间戳、无机器名，本身就是确定性的。

## 7. 三仓库统一工程与调用图

### 7.1 跨仓库怎么连得上

三个仓库目录作为同一逻辑工程一次性装载进一个 `GlobalIndex`：
- 所有类进同一张 `短名 → FQN` 表与 `(文件, 短名) → import FQN` 表；
- 控制层里 `import com.filesvc.common.path.PathUtils` 与工具库中的类声明在该表汇合，`pathUtils.joinUnsafe(...)` 即可解析到 `repo-common` 内的方法 FQN；过滤器插件同理。报告位置用 `repo/相对路径` 保留仓库归属。

### 7.2 调用解析与多态

按三级回退：① 接收者类型提示 → import 解析类 FQN → 继承/接口族（`_hierarchy_names` 传递收集父类与接口）内同名同参数个数方法；② 同类内/静态调用；③ 短名+参数个数族。解析状态分 `UNIQUE / POLY / EXTERNAL / TRUNCATED`。多态不只取一个目标，避免漏报。

### 7.3 调用图边数上界与超界策略（明确口径）

- **每调用点目标数上界 B=16**；调用图边数硬上界 = `调用点数 × B`，指标里同时输出实际边数与上界，断言 `edge_count ≤ edge_upper_bound`；
- **超界策略**：某调用点候选超过 B 时，按目标方法 FQN 字典序确定性截取前 B 个（FQN 含包/类/方法/参数，全局唯一且稳定）；被裁目标不静默丢弃——该调用点置 `TRUNCATED`，在摘要中记为不可判定边并计入未知路径占比。确定性的截取顺序保证双跑一致；
- 过程间另有两道有界闸门：调用串深度 ≤ 8（`CALL_STRING_BOUND`）、单调用点被调目标 ≤ 16，触界即记 `bounded:` 未知边而非无限展开。递归因调用串去重在深度上有界终止。

## 8. 过程间摘要的增量复用，且不产生跨版本漂移

这是题目要求专门说明的机制，由四条设计共同保证。

### 8.1 缓存键与缓存值

- **键** = `分析器版本 | schema 版本 | catalog 版本 | 方法 FQN | 方法体源码哈希`（`cache.py`）。方法体字节不变，键就不变，与提交号、分支、机器、文件修改时间全部无关；
- **值** = “未链接”的 `MethodSummary`：所有调用点的 `targets=[]、resolution=PENDING`，**不含任何跨文件符号事实**（不含被调 FQN、不含其他类的字段类型结论）。

### 8.2 增量复用方式

- 全量扫描：方法体哈希命中即读缓存，未命中才跑过程内分析；20 万行工程里稳态二次扫描几乎只剩“解析 + 装载链接 + 引擎”。
- 增量扫描（CI 传变更清单）：**所有文件仍全部解析、索引仍全量构建**（保证跨文件视图完整），但只有变更文件中的方法重算摘要，其余直接命中；装载期 `link_calls` 对全量方法统一重跑。因此增量成本 ≈ 变更方法的过程内分析 + 全量链接/引擎，实现 <15 秒预算（§10 实测）。

### 8.3 为什么不会跨版本漂移

漂移的典型成因是“缓存值里固化了依赖文件的旧结论，依赖变更后复用了过期事实”。本设计从结构上排除：

1. **跨文件事实不进缓存**。A 调用 B 的解析结果只活在当次扫描的索引里；B 改了签名，A 的缓存摘要照常复用，但装载期链接会按新索引得到新目标——A 不需要失效也能得到正确结论。
2. **缓存值自校验**。读取时复核 `fqn` 与 `body_hash`，不符即弃；文件原子发布（tmp + rename），不存在半截缓存。
3. **版本化命名空间**。分析器/schema/catalog 任一升级，缓存根目录哈希整体更换，新旧结构不可能混用。
4. **方法体哈希是唯一失效信号**。方法自身字节变化 → 键变化 → 必然重算；外部变化 → 不进缓存值 → 链接期自然反映。失效条件因此既是充分的也是必要的，没有“该失效没失效”的窗口。

### 8.4 缓存命中与否不改变结论

同一份方法体，重算与读缓存得到的摘要在 schema 上逐字段同构；之后的链接、字段不动点、传播、序列化完全共用同一条确定性流水线。验证台以“开缓存/关缓存”双模式产出 SARIF 做逐字节比对（§9）。

## 9. 确定性：双跑逐字节一致

- 所有遍历按排序键（FQN、字段名、行号、标签 canon），不使用集合迭代序、墙钟时间、随机数；SARIF 中时间字段固定为纪元值；
- JSON 输出 `sort_keys + 紧凑分隔符 + LF`，路径为仓库内相对 URI（反斜杠归一为 `/`），不写主机名/绝对路径；
- 结果排序键 `(ruleId, repo, file, line, kind)`，fingerprint = 这些稳定字段的 SHA-256；
- 缓存写入也排序并原子替换，缓存目录内容不影响 SARIF 字节。

## 10. CI 集成与“阻断新增”

- 扫描产出 SARIF 与指标 JSON；退出码：存在相对基线新增的 PG-1001 → 1，否则 0；
- 基线模式读取基线 SARIF 的 fingerprint 集合，只阻断**新 fingerprint**；存量问题随基线保留，PG-1999 未知项为 warning 不阻断，推动人工补全类型信息而非卡死流水线；
- 三仓库在 CI 同一 job 中以三个根路径传入；增量模式由平台给变更文件清单（`--changed-list`），缓存目录按仓库挂载复用。

## 11. 未知路径占比口径

报告 `properties.pathGuardMetrics.unknownPaths` 给两个互补比率：

| 指标 | 计算 |
|---|---|
| `unknown_edge_ratio` | 未知边数 / 调用图边总数（未知边含：不可解析外部调用、多态超界裁剪、调用串触界、缺失摘要目标） |
| `unknown_sink_ratio` | 含 unknown 标记的落点到达数 / 全部落点到达数（直接回答“有多少落点结论不可判定”） |

另输出调用图 `call_sites / edge_count / edge_upper_bound / truncated_sites / truncated_edges / over_bound`，超界策略可审计。未知占比持续升高时，CI 指标审查会暴露（例如大量库调用无源码），指导补 stub 或收窄接收者特征。

## 12. 性能预算与支撑手段

| 预算 | 支撑 |
|---|---|
| 全量 20 万行 <180 s | tree-sitter 增量式 C 解析；过程内每方法线性、循环固定两轮；摘要缓存使稳态扫描跳过过程内；字段不动点上限 64 轮、传播闭包单点 128 轮护栏 |
| 增量 <15 s | 全量解析+索引保留完整视图，仅变更方法重算摘要；链接与引擎为图遍历，规模随边数（有上界）线性 |
| 内存 | field-based 不建对象敏感堆；标签为短字符串 intern 化；摘要可换磁盘 KV（当前文件型缓存即其简化实现） |

验证台（`tools/eval_harness.py`）合成确定性的 ~20 万行模板工程（无随机数，类/方法数可复算），测量冷全量、暖全量、单文件增量三段耗时并断言预算。

## 13. 精度验证口径（50 样本）

- `tools/gen_samples.py` 生成 50 个带标签用例（7 个类），覆盖：四类落点 × 三类源 × 跨方法/字段/getter-setter/List/Map/数组 × 净化三范式 × 只规范化/只守卫的反例 × 2 个未知重载用例；
- 统计口径：
  - 召回 = TP /（TP+FN），分母为标注 vulnerable 的用例；
  - 误报率 = FP / 安全用例数（安全用例不含 unknown 用例）；
  - unknown 用例要求命中 PG-1999 且**不得**同时报 PG-1001，单独统计；
- 门槛：召回 ≥0.85、误报率 ≤0.15，未达标则退出码非 0；FN/FP 用例清单写入报告便于回归。

## 14. 模块与产物索引

```
analyzer/
  astutil.py   语法树工具      catalog.py   自研源/落点/净化目录（建模层）
  parser.py    AST→FileUnit    index.py     跨仓索引、调用解析、边数上界
  intra.py     过程内摘要       engine.py    字段不动点+过程间传播+未知计量
  cache.py     内容寻址缓存     sarif.py     确定性 SARIF/基线 fingerprint
  cli.py       扫描编排/CI 出口
fixtures/repos/{repo-controller,repo-common,repo-filter-plugin}  六类文件服务夹具
tools/gen_samples.py   50 条标注样本生成
tools/eval_harness.py  召回/误报/性能/确定性/未知占比一体验证
```

## 15. 已知局限（诚实边界）

1. 类型系统是短名级而非 Java 泛型完整推断，同名类多态靠候选族 + 上界裁剪兜底，极端情况下 PG-1999 比例上升；
2. field-based 不区分对象实例，同名字段的不同对象会合并（可能引入少量过近似，靠净化与守卫证据收敛）；
3. 反射、动态类加载、字符串拼方法名不在静态可判定范围内，按外部未知边计入未知占比；
4. 自定义净化的结构核验基于“规范化调用 + 前缀守卫”证据模式，复杂封装（多层委托净化）需调用串深度内可见，过深时保守不净化并可能落 PG-1001，倾向误报而非漏报。
