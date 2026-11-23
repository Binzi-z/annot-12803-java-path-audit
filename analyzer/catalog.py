"""自建分析模型：污点源、落点、净化方法、未知重载的目录。

这是分析器自己定义的建模层（不是任何第三方规则集）：只给出“方法名 + 接收者
类型特征 + 所在方法名特征”的匹配规格，具体调用解析由 index 层完成。
"""
from __future__ import annotations

from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# 污点源（三类：请求参数 / 上传文件名 / 配置；另含解压条目名这一文件内来源）
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SourceSpec:
    method: str                 # 方法短名
    kind: str                   # REQUEST / UPLOAD / CONFIG / ZIP_ENTRY
    receiver_tokens: tuple[str, ...] = ()   # 接收者类型名特征（命中其一即可）
    arg_index: int | None = None            # None 表示返回值为源；数字表示该实参被标记


SOURCES: tuple[SourceSpec, ...] = (
    # —— 请求参数 / 请求头 ——
    SourceSpec("getParameter", "REQUEST"),
    SourceSpec("getParameterValues", "REQUEST"),
    SourceSpec("getHeader", "REQUEST"),
    SourceSpec("getQueryString", "REQUEST"),
    # —— 上传文件名（要求接收者类型含 Multipart 特征，避免 getName 误伤）——
    SourceSpec("getSubmittedFileName", "UPLOAD", ("MultipartFile", "multipart")),
    SourceSpec("getName", "UPLOAD", ("MultipartFile", "multipart", "FileItem")),
    SourceSpec("getName", "ZIP_ENTRY", ("ZipEntry", "JarEntry", "ZipFile")),
    # —— 配置 ——
    SourceSpec("getProperty", "CONFIG", ("System", "Properties", "Environment", "Config")),
    SourceSpec("getEnv", "CONFIG", ("System",)),
    SourceSpec("resolveRequiredPlaceholders", "CONFIG"),
    SourceSpec("getString", "CONFIG", ("Config", "Bundle", "Properties")),
)

# 注解形式的配置/注入源：被这些注解标注的参数或字段视为 CONFIG 源
SOURCE_ANNOTATIONS: tuple[str, ...] = ("Value", "ConfigurationProperty")

# ---------------------------------------------------------------------------
# 落点（四类：文件读取拼接 / 解压落盘 / 静态目录服务 / 模板 include）
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SinkSpec:
    method: str                         # 方法短名；"<init>" 表示构造器
    kind: str                           # FILE_READ / UNZIP / STATIC_SERVE / TEMPLATE_INCLUDE
    arg_index: int = 0                  # 污点到达该实参即命中
    receiver_tokens: tuple[str, ...] = ()
    enclosing_method_regex: str = ""    # 仅当所在方法名匹配时才命中（空=不限）


SINKS: tuple[SinkSpec, ...] = (
    # —— 文件读取 / 路径拼接后读取 ——
    SinkSpec("<init>", "FILE_READ", 0, ("FileInputStream", "FileReader", "RandomAccessFile")),
    SinkSpec("readAllBytes", "FILE_READ", 0, ("Files",)),
    SinkSpec("readString", "FILE_READ", 0, ("Files",)),
    SinkSpec("readAllLines", "FILE_READ", 0, ("Files",)),
    SinkSpec("lines", "FILE_READ", 0, ("Files",)),
    SinkSpec("newInputStream", "FILE_READ", 0, ("Files",)),
    SinkSpec("newBufferedReader", "FILE_READ", 0, ("Files",)),
    SinkSpec("exists", "FILE_READ", 0, ("Files",)),          # 目录浏览常见判定
    SinkSpec("isDirectory", "FILE_READ", 0, ("Files",)),
    SinkSpec("list", "FILE_READ", 0, ("Files",)),
    SinkSpec("newDirectoryStream", "FILE_READ", 0, ("Files",)),
    # —— 解压落盘（仅在 unzip/extract/untar 语义方法内命中写盘 API）——
    SinkSpec("<init>", "UNZIP", 0, ("FileOutputStream",), r"(?i).*(unzip|extract|untar|decompress).*"),
    SinkSpec("write", "UNZIP", 0, ("Files",), r"(?i).*(unzip|extract|untar|decompress).*"),
    SinkSpec("copy", "UNZIP", 0, ("Files",), r"(?i).*(unzip|extract|untar|decompress).*"),
    # 通用写盘（非解压语义方法内）：同样是路径穿越危险落点
    SinkSpec("<init>", "FILE_READ", 0, ("FileOutputStream", "FileWriter")),
    SinkSpec("write", "FILE_READ", 0, ("Files",)),
    SinkSpec("copy", "FILE_READ", 0, ("Files",)),
    # —— 静态目录服务 ——
    SinkSpec("addResourceLocations", "STATIC_SERVE", 0,
             ("ResourceHandlerRegistry", "ResourceHttpRequestHandler", "Registry")),
    SinkSpec("setResourceLocations", "STATIC_SERVE", 0, ("ResourceHttpRequestHandler",)),
    SinkSpec("<init>", "STATIC_SERVE", 0, ("FileSystemResource", "ClassPathResource")),
    SinkSpec("readAllBytes", "STATIC_SERVE", 0, ("Files",), r"(?i).*(serve|static|resource|download).*"),
    SinkSpec("newInputStream", "STATIC_SERVE", 0, ("Files",), r"(?i).*(serve|static|resource|download).*"),
    SinkSpec("<init>", "STATIC_SERVE", 0, ("FileInputStream",), r"(?i).*(serve|static|resource|download).*"),
    # —— 模板 include ——
    SinkSpec("getRequestDispatcher", "TEMPLATE_INCLUDE", 0, ("ServletRequest", "HttpServletRequest")),
    SinkSpec("include", "TEMPLATE_INCLUDE", 0, ("RequestDispatcher",)),
    SinkSpec("process", "TEMPLATE_INCLUDE", 0, ("TemplateEngine",)),
    SinkSpec("getTemplate", "TEMPLATE_INCLUDE", 0, ("Configuration", "freemarker")),
)

# 路径构造 API：污点透传（实参污点 -> 返回值污点），本身不算落点
PATH_BUILDERS: tuple[str, ...] = ("get", "of", "resolve", "resolveSibling")
PATH_BUILDER_RECEIVERS: tuple[str, ...] = ("Paths", "Path", "File")
FILE_CONSTRUCTOR = "File"

# ---------------------------------------------------------------------------
# 净化：规范化 + 前缀校验
# ---------------------------------------------------------------------------

# 规范化方法（短名）。若调用无法唯一解析到已知签名，则升级为“未知重载”，不净化。
# 注意：getAbsolutePath/getAbsoluteFile 不做 ../ 消解，不属于规范化，刻意不收。
NORMALIZER_METHODS: tuple[str, ...] = (
    "normalize", "toRealPath", "getCanonicalPath", "getCanonicalFile",
    "canonicalize", "normalizePath",
)
# JDK/已知库中可直接信任的规范化签名（接收者特征 + 方法名）
KNOWN_NORMALIZER_RECEIVERS: dict[str, tuple[str, ...]] = {
    "normalize": ("Path", "Paths", "StringUtils", "FilenameUtils"),
    "toRealPath": ("Path",),
    "getCanonicalPath": ("File",),
    "getCanonicalFile": ("File",),
    "canonicalize": ("FilenameUtils", "Spring", "Resource"),
    "normalizePath": ("StringUtils", "FilenameUtils"),
}

# 前缀校验方法名（出现在条件表达式中时，对真分支内实参做净化）
PREFIX_CHECK_METHODS: tuple[str, ...] = ("startsWith", "checkWithin", "isWithin", "isSafePath", "checkInside", "startsWithSafe")
# 穿越片段检测方法（出现在守卫条件中并配合 throw/return 时，对守卫之后代码净化）
TRAVERSAL_CHECK_METHODS: tuple[str, ...] = ("contains", "indexOf")
TRAVERSAL_TOKENS: tuple[str, ...] = ("..",)

# 自定义“整体净化”工具方法名特征：名字是宽松闸门，真正确认由引擎做结构核验
# （方法体摘要须同时包含“已知规范化方法”与“前缀/穿越校验守卫”两类证据；
#  或存在穿越片段 reject 守卫——与过程内 reject-guard 语义保持一致）
SANITIZER_HELPER_REGEX = r"(?i)^(safe|sanitize|secure|guard|check|normalize|canonical).*$|.*(safe|sanitize|secure|guard).*$"

# 入口类约定：这些类的公开方法参数视为请求绑定源（REQUEST），accessor 方法除外
ENTRY_CLASS_REGEX = r".*(Controller|Filter|Servlet|Resource|Handler|Endpoint|Sample|Big).*"
# 入口方法注解：出现即视为请求绑定入口
ENTRY_METHOD_ANNOTATIONS: tuple[str, ...] = (
    "RequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping",
)

# ---------------------------------------------------------------------------
# 匹配函数
# ---------------------------------------------------------------------------

def _recv_hit(recv_chain: str, tokens: tuple[str, ...]) -> bool:
    if not tokens:
        return True
    return any(t.lower() in recv_chain.lower() for t in tokens)


def match_source(method_name: str, recv_chain: str) -> SourceSpec | None:
    for spec in SOURCES:
        if spec.method == method_name and _recv_hit(recv_chain, spec.receiver_tokens):
            return spec
    return None


def match_sink(method_name: str, recv_chain: str, enclosing: str) -> list[SinkSpec]:
    out = []
    for spec in SINKS:
        if spec.method != method_name:
            continue
        if spec.enclosing_method_regex and not _regex_hit(spec.enclosing_method_regex, enclosing):
            continue
        if _recv_hit(recv_chain, spec.receiver_tokens):
            out.append(spec)
    return out


import re
_REGEX_CACHE: dict[str, re.Pattern] = {}


def _regex_hit(pattern: str, value: str) -> bool:
    p = _REGEX_CACHE.get(pattern)
    if p is None:
        p = re.compile(pattern)
        _REGEX_CACHE[pattern] = p
    return bool(p.match(value))


def is_normalizer_name(name: str) -> bool:
    return name in NORMALIZER_METHODS


def is_known_normalizer(name: str, recv_chain: str) -> bool:
    tokens = KNOWN_NORMALIZER_RECEIVERS.get(name, ())
    return _recv_hit(recv_chain, tokens)


def is_prefix_check(name: str) -> bool:
    return name in PREFIX_CHECK_METHODS
