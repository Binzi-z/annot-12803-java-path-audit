"""生成 50 条带标签的 Java 样本（每条一个独立方法，方法名生成时统一编号）。

标签约定写在样本清单 labels.json：
  vulnerable=true  期望命中 PG-1001（召回口径）
  vulnerable=false 期望不产生 error（误报口径）
  unknown=true     期望命中 PG-1999（未知规范化重载，不计入上述两类）
覆盖维度：四类落点 × 三类源 × 跨类/跨包/getter-setter/集合 × 净化/守卫/未知。
"""
from __future__ import annotations

import json
import os

HEADER = """package com.sample.gen;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;

public class Sample{n} {{
{fields}
{methods}
{interfaces}
}}
"""

IFACES = """
    public interface MultipartFile { String getSubmittedFileName(); }
    public interface Registry { void addResourceLocations(String s); }
    public interface Normalizer { String normalize(String s); }
"""

# (方法体模板, 期望标签)。方法名统一写 caseXX，生成时按序替换为 case01..case50。
TEMPLATES: list[tuple[str, dict]] = []


def t(body: str, expect: dict):
    TEMPLATES.append((body, expect))


# ---------------- 1-10：FILE_READ × REQUEST，含净化/守卫/集合/跨方法 ----------------
t("""    public void caseXX(String requested) throws Exception {
        File target = new File(base, requested);
        new FileInputStream(target);
    }""", {"vulnerable": True, "sink": "FILE_READ", "source": "REQUEST"})

t("""    public void caseXX(String requested) throws Exception {
        Path target = Paths.get(base).resolve(requested);
        Files.readAllBytes(target);
    }""", {"vulnerable": True, "sink": "FILE_READ", "source": "REQUEST"})

t("""    public void caseXX(String requested) throws Exception {
        File target = new File(base, requested);
        File canon = target.getCanonicalFile();
        if (!canon.getPath().startsWith(base)) { throw new SecurityException("x"); }
        new FileInputStream(canon);
    }""", {"vulnerable": False, "sink": "FILE_READ", "source": "REQUEST"})

t("""    public void caseXX(String requested) throws Exception {
        if (requested.contains("..")) { throw new SecurityException("x"); }
        File target = new File(base, requested);
        new FileInputStream(target);
    }""", {"vulnerable": False, "sink": "FILE_READ", "source": "REQUEST"})

t("""    public void caseXX(HttpServletRequest r) throws Exception {
        String[] names = r.getParameterValues("n");
        List<String> pending = new ArrayList<>();
        for (String n : names) { pending.add(n); }
        for (String one : pending) { new FileInputStream(new File(base, one)); }
    }""", {"vulnerable": True, "sink": "FILE_READ", "source": "REQUEST"})

t("""    public void caseXX(HttpServletRequest r) throws Exception {
        String name = r.getParameter("name");
        this.file = name;
    }
    public void caseXXRead() throws Exception {
        new FileInputStream(new File(base, this.file));
    }""", {"vulnerable": True, "sink": "FILE_READ", "source": "REQUEST"})

t("""    public void caseXX(HttpServletRequest r) throws Exception {
        String name = r.getParameter("name");
        setFile(name);
        new FileInputStream(new File(base, getFile()));
    }""", {"vulnerable": True, "sink": "FILE_READ", "source": "REQUEST"})

t("""    public void caseXX(String requested) throws Exception {
        Path p = Paths.get(base, requested).normalize();
        if (!p.startsWith(Paths.get(base))) { throw new SecurityException("x"); }
        Files.newInputStream(p);
    }""", {"vulnerable": False, "sink": "FILE_READ", "source": "REQUEST"})

t("""    public void caseXX(HttpServletRequest r) throws Exception {
        Map<String, String> m = new HashMap<>();
        m.put("k", r.getParameter("name"));
        String v = m.get("k");
        new FileInputStream(new File(base, v));
    }""", {"vulnerable": True, "sink": "FILE_READ", "source": "REQUEST"})

t("""    public void caseXX(String requested) throws Exception {
        File target = new File(base, requested);
        target.getAbsoluteFile();
        new FileInputStream(target);
    }""", {"vulnerable": True, "sink": "FILE_READ", "source": "REQUEST"})

# ---------------- 11-18：UNZIP × ZIP_ENTRY ----------------
t("""    public void caseXX(ZipFile zip) throws Exception {
        var it = zip.entries();
        while (it.hasMoreElements()) {
            ZipEntry e = it.nextElement();
            File out = new File(base, e.getName());
            new FileOutputStream(out);
        }
    }""", {"vulnerable": True, "sink": "UNZIP", "source": "ZIP_ENTRY"})

t("""    public void caseXX(ZipFile zip) throws Exception {
        var it = zip.entries();
        while (it.hasMoreElements()) {
            ZipEntry e = it.nextElement();
            if (e.getName().contains("..")) { throw new SecurityException("x"); }
            File out = new File(base, e.getName());
            new FileOutputStream(out);
        }
    }""", {"vulnerable": False, "sink": "UNZIP", "source": "ZIP_ENTRY"})

t("""    public void caseXX(ZipFile zip) throws Exception {
        var it = zip.entries();
        while (it.hasMoreElements()) {
            ZipEntry e = it.nextElement();
            File out = new File(base, e.getName());
            File canon = out.getCanonicalFile();
            if (!canon.getPath().startsWith(base)) { throw new SecurityException("x"); }
            new FileOutputStream(canon);
        }
    }""", {"vulnerable": False, "sink": "UNZIP", "source": "ZIP_ENTRY"})

t("""    public void caseXX(ZipFile zip) throws Exception {
        List<String> names = new ArrayList<>();
        var it = zip.entries();
        while (it.hasMoreElements()) {
            ZipEntry e = it.nextElement();
            names.add(e.getName());
        }
        for (String n : names) { Files.write(Paths.get(base).resolve(n), new byte[0]); }
    }""", {"vulnerable": True, "sink": "UNZIP", "source": "ZIP_ENTRY"})

t("""    public void caseXX(ZipFile zip) throws Exception {
        var it = zip.entries();
        while (it.hasMoreElements()) {
            ZipEntry e = it.nextElement();
            String safe = safeEntry(e.getName());
            new FileOutputStream(new File(base, safe));
        }
    }
    private String safeEntry(String raw) {
        File f = new File(base, raw);
        File c = f.getCanonicalFile();
        if (!c.getPath().startsWith(base)) { throw new SecurityException("x"); }
        return c.getPath();
    }""", {"vulnerable": False, "sink": "UNZIP", "source": "ZIP_ENTRY"})

t("""    public void caseXX(ZipFile zip) throws Exception {
        var it = zip.entries();
        while (it.hasMoreElements()) {
            ZipEntry e = it.nextElement();
            List<String> bucket = new ArrayList<>();
            bucket.add(e.getName());
            for (String n : bucket) { new FileOutputStream(new File(base, n)); }
        }
    }""", {"vulnerable": True, "sink": "UNZIP", "source": "ZIP_ENTRY"})

t("""    public void caseXX(ZipFile zip) throws Exception {
        var it = zip.entries();
        while (it.hasMoreElements()) {
            ZipEntry e = it.nextElement();
            File out = Paths.get(base).resolve(e.getName()).toFile();
            new FileOutputStream(out);
        }
    }""", {"vulnerable": True, "sink": "UNZIP", "source": "ZIP_ENTRY"})

t("""    public void caseXX(ZipFile zip) throws Exception {
        var it = zip.entries();
        while (it.hasMoreElements()) {
            ZipEntry e = it.nextElement();
            if (e.getName().contains("..")) { throw new SecurityException("x"); }
            Files.write(Paths.get(base).resolve(e.getName()), new byte[0]);
        }
    }""", {"vulnerable": False, "sink": "UNZIP", "source": "ZIP_ENTRY"})

# ---------------- 19-26：STATIC_SERVE / 通用文件服务 ----------------
t("""    public void caseXX(HttpServletRequest r, Registry reg) {
        reg.addResourceLocations(base + "/" + r.getParameter("sub"));
    }""", {"vulnerable": True, "sink": "STATIC_SERVE", "source": "REQUEST"})

t("""    public void caseXX(Registry reg) {
        reg.addResourceLocations(base + "/public/");
    }""", {"vulnerable": False, "sink": "STATIC_SERVE", "source": "LITERAL"})

t("""    public void caseXX(HttpServletRequest r) throws Exception {
        String sub = r.getParameter("sub");
        File f = new File(base, sub);
        Files.readAllBytes(f.toPath());
    }""", {"vulnerable": True, "sink": "FILE_READ", "source": "REQUEST"})

t("""    public void caseXX(String requested) throws Exception {
        String safe = safePath(requested);
        new FileInputStream(new File(base, safe));
    }
    private String safePath(String raw) {
        File f = new File(base, raw);
        File c = f.getCanonicalFile();
        if (!c.getPath().startsWith(base)) { throw new SecurityException("x"); }
        return c.getPath();
    }""", {"vulnerable": False, "sink": "FILE_READ", "source": "REQUEST"})

t("""    public void caseXX(String requested) throws Exception {
        String only = normalizeOnlyPath(requested);
        new FileInputStream(new File(base, only));
    }
    private String normalizeOnlyPath(String raw) {
        return new File(base, raw).getAbsolutePath();
    }""", {"vulnerable": True, "sink": "FILE_READ", "source": "REQUEST"})

t("""    public void caseXX(HttpServletRequest r, Registry reg) {
        String sub = r.getHeader("X-Static");
        reg.addResourceLocations(base + "/" + sub);
    }""", {"vulnerable": True, "sink": "STATIC_SERVE", "source": "REQUEST"})

t("""    public void caseXX(Registry reg, String fixed) {
        reg.addResourceLocations(fixed);
    }""", {"vulnerable": True, "sink": "STATIC_SERVE", "source": "CONFIG"})

t("""    public void caseXX(HttpServletRequest r) throws Exception {
        String sub = r.getParameter("sub");
        if (sub.contains("..")) { throw new SecurityException("x"); }
        Registry reg = null;
        reg.addResourceLocations(base + "/" + sub);
    }""", {"vulnerable": False, "sink": "STATIC_SERVE", "source": "REQUEST"})

# ---------------- 27-34：TEMPLATE_INCLUDE ----------------
t("""    public void caseXX(HttpServletRequest r) throws Exception {
        String page = r.getParameter("page");
        RequestDispatcher d = r.getRequestDispatcher(page);
        d.include(null, null);
    }""", {"vulnerable": True, "sink": "TEMPLATE_INCLUDE", "source": "REQUEST"})

t("""    public void caseXX(String page) throws Exception {
        if (!page.startsWith("/WEB-INF/tpl/")) { throw new SecurityException("x"); }
        RequestDispatcher d = req.getRequestDispatcher(page);
        d.include(null, null);
    }""", {"vulnerable": False, "sink": "TEMPLATE_INCLUDE", "source": "REQUEST"})

t("""    public void caseXX(HttpServletRequest r) throws Exception {
        String page = r.getParameter("page");
        req.getRequestDispatcher(page).include(null, null);
    }""", {"vulnerable": True, "sink": "TEMPLATE_INCLUDE", "source": "REQUEST"})

t("""    public void caseXX(HttpServletRequest r) throws Exception {
        String page = r.getHeader("X-Page");
        RequestDispatcher d = r.getRequestDispatcher(page);
        d.include(null, null);
    }""", {"vulnerable": True, "sink": "TEMPLATE_INCLUDE", "source": "REQUEST"})

t("""    public void caseXX(String page) throws Exception {
        RequestDispatcher d = req.getRequestDispatcher(page + ".jsp");
        d.include(null, null);
    }""", {"vulnerable": True, "sink": "TEMPLATE_INCLUDE", "source": "REQUEST"})

t("""    public void caseXX(HttpServletRequest r) throws Exception {
        String page = r.getParameter("page");
        String guarded = guardPage(page);
        req.getRequestDispatcher(guarded).include(null, null);
    }
    private String guardPage(String raw) {
        if (raw.contains("..")) { throw new SecurityException("x"); }
        return raw;
    }""", {"vulnerable": False, "sink": "TEMPLATE_INCLUDE", "source": "REQUEST"})

t("""    public void caseXX(HttpServletRequest r) throws Exception {
        String[] pages = r.getParameterValues("pages");
        for (String page : pages) {
            req.getRequestDispatcher(page).include(null, null);
        }
    }""", {"vulnerable": True, "sink": "TEMPLATE_INCLUDE", "source": "REQUEST"})

t("""    public void caseXX(String page) throws Exception {
        if (page.contains("..")) { return; }
        req.getRequestDispatcher(page).include(null, null);
    }""", {"vulnerable": False, "sink": "TEMPLATE_INCLUDE", "source": "REQUEST"})

# ---------------- 35-42：UPLOAD / CONFIG 源 ----------------
t("""    public void caseXX(MultipartFile mf) throws Exception {
        String name = mf.getSubmittedFileName();
        new FileInputStream(new File(base, name));
    }""", {"vulnerable": True, "sink": "FILE_READ", "source": "UPLOAD"})

t("""    public void caseXX(MultipartFile mf) throws Exception {
        String name = mf.getSubmittedFileName();
        if (name.contains("..")) { throw new SecurityException("x"); }
        new FileInputStream(new File(base, name));
    }""", {"vulnerable": False, "sink": "FILE_READ", "source": "UPLOAD"})

t("""    public void caseXX() throws Exception {
        String sub = props.getProperty("subpath");
        new FileInputStream(new File(base, sub));
    }""", {"vulnerable": True, "sink": "FILE_READ", "source": "CONFIG"})

t("""    public void caseXX() throws Exception {
        String fixed = "/var/data/public";
        new FileInputStream(new File(fixed, "readme.txt"));
    }""", {"vulnerable": False, "sink": "FILE_READ", "source": "LITERAL"})

t("""    public void caseXX(String cfg) throws Exception {
        new FileInputStream(new File(cfg, "x"));
    }""", {"vulnerable": True, "sink": "FILE_READ", "source": "CONFIG"})

t("""    public void caseXX(MultipartFile mf) throws Exception {
        List<String> names = new ArrayList<>();
        names.add(mf.getSubmittedFileName());
        for (String n : names) { new FileOutputStream(new File(base, n)); }
    }""", {"vulnerable": True, "sink": "FILE_READ", "source": "UPLOAD"})

t("""    public void caseXX(MultipartFile mf) throws Exception {
        String name = mf.getSubmittedFileName();
        File c = new File(base, name).getCanonicalFile();
        if (!c.getPath().startsWith(base)) { throw new SecurityException("x"); }
        new FileInputStream(c);
    }""", {"vulnerable": False, "sink": "FILE_READ", "source": "UPLOAD"})

t("""    public void caseXX() throws Exception {
        String sub = System.getenv("DATA_SUB");
        new FileInputStream(new File(base, sub));
    }""", {"vulnerable": True, "sink": "FILE_READ", "source": "CONFIG"})

# ---------------- 43-50：未知重载 / 边界 / 净化变体 ----------------
t("""    public void caseXX(String requested, Normalizer n) throws Exception {
        String s = n.normalize(requested);
        new FileInputStream(new File(base, s));
    }""", {"vulnerable": False, "unknown": True, "sink": "FILE_READ", "source": "REQUEST"})

t("""    public void caseXX(String requested) throws Exception {
        Path p = Paths.get(base, requested).toRealPath();
        if (!p.startsWith(Paths.get(base))) { throw new SecurityException("x"); }
        Files.readAllBytes(p);
    }""", {"vulnerable": False, "sink": "FILE_READ", "source": "REQUEST"})

t("""    public void caseXX(HttpServletRequest r) throws Exception {
        String name = r.getParameter("name");
        List<String> all = new ArrayList<>();
        all.add(name);
        String[] arr = all.toArray(new String[0]);
        for (String a : arr) { new FileInputStream(new File(base, a)); }
    }""", {"vulnerable": True, "sink": "FILE_READ", "source": "REQUEST"})

t("""    public void caseXX(String requested) throws Exception {
        if (!requested.startsWith(base)) { throw new SecurityException("x"); }
        new FileInputStream(new File(requested));
    }""", {"vulnerable": False, "sink": "FILE_READ", "source": "REQUEST"})

t("""    public void caseXX(HttpServletRequest r) throws Exception {
        String a = r.getParameter("a");
        String b = r.getParameter("b");
        String combo = a + "/" + b;
        new FileInputStream(new File(base, combo));
    }""", {"vulnerable": True, "sink": "FILE_READ", "source": "REQUEST"})

t("""    public void caseXX(String requested) throws Exception {
        File f = new File(base, requested);
        if (Files.isDirectory(f.toPath())) {
            Files.newDirectoryStream(f.toPath());
        }
    }""", {"vulnerable": True, "sink": "FILE_READ", "source": "REQUEST"})

t("""    public void caseXX(HttpServletRequest r) throws Exception {
        String name = r.getHeader("X-File");
        new FileInputStream(new File(base, name));
    }""", {"vulnerable": True, "sink": "FILE_READ", "source": "REQUEST"})

t("""    public void caseXX(String requested, Normalizer n) throws Exception {
        String s = n.normalize(requested);
        if (s.contains("..")) { throw new SecurityException("x"); }
        new FileInputStream(new File(base, s));
    }""", {"vulnerable": False, "unknown": True, "sink": "FILE_READ", "source": "REQUEST"})


FIELDS = """    private String base = "/var/data";
    private String file;
    private HttpServletRequest req;
    private Properties props = new Properties();
    public void setFile(String f) { this.file = f; }
    public String getFile() { return this.file; }
"""


def generate(out_dir: str) -> dict:
    assert len(TEMPLATES) == 50, f"expected 50 samples, got {len(TEMPLATES)}"
    os.makedirs(out_dir, exist_ok=True)
    labels = []
    per_class = 8
    chunks = [TEMPLATES[i:i + per_class] for i in range(0, len(TEMPLATES), per_class)]
    case_idx = 0
    for ci, chunk in enumerate(chunks, start=1):
        methods = []
        for body, expect in chunk:
            case_idx += 1
            cid = f"case{case_idx:02d}"
            # 主方法名替换；配套 Read 方法名保持唯一后缀
            renamed = body.replace("caseXXRead", f"{cid}Read").replace("caseXX", cid)
            methods.append(renamed)
            labels.append({"id": cid, "class": f"Sample{ci}", **expect})
        src = HEADER.format(n=ci, fields=FIELDS, methods="\n".join(methods), interfaces=IFACES)
        with open(os.path.join(out_dir, f"Sample{ci}.java"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(src)
    with open(os.path.join(out_dir, "labels.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(labels, fh, ensure_ascii=False, sort_keys=True, indent=2)
    return {"samples": len(labels),
            "vulnerable": sum(1 for x in labels if x.get("vulnerable")),
            "safe": sum(1 for x in labels if not x.get("vulnerable") and not x.get("unknown")),
            "unknown": sum(1 for x in labels if x.get("unknown"))}


if __name__ == "__main__":
    import sys
    stats = generate(sys.argv[1] if len(sys.argv) > 1 else "fixtures/samples")
    print(json.dumps(stats, sort_keys=True))
