package com.filesvc.web;

import com.filesvc.common.path.PathUtils;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/** 控制层：目录浏览/下载/上传（六个类之一）。 */
public class FileController {

    private final PathUtils pathUtils = new PathUtils();
    private String baseDir;

    public void setBaseDir(String baseDir) {
        this.baseDir = baseDir;
    }

    public String getBaseDir() {
        return this.baseDir;
    }

    /** 漏洞 1：请求参数 -> 跨仓库工具类裸拼接 -> 文件读取。 */
    public FileInputStream download(String requested) throws Exception {
        String name = requested;
        File target = pathUtils.joinUnsafe(getBaseDir(), name);
        return new FileInputStream(target);
    }

    /** 安全 1：同一链路改用 safeJoin（规范化+前缀校验）。 */
    public FileInputStream downloadSafe(String requested) throws Exception {
        File target = pathUtils.safeJoin(getBaseDir(), requested);
        return new FileInputStream(target);
    }

    /** 漏洞 2：目录浏览，Paths.resolve 透传后 newDirectoryStream。 */
    public void browse(String sub) throws Exception {
        Path root = Paths.get(getBaseDir());
        Path dir = root.resolve(sub);
        Files.newDirectoryStream(dir);
    }

    /** 漏洞 3：上传文件名（UPLOAD 源）落盘。 */
    public void saveUpload(MultipartFile file) throws Exception {
        String submitted = file.getSubmittedFileName();
        File target = pathUtils.joinUnsafe(getBaseDir(), submitted);
        try (FileInputStream ignore = new FileInputStream(target)) {
            // 读取上传目标以触发同型落点
        }
    }

    /** 漏洞 4：集合传播——getParameterValues 入 List，增强 for 中逐个读取。 */
    public void downloadBatch(HttpServletRequest req) throws Exception {
        String[] names = req.getParameterValues("names");
        List<String> pending = new ArrayList<>();
        for (String n : names) {
            pending.add(n);
        }
        for (String one : pending) {
            File target = new File(getBaseDir(), one);
            new FileInputStream(target);
        }
    }

    /** 安全 2：reject 守卫（contains("..") -> throw）后再用。 */
    public FileInputStream downloadGuarded(String requested) throws Exception {
        if (requested.contains("..")) {
            throw new SecurityException("traversal");
        }
        File target = new File(getBaseDir(), requested);
        return new FileInputStream(target);
    }

    /** 未知：规范化重载无法静态确定，须报 PG-1999 而非静默放行。 */
    public FileInputStream downloadUnknown(String requested, Object normalizer) throws Exception {
        String normalized = pathUtils.unknownNormalize(requested, normalizer);
        File target = new File(getBaseDir(), normalized);
        return new FileInputStream(target);
    }

    /** 接口桩：框架类型无源码，靠目录中的接收者特征识别。 */
    public interface MultipartFile {
        String getSubmittedFileName();
    }

    public interface HttpServletRequest {
        String getParameter(String key);
        String[] getParameterValues(String key);
    }
}
