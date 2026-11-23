package com.filesvc.common.path;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

/** 公共工具库：路径拼接与净化（六个类之一，跨仓库被控制层/过滤器调用）。 */
public class PathUtils {

    /** 裸拼接：不规范化、不校验前缀，跨仓库传播链的核心危险方法。 */
    public File joinUnsafe(String baseDir, String sub) {
        return new File(baseDir + File.separator + sub);
    }

    /** 经 Path 构造透传，同样无净化。 */
    public Path resolveUnsafe(String baseDir, String sub) {
        return Paths.get(baseDir).resolve(sub);
    }

    /** 规范化 + 前缀校验：题目认可的净化范式。 */
    public File safeJoin(String baseDir, String sub) {
        File base = new File(baseDir);
        File target = new File(base, sub);
        File canonical = new File(target.getAbsolutePath()).getCanonicalFile();
        if (!canonical.getPath().startsWith(base.getAbsolutePath())) {
            throw new SecurityException("path escapes root: " + sub);
        }
        return canonical;
    }

    /** 名字像净化、但只规范化不做前缀校验：不得算净化。 */
    public File normalizeOnly(String baseDir, String sub) {
        File target = new File(baseDir, sub);
        return target.getAbsoluteFile();
    }

    /** 只做穿越片段包含检查、无规范化：配合 reject 守卫时按净化处理（题目认可守卫语义）。 */
    public String guardOnly(String raw) {
        if (raw.contains("..")) {
            throw new SecurityException("traversal token");
        }
        return raw;
    }

    /** 规范化方法重载不可静态确定：必须标未知。 */
    public String unknownNormalize(String raw, Object normalizer) {
        return normalizer.normalize(raw);
    }
}
