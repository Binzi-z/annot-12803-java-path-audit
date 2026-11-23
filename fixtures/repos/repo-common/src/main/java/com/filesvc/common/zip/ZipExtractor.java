package com.filesvc.common.zip;

import com.filesvc.common.path.PathUtils;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** 公共工具库：解压落盘（Zip Slip），条目名是文件内污点源。 */
public class ZipExtractor {

    private final PathUtils pathUtils = new PathUtils();

    /** 危险：ZipEntry.getName() 直接拼落盘路径。 */
    public void unzipVulnerable(ZipFile zip, File destDir) throws Exception {
        var entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            File outFile = pathUtils.joinUnsafe(destDir.getAbsolutePath(), entry.getName());
            try (FileOutputStream fos = new FileOutputStream(outFile)) {
                InputStream is = zip.getInputStream(entry);
                byte[] buf = new byte[4096];
                int n;
                while ((n = is.read(buf)) > 0) {
                    fos.write(buf, 0, n);
                }
            }
        }
    }

    /** 安全：净化工具 + reject 守卫双重保护。 */
    public void extractSafely(ZipFile zip, File destDir) throws Exception {
        var entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            File outFile = pathUtils.safeJoin(destDir.getAbsolutePath(), entry.getName());
            if (entry.getName().contains("..")) {
                throw new SecurityException("zip slip");
            }
            try (FileOutputStream fos = new FileOutputStream(outFile)) {
                fos.write(new byte[0]);
            }
        }
    }
}
