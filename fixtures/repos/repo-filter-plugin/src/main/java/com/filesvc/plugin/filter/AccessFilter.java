package com.filesvc.plugin.filter;

import com.filesvc.common.path.PathUtils;
import java.io.File;
import java.io.FileInputStream;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;

/** 过滤器插件仓库：过滤器中的路径拼接（六个类之一），跨仓库调用公共工具库。 */
public class AccessFilter implements Filter {

    private final PathUtils pathUtils = new PathUtils();
    private String root;

    /** 漏洞 7：过滤器里请求参数直接拼接读取，无任何校验。 */
    public void doFilter(HttpServletRequest req, FilterChain chain) throws Exception {
        String path = req.getParameter("path");
        File target = pathUtils.joinUnsafe(root, path);
        try (FileInputStream in = new FileInputStream(target)) {
            in.read();
        }
        chain.doFilter(null, null);
    }

    /** 安全 5：过滤器中先做 reject 守卫再拼接。 */
    public void doFilterSafe(HttpServletRequest req, FilterChain chain) throws Exception {
        String path = req.getParameter("path");
        String guarded = pathUtils.guardOnly(path);
        File target = new File(root, guarded);
        try (FileInputStream in = new FileInputStream(target)) {
            in.read();
        }
        chain.doFilter(null, null);
    }

    /** 漏洞 8：配置源（@Value 注入的根目录被外部覆盖后）与请求参数拼接。 */
    public void doFilterConfig(String overrideRoot, HttpServletRequest req) throws Exception {
        String path = req.getParameter("path");
        File target = new File(overrideRoot, path);
        new FileInputStream(target);
    }

    public interface FilterChain {
        void doFilter(Object a, Object b);
    }
}
