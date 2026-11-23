package com.filesvc.web;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;

/** 控制层：静态目录服务注册 + 模板 include（六个类之一）。 */
public class StaticResourceConfig {

    private final HttpServletRequest request;

    public StaticResourceConfig(HttpServletRequest request) {
        this.request = request;
    }

    /** 漏洞 5：请求参数拼进静态资源目录。 */
    public void registerLocations(ResourceHandlerRegistry registry, String configuredRoot) {
        String sub = request.getParameter("staticSub");
        registry.addResourceLocations(configuredRoot + "/" + sub);
    }

    /** 安全 3：目录参数来自配置且为固定字面量拼接（无外部源）。 */
    public void registerFixedLocations(ResourceHandlerRegistry registry, String configuredRoot) {
        registry.addResourceLocations(configuredRoot + "/public/");
    }

    /** 漏洞 6：模板 include 路径来自请求参数。 */
    public void renderPage(String page) throws Exception {
        RequestDispatcher dispatcher = request.getRequestDispatcher(page);
        dispatcher.include(null, null);
    }

    /** 安全 4：include 白名单守卫。 */
    public void renderPageSafe(String page) throws Exception {
        if (!page.startsWith("/WEB-INF/templates/")) {
            throw new SecurityException("template outside");
        }
        RequestDispatcher dispatcher = request.getRequestDispatcher(page);
        dispatcher.include(null, null);
    }

    public interface ResourceHandlerRegistry {
        void addResourceLocations(String location);
    }
}
