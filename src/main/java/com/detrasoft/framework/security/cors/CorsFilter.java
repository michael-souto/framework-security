package com.detrasoft.framework.security.cors;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorsFilter implements Filter {

    @Value("${authorization.enable-origin-control}")
    private Boolean enableOriginControl;

    @Value("${cors.allowed.origin:*}")
    private String allowedOrigin;

    @Value("${authorization.security-https:true}")
    private Boolean securityHttps;

    @Override
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
            throws IOException, ServletException {

        if (enableOriginControl) {
            String protocol = securityHttps ? "https://" : "http://";
            var origins = Arrays.stream(allowedOrigin.split(";")).map(x -> x = protocol + x).toList();
            HttpServletRequest request = (HttpServletRequest) req;
            HttpServletResponse response = (HttpServletResponse) resp;

            String AccessControlAllowOrigin = allowedOrigin.equals("*")
                    ? "*"
                    : (request.getHeader("Origin") != null && origins.lastIndexOf(request.getHeader("Origin")) >= 0
                    ? origins.get(origins.lastIndexOf(request.getHeader("Origin")))
                    : null);

            response.setHeader("Access-Control-Allow-Origin", AccessControlAllowOrigin);
            response.setHeader("Access-Control-Allow-Credentials", "true");
            addSameSiteAttribute(response);

            if ("OPTIONS".equals(request.getMethod())
                    && (origins.lastIndexOf(request.getHeader("Origin")) >= 0
                    || allowedOrigin.equals("*"))) {
                response.setHeader("Access-Control-Allow-Methods", "POST, GET, DELETE, PUT, PATCH, OPTIONS");
                response.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept");
                response.setHeader("Access-Control-Max-Age", "3600");

                response.setStatus(HttpServletResponse.SC_OK);
            } else {
                chain.doFilter(req, resp);
            }
        } else {
            chain.doFilter(req, resp);
        }
    }

    @Override
    public void destroy() {
    }

    @Override
    public void init(FilterConfig arg0) throws ServletException {
    }

    private void addSameSiteAttribute(HttpServletResponse response) {
        Collection<String> headers = response.getHeaders("Set-Cookie");
        boolean firstHeader = true;
        for (String header : headers) {
            if (firstHeader) {
                response.setHeader("Set-Cookie", String.format("%s; %s", header, "SameSite=None"));
                firstHeader = false;
                continue;
            }
            response.addHeader("Set-Cookie", String.format("%s; %s", header, "SameSite=None"));
        }
    }

}
