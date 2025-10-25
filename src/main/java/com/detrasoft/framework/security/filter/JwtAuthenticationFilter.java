package com.detrasoft.framework.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.detrasoft.framework.core.context.GenericContext;
import com.detrasoft.framework.security.model.JwtPayload;
import com.detrasoft.framework.security.services.JwtService;

import io.jsonwebtoken.ExpiredJwtException;

import java.io.IOException;
import java.util.Map;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    public JwtAuthenticationFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);

        try {
            String username = jwtService.extractUsername(token);

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                JwtPayload userDetails = jwtService.decodeTokenToUserDetails(token);

                if (jwtService.isValid(token, userDetails)) {
                        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities()
                    );

                    authToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );

                    Map<String, Object> toke = (Map<String, Object>) jwtService.extractInfo(token);
                    if (toke.get("sub") != null) {
                        GenericContext.setContexts("userEmail", toke.get("sub").toString());
                    }
                    if (toke.get("userId") != null) {
                        GenericContext.setContexts("userId", toke.get("userId").toString());
                    }
                    if (toke.get("tokenId") != null) {
                        GenericContext.setContexts("tokenId", toke.get("tokenId").toString());
                    }
                    if (toke.get("detrasoftId") != null) {
                        GenericContext.setContexts("detrasoftId", toke.get("detrasoftId").toString());
                    }
                    var fullName = "";
                    if (toke.get("firstName") != null) {
                        fullName = toke.get("firstName").toString();
                        GenericContext.setContexts("firstName", toke.get("firstName").toString());
                    }
                    if (toke.get("lastName") != null) {
                        fullName = fullName + " " + toke.get("lastName").toString();
                        GenericContext.setContexts("lastName", toke.get("lastName").toString());
                    }
                    if (fullName != null && !fullName.isBlank()) {
                        GenericContext.setContexts("fullName", fullName);
                    }
                    if (toke.get("type") != null) {
                        GenericContext.setContexts("type", toke.get("type").toString());
                    }
                    if (toke.get("business") != null) {
                        GenericContext.setContexts("business", toke.get("business").toString());
                    }
                    if (toke.get("software") != null) {
                        GenericContext.setContexts("software", toke.get("software").toString());
                    }
                    if (toke.get("subscription") != null) {
                        GenericContext.setContexts("subscription", toke.get("subscription").toString());
                    }
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }

            filterChain.doFilter(request, response);
        } catch (ExpiredJwtException ex) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{ \"error\": \"Token expirado. Por favor, faça login novamente.\" }");
        }
    }
}