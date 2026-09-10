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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;

import java.io.IOException;

/**
 * Autentica a requisicao a partir do access token.
 *
 * O parse acontece UMA vez por requisicao (`parseClaims`) e o JwtPayload e o
 * GenericContext derivam dessas mesmas claims. Antes cada campo lido disparava
 * um parse completo com nova verificacao de assinatura -- e o GenericContext era
 * populado a partir de um segundo parse independente, que podia divergir do
 * primeiro.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String ACCESS_TOKEN = "ACCESS_TOKEN";

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
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                authenticate(token, request);
            }
            filterChain.doFilter(request, response);
        } catch (ExpiredJwtException ex) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{ \"error\": \"Token expirado. Por favor, faça login novamente.\" }");
        } catch (io.jsonwebtoken.JwtException | IllegalArgumentException ex) {
            // Token invalido nao autentica -- e nao derruba a cadeia: o mesmo
            // contexto responde 401/403 nos endpoints protegidos. Sem este catch
            // uma assinatura invalida viraria 500, o que confunde diagnostico e
            // expoe a stack trace de parsing na resposta.
            filterChain.doFilter(request, response);
        }
    }

    private void authenticate(String token, HttpServletRequest request) {
        // Um unico parse (e uma unica verificacao de assinatura) por requisicao.
        Claims claims = jwtService.parseClaims(token);

        // Apenas tokens de acesso autenticam. Sem esta checagem um refresh token
        // (7 dias) ou um token de reset de senha valia como credencial de acesso.
        if (!ACCESS_TOKEN.equals(claims.get("tokenType", String.class))) {
            return;
        }

        String username = claims.getSubject();
        if (username == null) {
            return;
        }

        if (!jwtService.issuerAndAudienceValid(claims)) {
            return;
        }

        JwtPayload userDetails = jwtService.toJwtPayload(claims);

        if (!jwtService.isValid(token, userDetails)) {
            return;
        }

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        populateContext(claims);
        SecurityContextHolder.getContext().setAuthentication(authToken);
    }

    /** Popula o GenericContext com as MESMAS claims ja verificadas. */
    private void populateContext(Claims claims) {
        GenericContext.setContexts("userEmail", claims.getSubject());
        GenericContext.setContexts("userId", asString(claims.get("userId")));
        GenericContext.setContexts("tokenId", asString(claims.get("tokenId")));
        GenericContext.setContexts("detrasoftId", asString(claims.get("detrasoftId")));

        String firstName = asString(claims.get("firstName"));
        String lastName = asString(claims.get("lastName"));
        GenericContext.setContexts("firstName", firstName);
        GenericContext.setContexts("lastName", lastName);
        String fullName = firstName == null ? "" : firstName;
        if (lastName != null) {
            fullName = fullName + " " + lastName;
        }
        GenericContext.setContexts("fullName", fullName.isBlank() ? null : fullName);

        GenericContext.setContexts("type", asString(claims.get("type")));
        GenericContext.setContexts("business", asString(claims.get("business")));
        GenericContext.setContexts("software", asString(claims.get("software")));
        GenericContext.setContexts("subscriptionSpeak", asString(claims.get("subscriptionSpeak")));
        GenericContext.setContexts("subscriptionTask", asString(claims.get("subscriptionTask")));
        GenericContext.setContexts("language", asString(claims.get("language")));
        GenericContext.setContexts("timezoneOffset", asString(claims.get("timezoneOffset")));
    }

    private String asString(Object value) {
        return value == null ? null : value.toString();
    }
}
