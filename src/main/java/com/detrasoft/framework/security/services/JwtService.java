package com.detrasoft.framework.security.services;

import javax.crypto.SecretKey;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import com.detrasoft.framework.security.model.JwtPayload;
import com.detrasoft.framework.security.model.SessionStatus;
import com.detrasoft.framework.security.model.UserType;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.stream.Collectors;
import java.util.function.Function;
import java.util.UUID;

@Service
public class JwtService {
@Value("${application.security.jwt.secret-key}")
    private String secretKey;

    @Value("${application.security.jwt.access-token-expiration}")
    private long accessTokenExpire;

    @Value("${application.security.jwt.refresh-token-expiration}")
    private long refreshTokenExpire;

    @Value("${application.security.jwt.user-status-control-enabled:true}")
    private boolean userStatusControlEnabled;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public boolean isValid(String token) {
        return !isTokenExpired(token);
    }

    public boolean isValid(String token, JwtPayload user) {
        String username = extractUsername(token);
        if (userStatusControlEnabled) {
            boolean isLogged = ((JwtPayload)user).getStatus() == SessionStatus.LOGGED_IN;
            return (username.equals(user.getUsername())) && !isTokenExpired(token) && isLogged;
        }
        else
            return (username.equals(user.getUsername())) && !isTokenExpired(token);
    }

    public boolean isValidRefreshToken(String token, JwtPayload user) {
        String username = extractUsername(token);

        if (userStatusControlEnabled) {
            boolean isLogged = user.getStatus() == SessionStatus.LOGGED_IN;
            return (username.equals(user.getUsername())) && !isTokenExpired(token) && isLogged;
        }
        else
            return (username.equals(user.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .verifyWith(getSigninKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> extractInfo(String token) {
        Claims claims = (Claims) Jwts
                .parser()
                .verifyWith(getSigninKey())
                .build()
                .parse(token)
                .getPayload();
        
        Map<String, Object> result = new HashMap<>();
        ObjectMapper mapper = new ObjectMapper();
        result = mapper.convertValue(claims, Map.class);
        return result;
    }

    public Map<String, String> generateAccessToken(JwtPayload user, UUID tokenId) {
        List<String> authorities = new ArrayList<String>();

        if (user.getType().equals(UserType.Admin)) {
            authorities.add("ADMIN");
        } else {
            authorities.add("DEFAULT");

            authorities.addAll(
                user.getAuthorities().stream()
                    .map(role -> role.getAuthority())
                    .collect(Collectors.toList())
            );
        }
        if (tokenId == null) {
            tokenId = UUID.randomUUID();
        }
        String token = Jwts
                .builder()
                .subject(user.getUsername())
                .claim("userId", user.getUserId())
                .claim("tokenId", tokenId)
                .claim("firstName", user.getFirstName())
                .claim("lastName", user.getLastName())
                .claim("type", user.getType())
                .claim("detrasoftId", user.getDetrasoftId())
                .claim("urlImg", user.getUrlImg())
                .claim("urlHome", user.getUrlHome())
                .claim("business", user.getBusiness())
                .claim("authorities", authorities)
                .claim("expiresIn", accessTokenExpire)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + (accessTokenExpire * 1000)))
                .signWith(getSigninKey())
                .compact();

        Map<String, String> result = new HashMap<>();
        result.put("token", token);
        result.put("tokenId", tokenId.toString());
        return result;
    }

    public Map<String, String> generateRefreshToken(JwtPayload user, UUID tokenId) {
        String token = Jwts
            .builder()
            .subject(user.getUsername())
            .claim("tokenId", tokenId)
            .claim("expiresIn", refreshTokenExpire)
            .issuedAt(new Date(System.currentTimeMillis()))
            .expiration(new Date(System.currentTimeMillis() + (refreshTokenExpire * 1000)))
            .signWith(getSigninKey())
            .compact();
        Map<String, String> result = new HashMap<>();
        result.put("refreshToken", token);
        result.put("tokenId", tokenId.toString());
        return result;
    }

    private SecretKey getSigninKey() {
        byte[] keyBytes = Decoders.BASE64URL.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    @SuppressWarnings("unchecked")
    public JwtPayload decodeTokenToUserDetails(String token) {
        try {
            Claims claims = extractAllClaims(token);
            String username = claims.getSubject();
            List<String> roles = claims.get("authorities", List.class);
            List<SimpleGrantedAuthority> authorities = new ArrayList<>();
            if (roles != null) {
                authorities = roles.stream()
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
            }

            String userId = claims.get("userId", String.class);
            String firstName = claims.get("firstName", String.class);
            String lastName = claims.get("lastName", String.class);
            String type = claims.get("type", String.class);
            Long detrasoftId = claims.get("detrasoftId", Long.class);
            String urlImg = claims.get("urlImg", String.class);
            String urlHome = claims.get("urlHome", String.class);
            String business = claims.get("business", String.class);

            JwtPayload user = JwtPayload.builder()
                    .userId(userId)
                    .username(username)
                    .authorities(authorities)
                    .firstName(firstName)
                    .lastName(lastName)
                    .detrasoftId(detrasoftId)
                    .type(type)
                    .urlImg(urlImg)
                    .urlHome(urlHome)
                    .business(business)
                    .status(SessionStatus.LOGGED_IN)
                    .build();
    
            return user;

        } catch (Exception e) {
            throw new RuntimeException("Erro ao decodificar o token JWT: " + e.getMessage(), e);
        }
    }
}
