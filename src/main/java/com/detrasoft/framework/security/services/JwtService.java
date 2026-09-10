package com.detrasoft.framework.security.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import com.detrasoft.framework.security.dtos.UserConfigDTO;
import com.detrasoft.framework.security.dtos.UserFavoriteDTO;
import com.detrasoft.framework.security.model.JwtPayload;
import com.detrasoft.framework.security.model.SessionStatus;
import com.detrasoft.framework.security.model.UserType;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Validacao de JWT nos microsservicos consumidores.
 *
 * A verificacao e ASSIMETRICA e NAO TEM FALLBACK. A chave publica RSA do
 * authorization-server vem por configuracao (application.security.jwt.rsa.
 * public-key-pem) e e resolvida em memoria por `kid`, sem I/O no caminho da
 * requisicao. O algoritmo e escolhido pela CONFIGURACAO, nunca pelo header do
 * token -- e isso que fecha o ataque de confusao de algoritmo (assinar HS256
 * usando a chave publica como segredo HMAC).
 *
 * A chave simetrica compartilhada foi REMOVIDA de proposito. Enquanto ela
 * existisse em cada servico, quem a lesse forjava tokens de QUALQUER usuario sem
 * precisar roubar token algum: era uma credencial de emissao distribuida por
 * configuracao, e nenhuma outra defesa compensa isso. Tambem saiu o fallback
 * HS256 da janela de migracao: manter dois caminhos de verificacao aceitos
 * significa que o mais fraco define a forca do conjunto.
 *
 * Nota de performance: um unico parse (e uma unica verificacao de assinatura)
 * por requisicao. `parseClaims` devolve as claims e JwtPayload/GenericContext
 * derivam delas, em vez de reparsear o token a cada campo lido.
 */
@Service
public class JwtService {

    @Value("${application.security.jwt.access-token-expiration}")
    private long accessTokenExpire;

    @Value("${application.security.jwt.refresh-token-expiration}")
    private long refreshTokenExpire;

    @Value("${application.security.jwt.user-status-control-enabled:false}")
    private boolean userStatusControlEnabled;

    /** Chave publica RSA (PEM) do authorization-server. Obrigatoria. */
    @Value("${application.security.jwt.rsa.public-key-pem:}")
    private String rsaPublicKeyPem;

    @Value("${application.security.jwt.rsa.key-id:detrasoft-default}")
    private String rsaKeyId;

    /** Chave publica da proxima chave (rotacao). Opcional. */
    @Value("${application.security.jwt.rsa.next-public-key-pem:}")
    private String nextPublicKeyPem;

    @Value("${application.security.jwt.rsa.next-key-id:}")
    private String nextKeyId;

    /**
     * Chave privada RSA, usada SOMENTE pelos metodos generate*. Os servicos
     * consumidores nao a configuram: quem emite tokens e o authorization-server.
     * Sem ela, qualquer chamada a generate* falha com mensagem explicita em vez
     * de produzir um token que ninguem consegue verificar.
     */
    @Value("${application.security.jwt.rsa.private-key-pem:}")
    private String rsaPrivateKeyPem;

    /**
     * `iss` esperado. O emissor e um identificador LOGICO, nao o host fisico: o
     * mesmo authorization-server e alcancado por security.speakfy.app,
     * security.dutfy.app etc., e o valor precisa ser identico nos dois lados.
     */
    @Value("${application.security.jwt.issuer:}")
    private String expectedIssuer;

    /** Audiencias aceitas. Vazio = nao validar `aud`. */
    @Value("${application.security.jwt.expected-audiences:}")
    private String expectedAudiences;

    /** kid -> chave publica. Cache O(1), alimentado uma vez por configuracao. */
    private final Map<String, PublicKey> publicKeys = new ConcurrentHashMap<>();
    private volatile boolean keysInitialized;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public boolean isValid(String token) {
        return !isTokenExpired(token);
    }

    public boolean isValid(String token, JwtPayload user) {
        String username = extractUsername(token);
        if (userStatusControlEnabled) {
            boolean isLogged = ((JwtPayload) user).getStatus() == SessionStatus.LOGGED_IN;
            return (username.equals(user.getUsername())) && !isTokenExpired(token) && isLogged;
        }
        return (username.equals(user.getUsername())) && !isTokenExpired(token);
    }

    /**
     * Valida um refresh token. Exige o claim `tokenType == REFRESH_TOKEN`: sem
     * isso um access token (ou um token de reset de senha) seria aceito como
     * refresh.
     */
    public boolean isValidRefreshToken(String token, JwtPayload user) {
        String username = extractUsername(token);
        if (!"REFRESH_TOKEN".equals(extractTokenType(token))) {
            return false;
        }

        if (userStatusControlEnabled) {
            boolean isLogged = user.getStatus() == SessionStatus.LOGGED_IN;
            return (username.equals(user.getUsername())) && !isTokenExpired(token) && isLogged;
        }
        return (username.equals(user.getUsername())) && !isTokenExpired(token);
    }

    /** Valida um token de definicao de senha (`tokenType == NEW_PASSWORD`). */
    public boolean isValidNewPasswordToken(String token) {
        return "NEW_PASSWORD".equals(extractTokenType(token)) && !isTokenExpired(token);
    }

    /** Valida um token de codigo de verificacao (`tokenType == VALIDATION_CODE`). */
    public boolean isValidValidationCodeToken(String token) {
        return "VALIDATION_CODE".equals(extractTokenType(token)) && !isTokenExpired(token);
    }

    public String extractTokenType(String token) {
        return extractClaim(token, c -> c.get("tokenType", String.class));
    }

    /** Unico parse da requisicao: derive tudo a partir das Claims retornadas. */
    public Claims parseClaims(String token) {
        return extractAllClaims(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        return resolver.apply(extractAllClaims(token));
    }

    private Claims extractAllClaims(String token) {
        return parserFor(peekKeyId(token)).build().parseSignedClaims(token).getPayload();
    }

    /**
     * Monta o parser pelo `kid` do header. O algoritmo vem da CONFIGURACAO, nao
     * do header: aceitar o algoritmo que o token declara e exatamente o que
     * permite assinar HS256 usando a chave publica como segredo HMAC.
     */
    private io.jsonwebtoken.JwtParserBuilder parserFor(String kid) {
        initKeys();
        if (kid == null) {
            throw new JwtException("Token sem kid: a verificacao assimetrica exige o kid no header");
        }
        PublicKey key = publicKeys.get(kid);
        if (key == null) {
            throw new JwtException("kid desconhecido: " + kid);
        }
        return Jwts.parser().verifyWith(key);
    }

    /** Carrega as chaves publicas uma unica vez, de forma preguicosa e thread-safe. */
    private void initKeys() {
        if (keysInitialized) {
            return;
        }
        synchronized (this) {
            if (keysInitialized) {
                return;
            }
            if (rsaPublicKeyPem == null || rsaPublicKeyPem.isBlank()) {
                throw new IllegalStateException("application.security.jwt.rsa.public-key-pem nao configurada: "
                        + "sem a chave publica do authorization-server nenhum token pode ser verificado");
            }
            try {
                publicKeys.put(rsaKeyId, parsePublicKey(rsaPublicKeyPem));
                if (nextPublicKeyPem != null && !nextPublicKeyPem.isBlank()
                        && nextKeyId != null && !nextKeyId.isBlank()) {
                    publicKeys.put(nextKeyId, parsePublicKey(nextPublicKeyPem));
                }
            } catch (Exception e) {
                throw new IllegalStateException(
                        "Falha ao carregar application.security.jwt.rsa.public-key-pem", e);
            }
            keysInitialized = true;
        }
    }

    /**
     * Le o `kid` do header sem verificar a assinatura. O conteudo e tratado como
     * corpo NAO confiavel: ele so escolhe qual chave usar, e o parse seguinte
     * falha se a assinatura nao conferir com ela.
     */
    private String peekKeyId(String token) {
        try {
            int firstDot = token.indexOf('.');
            if (firstDot <= 0) {
                return null;
            }
            byte[] header = Decoders.BASE64URL.decode(token.substring(0, firstDot));
            Map<?, ?> json = new ObjectMapper().readValue(new ByteArrayInputStream(header), Map.class);
            Object kid = json.get("kid");
            return kid == null ? null : kid.toString();
        } catch (Exception e) {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> extractInfo(String token) {
        return new ObjectMapper().convertValue(extractAllClaims(token), Map.class);
    }

    /**
     * Serializa as configuracoes do usuario como mapa chave/valor.
     *
     * A guarda de nulo e obrigatoria, nao defensiva: quem monta este objeto a
     * partir de uma entidade que nao carregou os relacionamentos passa `null`, e
     * `null.stream()` derrubava a EMISSAO DO TOKEN inteira -- ou seja, o login.
     *
     * Mapa, e nao lista de DTO, de proposito: este claim e consumido, nao
     * reidratado. Uma lista de DTO obriga o token a carregar `id`, `name` e
     * `value` por config so para dizer o que um par chave/valor ja diz.
     */
    private Map<String, String> toConfigMap(List<UserConfigDTO> configs) {
        if (configs == null) {
            return null;
        }
        return configs.stream()
                .filter(c -> c != null && c.getName() != null)
                .collect(Collectors.toMap(
                        UserConfigDTO::getName,
                        c -> c.getValue() == null ? "" : c.getValue(),
                        (a, b) -> b));
    }

    /** Serializa os favoritos como lista de mapas, pelo mesmo motivo do configs. */
    private List<Map<String, Object>> toFavoriteList(List<UserFavoriteDTO> favorites) {
        if (favorites == null) {
            return null;
        }
        return favorites.stream()
                .filter(f -> f != null)
                .map(f -> {
                    Map<String, Object> item = new HashMap<>();
                    item.put("name", f.getName());
                    item.put("url", f.getUrl());
                    item.put("route", f.getRoute());
                    item.put("feature", f.getFeature());
                    item.put("icon", f.getIcon());
                    item.put("ordering", f.getOrdering());
                    item.put("system", f.getSystem());
                    return item;
                })
                .collect(Collectors.toList());
    }

    /** Quebra uma lista separada por virgulas, ignorando espacos e vazios. */
    private List<String> splitCsv(String value) {
        List<String> result = new ArrayList<>();
        if (value == null || value.isBlank()) {
            return result;
        }
        for (String part : value.split(",")) {
            if (!part.isBlank()) {
                result.add(part.trim());
            }
        }
        return result;
    }

    public Map<String, String> generateAccessToken(JwtPayload user, UUID tokenId, String software) {
        return generateAccessToken(user, tokenId, software, null, null, null);
    }

    public Map<String, String> generateAccessToken(
            JwtPayload user,
            UUID tokenId,
            String software,
            String subscriptionSpeak,
            String subscriptionTask
    ) {
        return generateAccessToken(user, tokenId, software, subscriptionSpeak, subscriptionTask, null);
    }

    public Map<String, String> generateAccessToken(
            JwtPayload user,
            UUID tokenId,
            String software,
            String subscriptionSpeak,
            String subscriptionTask,
            String deviceId
    ) {
        List<String> authorities = new ArrayList<>();
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

        // tokenId e o jti: identifica este token especificamente (revogacao) e e
        // independente do jti do refresh token. Reutilizar o mesmo id para os
        // dois tornava-os indistinguiveis, e o refresh valia como credencial de
        // acesso.
        if (tokenId == null) {
            tokenId = UUID.randomUUID();
        }

        var builder = Jwts
                .builder()
                .id(tokenId.toString())
                .subject(user.getUsername())
                .claim("userId", user.getUserId())
                .claim("tokenType", "ACCESS_TOKEN")
                .claim("tokenId", tokenId)
                .claim("firstName", user.getFirstName())
                .claim("lastName", user.getLastName())
                .claim("type", user.getType())
                .claim("detrasoftId", user.getDetrasoftId())
                .claim("urlImg", user.getUrlImg())
                .claim("urlHome", user.getUrlHome())
                .claim("business", user.getBusiness())
                .claim("software", software)
                .claim("subscriptionSpeak", subscriptionSpeak)
                .claim("subscriptionTask", subscriptionTask)
                .claim("language", user.getLanguage())
                .claim("timezoneOffset", user.getTimezoneOffset())
                .claim("configs", toConfigMap(user.getConfigs()))
                .claim("favorites", toFavoriteList(user.getFavorites()))
                .claim("authorities", authorities)
                .claim("expiresIn", accessTokenExpire)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + (accessTokenExpire * 1000)));

        if (deviceId != null && !deviceId.isBlank()) {
            builder.claim("deviceId", deviceId);
        }

        String token = sign(builder);
        Map<String, String> result = new HashMap<>();
        result.put("token", token);
        result.put("tokenId", tokenId.toString());
        return result;
    }

    public Map<String, String> generateRefreshToken(JwtPayload user, UUID tokenId, String software) {
        return generateRefreshToken(user, tokenId, software, null);
    }

    public Map<String, String> generateRefreshToken(JwtPayload user, UUID tokenId, String software, String deviceId) {
        if (tokenId == null) {
            tokenId = UUID.randomUUID();
        }
        var builder = Jwts
            .builder()
            .id(tokenId.toString())
            .subject(user.getUsername())
            .claim("tokenType", "REFRESH_TOKEN")
            .claim("tokenId", tokenId)
            .claim("userId", user.getUserId())
            .claim("software", software)
            .claim("expiresIn", refreshTokenExpire)
            .issuedAt(new Date(System.currentTimeMillis()))
            .expiration(new Date(System.currentTimeMillis() + (refreshTokenExpire * 1000)));

        if (deviceId != null && !deviceId.isBlank()) {
            builder.claim("deviceId", deviceId);
        }

        Map<String, String> result = new HashMap<>();
        result.put("refreshToken", sign(builder));
        result.put("tokenId", tokenId.toString());
        return result;
    }

    public Map<String, String> generateNewPasswordToken(JwtPayload user, UUID tokenId) {
        if (tokenId == null) {
            tokenId = UUID.randomUUID();
        }
        String token = sign(Jwts
            .builder()
            .id(tokenId.toString())
            .subject(user.getUsername())
            .claim("tokenType", "NEW_PASSWORD")
            .claim("tokenId", tokenId)
            .claim("expiresIn", 600)
            .issuedAt(new Date(System.currentTimeMillis()))
            .expiration(new Date(System.currentTimeMillis() + (600 * 1000))));

        Map<String, String> result = new HashMap<>();
        result.put("newPasswordToken", token);
        result.put("tokenId", tokenId.toString());
        return result;
    }

    public Map<String, String> generateValidationCodeToken(String userName, String code, UUID registerId) {
        var tokenId = UUID.randomUUID();

        String token = sign(Jwts
            .builder()
            .id(tokenId.toString())
            .subject(userName)
            .claim("tokenType", "VALIDATION_CODE")
            .claim("tokenId", tokenId)
            .claim("registerId", registerId)
            .claim("code", code)
            .claim("expiresIn", 600)
            .issuedAt(new Date(System.currentTimeMillis()))
            .expiration(new Date(System.currentTimeMillis() + (600 * 1000))));

        Map<String, String> result = new HashMap<>();
        result.put("validationCodeToken", token);
        result.put("tokenId", tokenId.toString());
        return result;
    }

    /**
     * Assina em RS256 com a chave privada do authorization-server.
     *
     * A escolha do algoritmo e determinada pela CONFIGURACAO, nunca pelo
     * conteudo do token: um token nao influencia como sera assinado nem
     * verificado. Isso e o que impede o ataque de confusao de algoritmo.
     */
    private String sign(io.jsonwebtoken.JwtBuilder builder) {
        if (rsaPrivateKeyPem == null || rsaPrivateKeyPem.isBlank()) {
            throw new IllegalStateException("application.security.jwt.rsa.private-key-pem nao configurada. "
                    + "Apenas o authorization-server emite tokens; o servico que precisa emitir deve ser "
                    + "apontado para ele em vez de receber a chave de assinatura.");
        }
        try {
            PrivateKey privateKey = parsePrivateKey(rsaPrivateKeyPem);
            return builder
                    .issuer(expectedIssuer)
                    .header().keyId(rsaKeyId).and()
                    .signWith(privateKey, Jwts.SIG.RS256)
                    .compact();
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Falha ao assinar com application.security.jwt.rsa.private-key-pem", e);
        }
    }

    private PrivateKey parsePrivateKey(String pem) throws Exception {
        return KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(decodePem(pem)));
    }

    private PublicKey parsePublicKey(String pem) throws Exception {
        return KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(decodePem(pem)));
    }

    private byte[] decodePem(String pem) {
        String normalized = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(normalized);
    }

    public boolean isUserStatusControlEnabled() {
        return userStatusControlEnabled;
    }

    /** Mantido por compatibilidade de API; delega para parseClaims + toJwtPayload. */
    public JwtPayload decodeTokenToUserDetails(String token) {
        return toJwtPayload(extractAllClaims(token));
    }

    /**
     * Monta o JwtPayload a partir de claims JA verificadas. Permite que o filtro
     * faca um unico parse por requisicao em vez de um por acesso a campo.
     */
    @SuppressWarnings("unchecked")
    public JwtPayload toJwtPayload(Claims claims) {
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
        String software = claims.get("software", String.class);
        String subscriptionSpeak = claims.get("subscriptionSpeak", String.class);
        String subscriptionTask = claims.get("subscriptionTask", String.class);
        String language = claims.get("language", String.class);
        String timezoneOffset = claims.get("timezoneOffset", String.class);
        List<UserConfigDTO> configs = readConfigs(claims);
        List<UserFavoriteDTO> favorites = readFavorites(claims);

        return JwtPayload.builder()
                .configs(configs)
                .favorites(favorites)
                .userId(userId)
                .username(username)
                .authorities(authorities)
                .firstName(firstName)
                .lastName(lastName)
                .detrasoftId(detrasoftId)
                .type(type != null ? UserType.valueOf(type) : null)
                .urlImg(urlImg)
                .urlHome(urlHome)
                .business(business)
                .software(software)
                .subscriptionSpeak(subscriptionSpeak)
                .subscriptionTask(subscriptionTask)
                .language(language)
                .timezoneOffset(timezoneOffset)
                .status(SessionStatus.LOGGED_IN)
                .build();
    }

    /**
     * Reidrata `configs` do token.
     *
     * O formato atual e um MAPA chave/valor. A lista de objetos tambem e aceita
     * porque tokens emitidos antes desta mudanca carregam `[{name,value}]` --
     * e um token ja emitido nao pode ser reemitido.
     */
    private List<UserConfigDTO> readConfigs(Claims claims) {
        Object raw = claims.get("configs");

        if (raw instanceof Map<?, ?> map) {
            List<UserConfigDTO> result = new ArrayList<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                result.add(UserConfigDTO.builder()
                        .name(str(entry.getKey()))
                        .value(str(entry.getValue()))
                        .build());
            }
            return result.isEmpty() ? null : result;
        }

        if (raw instanceof List<?> list) {
            List<UserConfigDTO> result = new ArrayList<>();
            for (Object item : list) {
                if (item instanceof Map<?, ?> map) {
                    result.add(UserConfigDTO.builder()
                            .name(str(map.get("name")))
                            .value(str(map.get("value")))
                            .build());
                }
            }
            return result.isEmpty() ? null : result;
        }

        return null;
    }

    /** Reidrata `favorites` do token. */
    private List<UserFavoriteDTO> readFavorites(Claims claims) {
        Object raw = claims.get("favorites");
        if (!(raw instanceof List<?> list)) {
            return null;
        }
        List<UserFavoriteDTO> result = new ArrayList<>();
        for (Object item : list) {
            if (item instanceof Map<?, ?> map) {
                result.add(UserFavoriteDTO.builder()
                        .name(str(map.get("name")))
                        .url(str(map.get("url")))
                        .route(str(map.get("route")))
                        .feature(str(map.get("feature")))
                        .icon(str(map.get("icon")))
                        .system(str(map.get("system")))
                        .ordering(map.get("ordering") == null ? null
                                : Integer.valueOf(map.get("ordering").toString()))
                        .build());
            }
        }
        return result;
    }

    private String str(Object value) {
        return value == null ? null : value.toString();
    }

    /**
     * Valida `iss` e `aud` das claims. Retorna true quando o servico nao tem a
     * configuracao correspondente -- nao ha valor esperado a comparar.
     */
    public boolean issuerAndAudienceValid(Claims claims) {
        if (expectedIssuer != null && !expectedIssuer.isBlank()) {
            if (!expectedIssuer.equals(claims.getIssuer())) {
                return false;
            }
        }
        List<String> audiences = splitCsv(expectedAudiences);
        if (!audiences.isEmpty()) {
            List<String> tokenAudiences = claims.getAudience() == null
                    ? List.of()
                    : new ArrayList<>(claims.getAudience());
            if (tokenAudiences.stream().noneMatch(audiences::contains)) {
                return false;
            }
        }
        return true;
    }
}
