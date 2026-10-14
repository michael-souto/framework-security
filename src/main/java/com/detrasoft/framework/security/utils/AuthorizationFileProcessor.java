package com.detrasoft.framework.security.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Properties;

@Component
public class AuthorizationFileProcessor {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationFileProcessor.class);

    private static final String AUTHORITIES_DIRECTORY = "authorities/";

    public void configureAuthoritiesFileConfig(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authz) {
        try {
            for (Resource resource : getAuthorityFiles()) {

                Properties props = new Properties();
                try (InputStream input = resource.getInputStream()) {
                    props.load(input);
                }

                for (String key : props.stringPropertyNames()) {
                    String[] keyParts = key.split("\\@");
                    if (keyParts.length != 2) {
                        logger.warn("Formato de chave inválido: {}", key);
                        continue;
                    }
                    String controllerMapping = keyParts[0];
                    String verbHttp = keyParts[1].toLowerCase();

                    String authoritiesString = props.getProperty(key).trim();
                    String[] authorities = authoritiesString.replaceAll("'", "").split("\\s*,\\s*");

                    String urlPattern = "/" + controllerMapping;

                    switch (verbHttp) {
                        case "post" -> authz
                            .requestMatchers(HttpMethod.POST, urlPattern)
                            .hasAnyAuthority(authorities);
                        case "put" -> authz
                            .requestMatchers(HttpMethod.PUT, urlPattern)
                            .hasAnyAuthority(authorities);
                        case "delete" -> authz
                            .requestMatchers(HttpMethod.DELETE, urlPattern)
                            .hasAnyAuthority(authorities);
                        case "get" -> authz
                            .requestMatchers(HttpMethod.GET, urlPattern)
                            .hasAnyAuthority(authorities);
                        default -> authz
                            .requestMatchers(urlPattern)
                            .hasAnyAuthority(authorities);
                    }
                    logger.info("Permissão adicionada [{}] {} com autoridades {}", verbHttp.toUpperCase(), urlPattern, Arrays.toString(authorities));
                }
            }

        } catch (Exception e) {
            logger.error("Erro ao configurar permissões de autoridade: ", e);
        }
    }

    /**
     * Arquivos em authorities/ do classpath. O PathMatchingResourcePatternResolver funciona em
     * JAR, WAR, IDE e GraalVM native image (protocolo resource:), onde CodeSource e java.io.File
     * não estão disponíveis. Ordenados pelo nome para a ordem dos requestMatchers ser estável.
     */
    private Resource[] getAuthorityFiles() throws IOException {
        Resource[] resources = new PathMatchingResourcePatternResolver(getClass().getClassLoader())
                .getResources("classpath*:" + AUTHORITIES_DIRECTORY + "*");
        Resource[] files = Arrays.stream(resources)
                .filter(Resource::isReadable)
                .filter(resource -> resource.getFilename() != null && !resource.getFilename().isEmpty())
                .sorted(Comparator.comparing(Resource::getFilename))
                .toArray(Resource[]::new);
        logger.info("Arquivos de permissões encontrados: {}",
                Arrays.stream(files).map(Resource::getFilename).toList());
        return files;
    }
}
