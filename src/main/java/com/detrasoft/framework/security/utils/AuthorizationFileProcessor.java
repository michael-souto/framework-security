package com.detrasoft.framework.security.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.Properties;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.stream.Stream;
import java.util.Arrays;

@Component
public class AuthorizationFileProcessor {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationFileProcessor.class);

    public void configureAuthoritiesFileConfig(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry authz) {
        try {
            for (String directory : getResourceFolderFiles()) {

                Properties props = new Properties();
                URI uri = this.getClass().getProtectionDomain().getCodeSource().getLocation().toURI();

                InputStream input;

                if (uri.getScheme().equals("jar")) {
                    input = this.getClass().getResourceAsStream("/" + directory);
                } else {
                    input = new FileInputStream(directory);
                }

                if (input == null) {
                    logger.error("Não foi possível carregar o arquivo de permissões: {}", directory);
                    continue; // Pula para o próximo arquivo
                }

                props.load(input);

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

    private ArrayList<String> getResourceFolderFiles() {
        ArrayList<String> result = new ArrayList<>();
        try {
            URI uri = this.getClass().getProtectionDomain().getCodeSource().getLocation().toURI();

            if (uri.getScheme().equals("jar")) {
                logger.info("Loading permissions by file JAR");
                String directoryPath = "authorities/";

                try (InputStream jarStream = this.getClass().getProtectionDomain().getCodeSource().getLocation().openStream();
                     JarInputStream jarInputStream = new JarInputStream(jarStream)) {

                    JarEntry entry;
                    while ((entry = jarInputStream.getNextJarEntry()) != null) {
                        String entryName = entry.getName();

                        if (entryName.startsWith(directoryPath) && !entryName.endsWith("/")) {
                            logger.info(" - Encontrado arquivo: {}", entryName);
                            result.add(entryName);
                        }
                    }
                }
            } else if (uri.getScheme().equals("war")) {
                FileSystem fileSystem = FileSystems.newFileSystem(uri, Collections.emptyMap());
                logger.info("Loading permissions by file WAR");
                Path myPath = fileSystem.getPath("/WEB-INF/classes/authorities/");
                Stream<Path> walk = Files.walk(myPath, 1);
                logger.info("Files searched:");
                for (Iterator<Path> it = walk.iterator(); it.hasNext();) {
                    String s = it.next().toString();
                    logger.info(" - " + s);
                    result.add(s);
                }
                walk.close();
                result.remove(0);
            } else {
                File[] files = new File(this.getClass().getClassLoader().getResource("authorities").getPath())
                        .listFiles();
                logger.info("Loading permissions by file MAVEN RUN");
                logger.info("Files searched:");
                for (File f : files) {
                    if (!f.isDirectory()) {
                        logger.info(" - " + f);
                        result.add(f.getAbsolutePath());
                    }
                }
            }

        } catch (URISyntaxException | IOException e) {
            logger.error("Erro ao buscar arquivos de permissões: ", e);
        }

        return result;
    }
}
