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
                    input = this.getClass().getResourceAsStream(directory);
                } else {
                    input = new FileInputStream(directory);
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
                    // Remove aspas simples e divide por vírgula
                    String[] authorities = authoritiesString.replaceAll("'", "").split("\\s*,\\s*");
    
                    // Construir o padrão de URL
                    String urlPattern = "/" + controllerMapping;
    
                    // Adicionar a autorização com base no método HTTP
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
            e.printStackTrace();
        }
    }

    private ArrayList<String> getResourceFolderFiles() {
        ArrayList<String> result = new ArrayList<String>();
        try {
            URI uri = this.getClass().getProtectionDomain().getCodeSource().getLocation().toURI();

            if (uri.getScheme().equals("jar")) {
                logger.info("Loading permissions by file JAR");
                // Obtemos o caminho do JAR
                String directoryPath = "authorities/";
                URI jarUri = this.getClass().getProtectionDomain().getCodeSource().getLocation().toURI();

                // Abrimos o JAR como um stream
                try (JarInputStream jarStream = new JarInputStream(Files.newInputStream(Path.of(jarUri)))) {
                    JarEntry entry;

                    while ((entry = jarStream.getNextJarEntry()) != null) {
                        String entryName = entry.getName();

                        // Verifica se o arquivo está dentro da pasta "authorities/"
                        if (entryName.startsWith(directoryPath) && !entryName.endsWith("/")) {
                            logger.info(" - Encontrado arquivo: {}", entryName);
                            result.add(entryName); // Adiciona o caminho completo do arquivo
                        }
                    }
                }
            } else if (uri.getScheme().equals("war")) {
                FileSystem fileSystem = FileSystems.newFileSystem(uri, Collections.<String, Object>emptyMap());
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
            e.printStackTrace();
        }

        return result;
    }
}
