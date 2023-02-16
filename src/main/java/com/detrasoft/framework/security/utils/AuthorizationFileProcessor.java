package com.detrasoft.framework.security.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

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
import java.util.stream.Stream;

public class AuthorizationFileProcessor {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationFileProcessor.class);

    public void configureAuthoritiesFileConfig(HttpSecurity http) {
        try {
            for (String directory : getResourceFolderFiles()) {

                Properties props = new Properties();
                URI uri = this.getClass().getProtectionDomain().getCodeSource().getLocation().toURI();

                InputStream input = null;

                if (uri.getScheme().equals("jar")) {
                    input = this.getClass().getResourceAsStream(directory);
                } else {
                    input = new FileInputStream(directory);
                }

                props.load(input);

                for (Object object : props.keySet()) {
                    String controllerMapping = object.toString().substring(0, object.toString().indexOf("*"));

                    String verbHttp = object.toString().substring(object.toString().indexOf("*") + 1,
                            object.toString().length());

                    String access = props.getProperty(object.toString());

                    switch (verbHttp) {
                        case "post" ->
                                http.authorizeRequests().antMatchers(HttpMethod.POST, "/" + controllerMapping)
                                        .access(access);
                        case "put" ->
                                http.authorizeRequests().antMatchers(HttpMethod.PUT, "/" + controllerMapping)
                                        .access(access);
                        case "delete" ->
                                http.authorizeRequests().antMatchers(HttpMethod.DELETE, "/" + controllerMapping)
                                        .access(access);
                        case "get" ->
                                http.authorizeRequests().antMatchers(HttpMethod.GET, "/" + controllerMapping)
                                        .access(access);
                        default -> http.authorizeRequests().antMatchers("/" + controllerMapping + "/").access(access);
                    }
                    logger.info("Permission added [" + verbHttp + "] /" + controllerMapping);
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
                FileSystem fileSystem = FileSystems.newFileSystem(uri, Collections.<String, Object>emptyMap());
                logger.info("Loading permissions by file JAR/WAR");
                Path myPath = fileSystem.getPath("/BOOT-INF/classes/authorities/");
                Stream<Path> walk = Files.walk(myPath, 1);
                logger.info("Files searched:");
                for (Iterator<Path> it = walk.iterator(); it.hasNext();) {
                    String s = it.next().toString();
                    logger.info(" - " + s);
                    result.add(s);
                }
                walk.close();
                result.remove(0);
            } else if (uri.getScheme().equals("war")) {
                FileSystem fileSystem = FileSystems.newFileSystem(uri, Collections.<String, Object>emptyMap());
                logger.info("Loading permissions by file JAR/WAR");
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
