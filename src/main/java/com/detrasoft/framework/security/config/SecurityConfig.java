package com.detrasoft.framework.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.detrasoft.framework.security.filter.JwtAuthenticationFilter;
import com.detrasoft.framework.security.utils.AuthorizationFileProcessor;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AuthorizationFileProcessor authorizationFileProcessor;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
                          AuthorizationFileProcessor authorizationFileProcessor
                          ) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.authorizationFileProcessor = authorizationFileProcessor;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authz -> {
                        authz
                            .requestMatchers("/auth/**").permitAll()
                            .requestMatchers("/public/**").permitAll()
                            .requestMatchers("/actuator/**").permitAll()
                            .requestMatchers("/h2-console/**").permitAll();
                        authorizationFileProcessor.configureAuthoritiesFileConfig(authz);
                        authz.anyRequest().authenticated();
                    }
                )
                .sessionManagement(session->session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(
                        e->e.accessDeniedHandler(
                                        (request, response, accessDeniedException)->response.setStatus(403)
                                )
                                .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .build();

    }
}
