package com.crypto.encryption.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CorsConfigurationSource corsConfigurationSource;

    public SecurityConfig(CorsConfigurationSource corsConfigurationSource) {
        this.corsConfigurationSource = corsConfigurationSource;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Enable CORS with the configuration source
                .cors(cors -> cors.configurationSource(corsConfigurationSource))

                // Disable CSRF for API (enable for web forms)
                .csrf(csrf -> csrf.disable())

                // Authorization configuration
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/health").permitAll()
                        .requestMatchers("/h2-console").permitAll()
                        .requestMatchers("/h2-console/**").permitAll()
                        .requestMatchers("/keys/**").permitAll()
                        .requestMatchers("/files/**").permitAll()
                        .anyRequest().permitAll()
                )

                // Disable security headers that might interfere
                .headers(headers -> headers
                        .frameOptions(frameOptions -> frameOptions.disable())
                        .xssProtection(xss -> xss.disable())
                );

        return http.build();
    }
}