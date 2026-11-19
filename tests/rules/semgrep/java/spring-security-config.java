package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import java.util.List;

public class SecurityConfig {

    @Bean
    SecurityFilterChain open(HttpSecurity http) throws Exception {
        http
            // ruleid: shyena.java.spring-csrf-disabled
            .csrf(AbstractHttpConfigurer::disable)
            // A chained matcher is reported where the chain starts (Semgrep spans the whole call).
            .authorizeHttpRequests(auth ->
                // ruleid: shyena.java.spring-permit-all-catch-all
                auth.requestMatchers("/public/**").permitAll()
                .anyRequest().permitAll());
        return http.build();
    }

    @Bean
    SecurityFilterChain legacy(HttpSecurity http) throws Exception {
        // ruleid: shyena.java.spring-csrf-disabled
        http.csrf().disable();
        // ruleid: shyena.java.spring-csrf-disabled
        http.csrf(c -> c.disable());
        return http.build();
    }

    @Bean
    SecurityFilterChain good(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                // ok: shyena.java.spring-permit-all-catch-all
                .requestMatchers("/actuator/health").permitAll()
                // ok: shyena.java.spring-permit-all-catch-all
                .anyRequest().authenticated());
        return http.build();
    }

    public void addCorsMappings(CorsRegistry registry) {
        // ruleid: shyena.java.spring-cors-any-origin
        registry.addMapping("/**").allowedOriginPatterns("*").allowCredentials(true);
        // ok: shyena.java.spring-cors-any-origin
        registry.addMapping("/api/**").allowedOrigins("https://app.example.com");
    }

    CorsConfiguration cors() {
        CorsConfiguration c = new CorsConfiguration();
        // ruleid: shyena.java.spring-cors-any-origin
        c.setAllowedOrigins(List.of("*"));
        return c;
    }
}

@RestController
class OpenController {
    // ruleid: shyena.java.spring-cors-any-origin
    @CrossOrigin
    @GetMapping("/a")
    String a() { return "a"; }

    // ok: shyena.java.spring-cors-any-origin
    @CrossOrigin(origins = "https://app.example.com")
    @GetMapping("/b")
    String b() { return "b"; }
}
